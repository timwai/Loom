//! L-001A **experimental** E2EE TLS 1.3 over an arbitrary reliable bearer.
//! NOT production admission. A trusted membership ledger, anti-rollback state,
//! resource Owner ACL, and audited secret storage are still required.
//!
//! The bearer (direct, relay, or TCP fallback) is untrusted. Both endpoints
//! validate each other's pinned Ed25519 X.509 certificates at the TLS layer.
//! A short encrypted association exchange then binds space, peer IDs and epochs.
//! Every subsequent ServiceOpen MUST independently enforce the Owner ACL.

use loom_crypto::CryptoError;
use loom_identity::{MembershipVerifier, PeerPrincipal};
use loom_types::{PeerId, SpaceId};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use x509_parser::prelude::{FromDer, X509Certificate};

const PEER_ID_DOMAIN: &[u8] = b"LOOM:PEER-ID:V1\0";
const ASSOCIATION_MAGIC: &[u8; 10] = b"LOOM-SCP1!";
const ASSOCIATION_SIZE: usize = 10 + 16 + 32 + 32 + 8;
const FIXED_SERVER_NAME: &str = "loom-peer.local";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurePeerError {
    InvalidCertificate,
    InvalidLocalIdentity,
    InvalidTlsConfiguration,
    HandshakeFailed,
    InvalidPeer,
    InvalidSpace,
    InvalidEpoch,
    UntrustedMembership,
    InvalidAssociation,
}

pub struct LocalTlsIdentity {
    pub certificate: CertificateDer<'static>,
    pub private_key: PrivateKeyDer<'static>,
    pub key_epoch: u64,
}

impl LocalTlsIdentity {
    pub fn peer_id(&self) -> Result<PeerId, SecurePeerError> {
        peer_id_from_certificate(&self.certificate)
    }
}

/// A certificate learned through a trusted, verified membership record.
/// Constructing this structure does **not** make the peer trusted: the
/// caller must also supply a MembershipVerifier backed by signed state.
#[derive(Clone)]
pub struct PinnedPeer {
    pub certificate: CertificateDer<'static>,
    pub peer_id: PeerId,
    pub key_epoch: u64,
}

impl PinnedPeer {
    pub fn new(
        certificate: CertificateDer<'static>,
        key_epoch: u64,
    ) -> Result<Self, SecurePeerError> {
        let peer_id = peer_id_from_certificate(&certificate)?;
        Ok(Self {
            certificate,
            peer_id,
            key_epoch,
        })
    }
}

fn peer_id_from_certificate(cert: &CertificateDer<'_>) -> Result<PeerId, SecurePeerError> {
    let (rem, parsed) = X509Certificate::from_der(cert.as_ref())
        .map_err(|_| SecurePeerError::InvalidCertificate)?;
    if !rem.is_empty()
        || parsed.public_key().algorithm.algorithm.to_id_string() != "1.3.101.112"
        || parsed.signature_algorithm.algorithm.to_id_string() != "1.3.101.112"
    {
        return Err(SecurePeerError::InvalidCertificate);
    }
    let raw = parsed.public_key().subject_public_key.data.as_ref();
    if raw.len() != 32 {
        return Err(SecurePeerError::InvalidCertificate);
    }
    let mut hasher = Sha256::new();
    hasher.update(PEER_ID_DOMAIN);
    hasher.update(raw);
    Ok(PeerId::from_digest(hasher.finalize().into()))
}

fn root_store(cert: CertificateDer<'static>) -> Result<RootCertStore, SecurePeerError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(cert)
        .map_err(|_| SecurePeerError::InvalidTlsConfiguration)?;
    Ok(roots)
}

pub struct SecurePeerContext {
    /// Expected remote peer and certificate from verified, current trust data.
    pub expected_remote: PinnedPeer,
    pub space_id: SpaceId,
}

pub struct SecurePeerChannel<S> {
    stream: S,
    remote: PeerPrincipal,
    remote_key_epoch: u64,
}

impl<S> SecurePeerChannel<S> {
    pub fn remote_principal(&self) -> &PeerPrincipal {
        &self.remote
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Revalidate before each diagnostic operation. The caller still needs a
    /// ResourceOwner decision and a coordinated revocation/session barrier.
    pub fn revalidate_membership(
        &self,
        membership: &dyn MembershipVerifier,
    ) -> Result<(), SecurePeerError> {
        let current = membership
            .resolve_principal(
                self.remote.peer_id,
                self.remote.space_id,
                self.remote_key_epoch,
            )
            .map_err(|_| SecurePeerError::UntrustedMembership)?;
        if current != self.remote {
            return Err(SecurePeerError::UntrustedMembership);
        }
        Ok(())
    }
}

impl<S: Send + Sync> super::VerifiedChannel for SecurePeerChannel<S> {
    fn remote_principal(&self) -> &PeerPrincipal {
        &self.remote
    }
}

fn matched_principal(
    presented_cert: Option<&[CertificateDer<'static>]>,
    expected: &PinnedPeer,
    space_id: SpaceId,
    membership: &dyn MembershipVerifier,
) -> Result<PeerPrincipal, SecurePeerError> {
    let cert = presented_cert
        .and_then(|certs| {
            if certs.len() == 1 {
                certs.first()
            } else {
                None
            }
        })
        .ok_or(SecurePeerError::InvalidPeer)?;
    if cert.as_ref() != expected.certificate.as_ref()
        || peer_id_from_certificate(cert)? != expected.peer_id
    {
        return Err(SecurePeerError::InvalidPeer);
    }
    let principal = membership
        .resolve_principal(expected.peer_id, space_id, expected.key_epoch)
        .map_err(|_: CryptoError| SecurePeerError::UntrustedMembership)?;
    if principal.peer_id != expected.peer_id
        || principal.space_id != space_id
        || principal.membership_epoch == 0
    {
        return Err(SecurePeerError::UntrustedMembership);
    }
    Ok(principal)
}

fn association(
    own_id: PeerId,
    intended_peer: PeerId,
    space_id: SpaceId,
    local_epoch: u64,
) -> [u8; ASSOCIATION_SIZE] {
    let mut data = [0_u8; ASSOCIATION_SIZE];
    data[..10].copy_from_slice(ASSOCIATION_MAGIC);
    data[10..26].copy_from_slice(space_id.as_bytes());
    data[26..58].copy_from_slice(intended_peer.digest());
    data[58..90].copy_from_slice(own_id.digest());
    data[90..98].copy_from_slice(&local_epoch.to_be_bytes());
    data
}

fn check_association(
    received: &[u8; ASSOCIATION_SIZE],
    local_id: PeerId,
    peer: &PinnedPeer,
    space: SpaceId,
) -> Result<(), SecurePeerError> {
    if &received[..10] != ASSOCIATION_MAGIC {
        return Err(SecurePeerError::InvalidAssociation);
    }
    if &received[10..26] != space.as_bytes() {
        return Err(SecurePeerError::InvalidSpace);
    }
    if &received[26..58] != local_id.digest() || &received[58..90] != peer.peer_id.digest() {
        return Err(SecurePeerError::InvalidPeer);
    }
    if received[90..98] != peer.key_epoch.to_be_bytes() {
        return Err(SecurePeerError::InvalidEpoch);
    }
    Ok(())
}

async fn exchange_association<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    local: PeerId,
    context: &SecurePeerContext,
    local_epoch: u64,
    initiator: bool,
) -> Result<(), SecurePeerError> {
    let hello = association(
        local,
        context.expected_remote.peer_id,
        context.space_id,
        local_epoch,
    );
    let mut incoming = [0_u8; ASSOCIATION_SIZE];
    if initiator {
        stream
            .write_all(&hello)
            .await
            .map_err(|_| SecurePeerError::HandshakeFailed)?;
        stream
            .flush()
            .await
            .map_err(|_| SecurePeerError::HandshakeFailed)?;
        stream
            .read_exact(&mut incoming)
            .await
            .map_err(|_| SecurePeerError::HandshakeFailed)?;
    } else {
        stream
            .read_exact(&mut incoming)
            .await
            .map_err(|_| SecurePeerError::HandshakeFailed)?;
        // Do not send an acknowledgement of successful membership until verified.
        check_association(&incoming, local, &context.expected_remote, context.space_id)?;
        stream
            .write_all(&hello)
            .await
            .map_err(|_| SecurePeerError::HandshakeFailed)?;
        stream
            .flush()
            .await
            .map_err(|_| SecurePeerError::HandshakeFailed)?;
    }
    check_association(&incoming, local, &context.expected_remote, context.space_id)
}

/// Establish inner TLS 1.3 mTLS on a bearer that may be carried by an untrusted Relay.
/// This does **not** grant access to any resources.
pub async fn connect<S>(
    bearer: S,
    local: LocalTlsIdentity,
    context: SecurePeerContext,
    membership: &dyn MembershipVerifier,
) -> Result<SecurePeerChannel<client::TlsStream<S>>, SecurePeerError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let local_id = local.peer_id()?;
    let roots = root_store(context.expected_remote.certificate.clone())?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![local.certificate], local.private_key)
        .map_err(|_| SecurePeerError::InvalidTlsConfiguration)?;
    let tls = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(FIXED_SERVER_NAME)
        .map_err(|_| SecurePeerError::InvalidTlsConfiguration)?;
    let mut stream = tls
        .connect(server_name, bearer)
        .await
        .map_err(|_| SecurePeerError::HandshakeFailed)?;
    let principal = matched_principal(
        stream.get_ref().1.peer_certificates(),
        &context.expected_remote,
        context.space_id,
        membership,
    )?;
    exchange_association(&mut stream, local_id, &context, local.key_epoch, true).await?;
    let channel = SecurePeerChannel {
        stream,
        remote: principal,
        remote_key_epoch: context.expected_remote.key_epoch,
    };
    channel.revalidate_membership(membership)?;
    Ok(channel)
}

/// Accept a mutual TLS peer; a stream is returned only after both membership and
/// the encrypted intended-target / space / key-epoch association have passed.
pub async fn accept<S>(
    bearer: S,
    local: LocalTlsIdentity,
    context: SecurePeerContext,
    membership: &dyn MembershipVerifier,
) -> Result<SecurePeerChannel<server::TlsStream<S>>, SecurePeerError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let local_id = local.peer_id()?;
    let roots = root_store(context.expected_remote.certificate.clone())?;
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| SecurePeerError::InvalidTlsConfiguration)?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![local.certificate], local.private_key)
        .map_err(|_| SecurePeerError::InvalidTlsConfiguration)?;
    let mut stream = TlsAcceptor::from(Arc::new(config))
        .accept(bearer)
        .await
        .map_err(|_| SecurePeerError::HandshakeFailed)?;
    let principal = matched_principal(
        stream.get_ref().1.peer_certificates(),
        &context.expected_remote,
        context.space_id,
        membership,
    )?;
    exchange_association(&mut stream, local_id, &context, local.key_epoch, false).await?;
    let channel = SecurePeerChannel {
        stream,
        remote: principal,
        remote_key_epoch: context.expected_remote.key_epoch,
    };
    channel.revalidate_membership(membership)?;
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::{Duration, timeout};

    struct Fixture {
        cert: CertificateDer<'static>,
        key: Vec<u8>,
        peer_id: PeerId,
        epoch: u64,
    }
    impl Fixture {
        fn new(epoch: u64) -> Self {
            let keypair = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let params = CertificateParams::new(vec![FIXED_SERVER_NAME.to_owned()]).unwrap();
            let cert = params.self_signed(&keypair).unwrap();
            let cert = CertificateDer::from(cert.der().to_vec());
            let peer_id = peer_id_from_certificate(&cert).unwrap();
            Self {
                cert,
                key: keypair.serialize_der(),
                peer_id,
                epoch,
            }
        }
        fn identity(&self) -> LocalTlsIdentity {
            LocalTlsIdentity {
                certificate: self.cert.clone(),
                private_key: PrivateKeyDer::Pkcs8(self.key.clone().into()),
                key_epoch: self.epoch,
            }
        }
        fn pinned(&self) -> PinnedPeer {
            PinnedPeer::new(self.cert.clone(), self.epoch).unwrap()
        }
    }

    #[derive(Clone)]
    struct StrictLedger {
        peer: PeerId,
        space: SpaceId,
        epoch: u64,
    }
    impl MembershipVerifier for StrictLedger {
        fn verify_membership(&self, principal: &PeerPrincipal) -> Result<(), CryptoError> {
            if principal.peer_id == self.peer
                && principal.space_id == self.space
                && principal.membership_epoch == self.epoch
            {
                Ok(())
            } else {
                Err(CryptoError::InvalidIdentity)
            }
        }
    }

    fn space() -> SpaceId {
        SpaceId::from_bytes([9; 16])
    }

    #[tokio::test]
    async fn direct_mutual_tls_and_encrypted_association() {
        let a = Fixture::new(1);
        let b = Fixture::new(4);
        let (left, right) = duplex(16384);
        let client_ledger = StrictLedger {
            peer: b.peer_id,
            space: space(),
            epoch: b.epoch,
        };
        let server_ledger = StrictLedger {
            peer: a.peer_id,
            space: space(),
            epoch: a.epoch,
        };
        let client = connect(
            left,
            a.identity(),
            SecurePeerContext {
                expected_remote: b.pinned(),
                space_id: space(),
            },
            &client_ledger,
        );
        let server = accept(
            right,
            b.identity(),
            SecurePeerContext {
                expected_remote: a.pinned(),
                space_id: space(),
            },
            &server_ledger,
        );
        let (client, server) = timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        assert_eq!(client.remote_principal().peer_id, b.peer_id);
        assert_eq!(server.remote_principal().peer_id, a.peer_id);
        client
            .stream_mut()
            .write_all(b"secret service payload")
            .await
            .unwrap();
        let mut output = [0u8; 22];
        server.stream_mut().read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"secret service payload");
    }

    #[tokio::test]
    async fn space_mismatch_fails_before_service_open() {
        let a = Fixture::new(2);
        let b = Fixture::new(3);
        let (left, right) = duplex(16384);
        let client_ledger = StrictLedger {
            peer: b.peer_id,
            space: space(),
            epoch: b.epoch,
        };
        let server_ledger = StrictLedger {
            peer: a.peer_id,
            space: SpaceId::from_bytes([7; 16]),
            epoch: a.epoch,
        };
        let client = connect(
            left,
            a.identity(),
            SecurePeerContext {
                expected_remote: b.pinned(),
                space_id: space(),
            },
            &client_ledger,
        );
        let server = accept(
            right,
            b.identity(),
            SecurePeerContext {
                expected_remote: a.pinned(),
                space_id: SpaceId::from_bytes([7; 16]),
            },
            &server_ledger,
        );
        let (client, server) = timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        assert!(client.is_err());
        assert!(matches!(server, Err(SecurePeerError::InvalidSpace)));
    }

    #[tokio::test]
    async fn wrong_target_certificate_fails_tls() {
        let a = Fixture::new(1);
        let b = Fixture::new(1);
        let impostor = Fixture::new(1);
        let (left, right) = duplex(16384);
        let client_ledger = StrictLedger {
            peer: b.peer_id,
            space: space(),
            epoch: b.epoch,
        };
        let server_ledger = StrictLedger {
            peer: a.peer_id,
            space: space(),
            epoch: a.epoch,
        };
        let client = connect(
            left,
            a.identity(),
            SecurePeerContext {
                expected_remote: b.pinned(),
                space_id: space(),
            },
            &client_ledger,
        );
        let server = accept(
            right,
            impostor.identity(),
            SecurePeerContext {
                expected_remote: a.pinned(),
                space_id: space(),
            },
            &server_ledger,
        );
        let (client, _) = timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn wrong_remote_epoch_or_revoked_membership_fails() {
        let a = Fixture::new(1);
        let b = Fixture::new(4);
        let (left, right) = duplex(16384);
        let client_ledger = StrictLedger {
            peer: b.peer_id,
            space: space(),
            epoch: b.epoch + 1,
        };
        let server_ledger = StrictLedger {
            peer: a.peer_id,
            space: space(),
            epoch: a.epoch,
        };
        let client = connect(
            left,
            a.identity(),
            SecurePeerContext {
                expected_remote: b.pinned(),
                space_id: space(),
            },
            &client_ledger,
        );
        let server = accept(
            right,
            b.identity(),
            SecurePeerContext {
                expected_remote: a.pinned(),
                space_id: space(),
            },
            &server_ledger,
        );
        let (client, _) = timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        assert!(matches!(client, Err(SecurePeerError::UntrustedMembership)));
    }

    #[tokio::test]
    async fn malicious_relay_observes_ciphertext_not_service_plaintext() {
        let a = Fixture::new(1);
        let b = Fixture::new(2);
        let (client_end, mut relay_left) = duplex(65536);
        let (mut relay_right, server_end) = duplex(65536);
        let capture = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let c1 = Arc::clone(&capture);
        let relay = tokio::spawn(async move {
            let (mut lread, mut lwrite) = tokio::io::split(&mut relay_left);
            let (mut rread, mut rwrite) = tokio::io::split(&mut relay_right);
            let forward = async {
                let mut buffer = [0u8; 4096];
                loop {
                    let len = lread.read(&mut buffer).await.unwrap();
                    if len == 0 {
                        break;
                    }
                    c1.lock().unwrap().extend_from_slice(&buffer[..len]);
                    rwrite.write_all(&buffer[..len]).await.unwrap();
                }
            };
            let reverse = async {
                let mut buffer = [0u8; 4096];
                loop {
                    let len = rread.read(&mut buffer).await.unwrap();
                    if len == 0 {
                        break;
                    }
                    lwrite.write_all(&buffer[..len]).await.unwrap();
                }
            };
            tokio::join!(forward, reverse);
        });
        let client_ledger = StrictLedger {
            peer: b.peer_id,
            space: space(),
            epoch: b.epoch,
        };
        let server_ledger = StrictLedger {
            peer: a.peer_id,
            space: space(),
            epoch: a.epoch,
        };
        let client = connect(
            client_end,
            a.identity(),
            SecurePeerContext {
                expected_remote: b.pinned(),
                space_id: space(),
            },
            &client_ledger,
        );
        let server = accept(
            server_end,
            b.identity(),
            SecurePeerContext {
                expected_remote: a.pinned(),
                space_id: space(),
            },
            &server_ledger,
        );
        let (client, server) = timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        const SECRET: &[u8] = b"TOP_SECRET_RELAY_MUST_NEVER_READ_12345";
        client.stream_mut().write_all(SECRET).await.unwrap();
        let mut result = vec![0u8; SECRET.len()];
        server.stream_mut().read_exact(&mut result).await.unwrap();
        assert_eq!(&result, SECRET);
        let wire = capture.lock().unwrap().clone();
        assert!(!wire.windows(SECRET.len()).any(|chunk| chunk == SECRET));
        assert!(!wire.is_empty());
        relay.abort();
    }

    #[tokio::test]
    async fn relay_cannot_modify_tls_handshake_into_valid_peer_channel() {
        let a = Fixture::new(1);
        let b = Fixture::new(1);
        let (client_end, mut relay_left) = duplex(16384);
        let (mut relay_right, server_end) = duplex(16384);
        let relay = tokio::spawn(async move {
            let (mut left_reader, mut left_writer) = tokio::io::split(&mut relay_left);
            let (mut right_reader, mut right_writer) = tokio::io::split(&mut relay_right);
            let forward = async {
                let mut record = [0u8; 4096];
                let count = left_reader.read(&mut record).await.unwrap();
                assert!(count > 0);
                // Corrupt the outer TLS record content type before it reaches B.
                record[0] ^= 0x80;
                right_writer.write_all(&record[..count]).await.unwrap();
                let _ = tokio::io::copy(&mut left_reader, &mut right_writer).await;
            };
            let back = async {
                let _ = tokio::io::copy(&mut right_reader, &mut left_writer).await;
            };
            tokio::join!(forward, back);
        });
        let client_ledger = StrictLedger {
            peer: b.peer_id,
            space: space(),
            epoch: b.epoch,
        };
        let server_ledger = StrictLedger {
            peer: a.peer_id,
            space: space(),
            epoch: a.epoch,
        };
        let client = connect(
            client_end,
            a.identity(),
            SecurePeerContext {
                expected_remote: b.pinned(),
                space_id: space(),
            },
            &client_ledger,
        );
        let server = accept(
            server_end,
            b.identity(),
            SecurePeerContext {
                expected_remote: a.pinned(),
                space_id: space(),
            },
            &server_ledger,
        );
        let (client, server) = timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        assert!(client.is_err());
        assert!(server.is_err());
        relay.abort();
    }
}
