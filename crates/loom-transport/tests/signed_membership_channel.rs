//! Real loopback mTLS with Root-delegated credentials, not an allowlist.
use ed25519_dalek::{Signer, SigningKey};
use loom_crypto::CryptoError;
use loom_crypto::{
    membership::*, owner_authority::issuer_key_id, space_trust::ExternallyPinnedRootForSpike,
};
use loom_crypto::{resource_grant::*, space_trust::*};
use loom_identity::signed_membership::SignedMembershipVerifier;
use loom_identity::{MembershipVerifier, PeerPrincipal};
use loom_transport::secure_channel::*;
use loom_types::{Action, PeerId, ResourceId, SpaceId};
use loom_wire::security_event::{
    CanonicalSecurityEvent, EventKind, encode_security_event, signing_input,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

struct Peer {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
    epoch: u64,
    member: Arc<SignedMembershipVerifier>,
    credential: VerifiedMembership,
}
fn space() -> SpaceId {
    SpaceId::from_bytes([81; 16])
}
impl Peer {
    fn new(epoch: u64, member_epoch: u64) -> Self {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let cert = CertificateParams::new(vec!["loom-peer.local".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let root = SigningKey::from_bytes(&[91; 32]);
        let writer = SigningKey::from_bytes(&[92; 32]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let d = MembershipWriterDelegation {
            space: space(),
            root_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_epoch: 3,
            issued_at_ms: now - 1000,
            expires_at_ms: now + 600_000,
        };
        let signed = SignedMembershipWriter {
            delegation: d,
            root_signature: root.sign(&membership_writer_transcript(&d)).to_bytes(),
        };
        let event = CanonicalSecurityEvent {
            kind: EventKind::MembershipGrant,
            space_id: *space().as_bytes(),
            signer_key_id: issuer_key_id(&d.writer_public_key),
            issuer_epoch: 3,
            issued_at_ms: now - 500,
            expires_at_ms: now + 300_000,
            seq: 8,
            payload: membership_payload(
                key.public_key_raw().try_into().unwrap(),
                epoch,
                member_epoch,
            ),
        };
        let bytes = encode_security_event(&event).unwrap();
        let verified = verify_membership(
            &ExternallyPinnedRootForSpike {
                space: space(),
                public_key: root.verifying_key().to_bytes(),
                key_epoch: 1,
            },
            &signed,
            MembershipRequirements {
                writer_epoch: 3,
                sequence: 8,
            },
            &bytes,
            &writer.sign(&signing_input(&bytes).unwrap()).to_bytes(),
            now,
        )
        .unwrap();
        assert_eq!(
            peer_id_for_public_key(&key.public_key_raw().try_into().unwrap()),
            verified.peer()
        );
        Self {
            cert: cert.der().to_vec().into(),
            key: key.serialize_der(),
            epoch,
            member: Arc::new(SignedMembershipVerifier::new(verified)),
            credential: verified,
        }
    }
    fn identity(&self) -> LocalTlsIdentity {
        LocalTlsIdentity {
            certificate: self.cert.clone(),
            private_key: PrivateKeyDer::Pkcs8(self.key.clone().into()),
            key_epoch: self.epoch,
        }
    }
    fn context(&self) -> SecurePeerContext {
        SecurePeerContext {
            expected_remote: PinnedPeer::new(self.cert.clone(), self.epoch).unwrap(),
            space_id: space(),
        }
    }
}

#[tokio::test]
async fn signed_credentials_bind_tls_key_and_distinct_membership_epoch() {
    let a = Peer::new(4, 51);
    let b = Peer::new(7, 69);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = async {
        let (tcp, _) = listener.accept().await.unwrap();
        accept(tcp, b.identity(), a.context(), a.member.as_ref()).await
    };
    let connected = async {
        connect(
            TcpStream::connect(address).await.unwrap(),
            a.identity(),
            b.context(),
            b.member.as_ref(),
        )
        .await
    };
    let (a_ch, b_ch) = timeout(Duration::from_secs(5), async {
        tokio::join!(connected, accepted)
    })
    .await
    .unwrap();
    let (mut a_ch, mut b_ch) = (a_ch.unwrap(), b_ch.unwrap());
    assert_eq!(a_ch.remote_principal().membership_epoch, 69);
    assert_eq!(b_ch.remote_principal().membership_epoch, 51);
    a_ch.revalidate_membership(b.member.as_ref()).unwrap();
    let grant = GrantFixture::new(&b.credential, 91);
    let checked = grant
        .verify(&b.credential, &grant.event, &grant.owner, 5)
        .unwrap();
    assert!(checked.matches(
        a_ch.remote_principal().peer_id,
        space(),
        grant.trust.resource(),
        Action::Read,
        grant.now
    ));
    assert!(!checked.matches(
        a_ch.remote_principal().peer_id,
        space(),
        grant.trust.resource(),
        Action::Write,
        grant.now
    ));
    a_ch.stream_mut()
        .write_all(b"signed member channel")
        .await
        .unwrap();
    let mut bytes = [0u8; 21];
    b_ch.stream_mut().read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"signed member channel");
    b.member.pause().unwrap();
    assert_eq!(
        a_ch.revalidate_membership(b.member.as_ref()),
        Err(SecurePeerError::UntrustedMembership)
    );
    a_ch.stream_mut().shutdown().await.unwrap();
}

#[tokio::test]
async fn paused_membership_refuses_real_tls_association() {
    let a = Peer::new(4, 51);
    let b = Peer::new(7, 69);
    a.member.pause().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = async {
        let (tcp, _) = listener.accept().await.unwrap();
        accept(tcp, b.identity(), a.context(), a.member.as_ref()).await
    };
    let connector = async {
        connect(
            TcpStream::connect(address).await.unwrap(),
            a.identity(),
            b.context(),
            b.member.as_ref(),
        )
        .await
    };
    let (left, right) = timeout(Duration::from_secs(5), async {
        tokio::join!(connector, acceptor)
    })
    .await
    .unwrap();
    assert!(left.is_err());
    assert_eq!(right.err(), Some(SecurePeerError::UntrustedMembership));
}

#[tokio::test]
async fn tls_key_epoch_cannot_impersonate_membership_epoch() {
    let mut a = Peer::new(4, 51);
    let b = Peer::new(7, 69);
    a.epoch = 51;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = async {
        let (tcp, _) = listener.accept().await.unwrap();
        accept(tcp, b.identity(), a.context(), a.member.as_ref()).await
    };
    let connector = async {
        connect(
            TcpStream::connect(address).await.unwrap(),
            a.identity(),
            b.context(),
            b.member.as_ref(),
        )
        .await
    };
    let (left, right) = timeout(Duration::from_secs(5), async {
        tokio::join!(connector, acceptor)
    })
    .await
    .unwrap();
    assert!(left.is_err());
    assert_eq!(right.err(), Some(SecurePeerError::UntrustedMembership));
}

// This candidate only verifies signed fields; it never creates AdmissionPermit.
struct GrantFixture {
    trust: VerifiedResourceTrust,
    owner: SigningKey,
    event: CanonicalSecurityEvent,
    now: u64,
}
impl GrantFixture {
    fn new(member: &VerifiedMembership, root_seed: u8) -> Self {
        let root = SigningKey::from_bytes(&[root_seed; 32]);
        let owner = SigningKey::from_bytes(&[93; 32]);
        let (start, end) = member.validity_interval();
        let now = start + 100;
        let manifest = ResourceTrustManifest {
            space: space(),
            resource: ResourceId::from_bytes([82; 16]),
            owner_public_key: owner.verifying_key().to_bytes(),
            owner_key_epoch: 9,
            witness_public_keys: [94, 95]
                .map(|v| SigningKey::from_bytes(&[v; 32]).verifying_key().to_bytes()),
            writer_epoch: 3,
            root_key_epoch: 1,
            issued_at_ms: start,
            expires_at_ms: end,
        };
        let trust = verify_resource_trust_for_spike(
            &ExternallyPinnedRootForSpike {
                space: space(),
                public_key: root.verifying_key().to_bytes(),
                key_epoch: 1,
            },
            &SignedResourceTrust {
                manifest,
                signature: root.sign(&trust_manifest_transcript(&manifest)).to_bytes(),
            },
            now,
        )
        .unwrap();
        let event = CanonicalSecurityEvent {
            kind: EventKind::OwnerGrant,
            space_id: *space().as_bytes(),
            signer_key_id: issuer_key_id(&owner.verifying_key().to_bytes()),
            issuer_epoch: 9,
            issued_at_ms: start,
            expires_at_ms: end,
            seq: 5,
            payload: owner_grant_payload(trust.resource(), member, 1),
        };
        Self {
            trust,
            owner,
            event,
            now,
        }
    }
    fn verify(
        &self,
        member: &VerifiedMembership,
        event: &CanonicalSecurityEvent,
        key: &SigningKey,
        sequence: u64,
    ) -> Result<VerifiedOwnerGrant, GrantError> {
        let bytes = encode_security_event(event).unwrap();
        verify_owner_grant_for_spike(
            &self.trust,
            member,
            sequence,
            &bytes,
            &key.sign(&signing_input(&bytes).unwrap()).to_bytes(),
            self.now,
        )
    }
}

#[test]
fn owner_grant_binds_root_resource_member_epochs_actions_and_time() {
    let peer = Peer::new(4, 51);
    let f = GrantFixture::new(&peer.credential, 91);
    let grant = f.verify(&peer.credential, &f.event, &f.owner, 5).unwrap();
    assert_eq!(grant.subject_epochs(), (4, 51));
    assert_eq!(grant.sequence(), 5);
    assert!(grant.matches(
        peer.credential.peer(),
        space(),
        f.trust.resource(),
        Action::Read,
        f.now
    ));
    for (id, scope, resource, action, now) in [
        (
            PeerId::from_digest([0; 32]),
            space(),
            f.trust.resource(),
            Action::Read,
            f.now,
        ),
        (
            peer.credential.peer(),
            SpaceId::from_bytes([0; 16]),
            f.trust.resource(),
            Action::Read,
            f.now,
        ),
        (
            peer.credential.peer(),
            space(),
            ResourceId::from_bytes([0; 16]),
            Action::Read,
            f.now,
        ),
        (
            peer.credential.peer(),
            space(),
            f.trust.resource(),
            Action::Write,
            f.now,
        ),
        (
            peer.credential.peer(),
            space(),
            f.trust.resource(),
            Action::Read,
            f.event.issued_at_ms - 1,
        ),
        (
            peer.credential.peer(),
            space(),
            f.trust.resource(),
            Action::Read,
            f.event.expires_at_ms,
        ),
    ] {
        assert!(!grant.matches(id, scope, resource, action, now));
    }
    let other_root = GrantFixture::new(&peer.credential, 90);
    assert_eq!(
        other_root.verify(&peer.credential, &other_root.event, &other_root.owner, 5),
        Err(GrantError::InvalidTrust)
    );
}

#[test]
fn owner_grant_refuses_stale_policy_and_membership_writer_authority() {
    let peer = Peer::new(4, 51);
    let f = GrantFixture::new(&peer.credential, 91);
    for current in [0, 4, 6] {
        assert_eq!(
            f.verify(&peer.credential, &f.event, &f.owner, current),
            Err(GrantError::InvalidSequence)
        );
    }
    let writer = SigningKey::from_bytes(&[92; 32]);
    assert_eq!(
        f.verify(&peer.credential, &f.event, &writer, 5),
        Err(GrantError::InvalidSignature)
    );
    let mut event = f.event.clone();
    event.signer_key_id = issuer_key_id(&writer.verifying_key().to_bytes());
    assert_eq!(
        f.verify(&peer.credential, &event, &writer, 5),
        Err(GrantError::InvalidScope)
    );
}

#[test]
fn owner_grant_refuses_signed_field_substitution() {
    let peer = Peer::new(4, 51);
    let f = GrantFixture::new(&peer.credential, 91);
    for (offset, error) in [
        (0, GrantError::InvalidScope),
        (16, GrantError::InvalidSubject),
        (48, GrantError::InvalidSubject),
        (56, GrantError::InvalidSubject),
    ] {
        let mut event = f.event.clone();
        event.payload[offset] ^= 1;
        assert_eq!(f.verify(&peer.credential, &event, &f.owner, 5), Err(error));
    }
    for mask in [0, 16, 255] {
        let mut event = f.event.clone();
        event.payload[64] = mask;
        assert_eq!(
            f.verify(&peer.credential, &event, &f.owner, 5),
            Err(GrantError::InvalidPayload)
        );
    }
    let mut event = f.event.clone();
    event.issuer_epoch += 1;
    assert_eq!(
        f.verify(&peer.credential, &event, &f.owner, 5),
        Err(GrantError::InvalidEpoch)
    );
    event = f.event.clone();
    event.kind = EventKind::MembershipGrant;
    assert_eq!(
        f.verify(&peer.credential, &event, &f.owner, 5),
        Err(GrantError::WrongKind)
    );
    for before in [true, false] {
        event = f.event.clone();
        if before {
            event.issued_at_ms -= 1;
        } else {
            event.expires_at_ms += 1;
        }
        assert_eq!(
            f.verify(&peer.credential, &event, &f.owner, 5),
            Err(GrantError::InvalidTime)
        );
    }
}

#[test]
fn owner_grant_refuses_tampered_truncated_and_noncanonical_input() {
    let peer = Peer::new(4, 51);
    let f = GrantFixture::new(&peer.credential, 91);
    let mut bytes = encode_security_event(&f.event).unwrap();
    let signature = f.owner.sign(&signing_input(&bytes).unwrap()).to_bytes();
    for length in 0..bytes.len() {
        assert!(
            verify_owner_grant_for_spike(
                &f.trust,
                &peer.credential,
                5,
                &bytes[..length],
                &signature,
                f.now
            )
            .is_err()
        );
    }
    bytes.push(0);
    assert_eq!(
        verify_owner_grant_for_spike(&f.trust, &peer.credential, 5, &bytes, &signature, f.now),
        Err(GrantError::NonCanonical)
    );
    bytes.pop();
    let last = bytes.len() - 1;
    bytes[last] = 3; // valid action bits, invalid signature
    assert_eq!(
        verify_owner_grant_for_spike(&f.trust, &peer.credential, 5, &bytes, &signature, f.now),
        Err(GrantError::InvalidSignature)
    );
}

struct ChangingMembership<'a> {
    inner: &'a SignedMembershipVerifier,
    calls: AtomicUsize,
    change_identity: bool,
}
impl MembershipVerifier for ChangingMembership<'_> {
    fn verify_membership(&self, principal: &PeerPrincipal) -> Result<(), CryptoError> {
        self.inner.verify_membership(principal)
    }
    fn resolve_principal(
        &self,
        peer: PeerId,
        space: SpaceId,
        key_epoch: u64,
    ) -> Result<PeerPrincipal, CryptoError> {
        let mut principal = self.inner.resolve_principal(peer, space, key_epoch)?;
        if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
            if !self.change_identity {
                return Err(CryptoError::InvalidIdentity);
            }
            principal.membership_epoch += 1;
        }
        Ok(principal)
    }
}
#[tokio::test]
async fn membership_is_rechecked_after_asynchronous_association() {
    for change_identity in [false, true] {
        let a = Peer::new(4, 51);
        let b = Peer::new(7, 69);
        let av = ChangingMembership {
            inner: &a.member,
            calls: AtomicUsize::new(0),
            change_identity,
        };
        let bv = ChangingMembership {
            inner: &b.member,
            calls: AtomicUsize::new(0),
            change_identity,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = async {
            let (tcp, _) = listener.accept().await.unwrap();
            accept(tcp, b.identity(), a.context(), &av).await
        };
        let connected = async {
            connect(
                TcpStream::connect(address).await.unwrap(),
                a.identity(),
                b.context(),
                &bv,
            )
            .await
        };
        let (left, right) = timeout(Duration::from_secs(5), async {
            tokio::join!(connected, accepted)
        })
        .await
        .unwrap();
        assert_eq!(left.err(), Some(SecurePeerError::UntrustedMembership));
        assert_eq!(right.err(), Some(SecurePeerError::UntrustedMembership));
        assert_eq!(av.calls.load(Ordering::SeqCst), 2);
        assert_eq!(bv.calls.load(Ordering::SeqCst), 2);
    }
}
