//! L-002F remote Witness RPC service.
//!
//! Each process owns one Root-pinned Witness key and one local append-only
//! SQLite log. The transport uses TLS 1.3 with the Ed25519 certificate key
//! pinned to the Witness public key in the Root-signed resource manifest.
//! Append requests remain Owner-signed end-to-end; reads are fresh-nonce,
//! Witness-signed observations. A successful append RPC is NOT quorum success.
//!
//! Run two instances under separate operators / hosts / credentials. This
//! service does not claim hardware anti-rollback or physical independence.

use ed25519_dalek::SigningKey;
use loom_crypto::{space_trust::VerifiedResourceTrust, witness_checkpoint::TrustedWitnessForSpike};
use loom_store::{
    challenge_witness_quorum::{
        QuorumChallenge, QuorumHighWater, QuorumObservation, SignedQuorumObservation,
    },
    remote_witness_quorum::{WitnessEndpoint, WitnessEndpointError},
    witness_append::{AppendError, SIGNED_APPEND_BYTES, SignedAppend, WitnessLog},
};
use loom_types::{ResourceId, SpaceId};
use loom_wire::{MAX_FRAME_BYTES, MAX_PREFIX_BYTES, decode_frame, encode_frame};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_rustls::rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use x509_parser::prelude::{FromDer, X509Certificate};

const TLS_SERVER_NAME: &str = "loom-witness.local";
const REQUEST_MAGIC: &[u8; 4] = b"LWR1";
const RESPONSE_MAGIC: &[u8; 4] = b"LWS1";
const OP_APPEND: u8 = 1;
const OP_OBSERVE: u8 = 2;
const CHALLENGE_BYTES: usize = 72;
const OBSERVATION_BYTES: usize = 288;
const MAX_CONNECTIONS_HARD_LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessRpcError {
    Io,
    InvalidFrame,
    InvalidMessage,
    InvalidCertificate,
    WrongWitnessIdentity,
    InvalidTlsConfiguration,
    InvalidServerConfiguration,
}

/// One service instance is bound to exactly one Root-pinned Witness key and
/// one enrolled SQLite log. The mutex serializes append / observe operations.
pub struct WitnessRpcService {
    signer: SigningKey,
    log: Mutex<WitnessLog>,
}

impl WitnessRpcService {
    pub fn new(
        trust: VerifiedResourceTrust,
        signer: SigningKey,
        log: WitnessLog,
    ) -> Result<Self, WitnessRpcError> {
        let key_id =
            TrustedWitnessForSpike::from_public_key(signer.verifying_key().to_bytes()).key_id;
        if log.manifest_commitment() != trust.manifest_commitment()
            || !trust
                .witnesses()
                .iter()
                .any(|witness| witness.key_id == key_id)
        {
            return Err(WitnessRpcError::WrongWitnessIdentity);
        }
        Ok(Self {
            signer,
            log: Mutex::new(log),
        })
    }

    pub fn witness_public_key(&self) -> [u8; 32] {
        self.signer.verifying_key().to_bytes()
    }

    fn append(&self, signed: SignedAppend) -> Result<(), AppendError> {
        let now = unix_time_ms().map_err(|_| AppendError::Storage)?;
        self.log
            .lock()
            .map_err(|_| AppendError::Storage)?
            .append(signed, now)
            .map(|_| ())
    }

    fn observe(&self, challenge: QuorumChallenge) -> Result<SignedQuorumObservation, AppendError> {
        let now = unix_time_ms().map_err(|_| AppendError::Storage)?;
        self.log
            .lock()
            .map_err(|_| AppendError::Storage)?
            .observe(&self.signer, challenge, now)
    }

    fn process(&self, request: &[u8]) -> Vec<u8> {
        match decode_request(request) {
            Ok(Request::Append(signed)) => encode_append_response(self.append(signed)),
            Ok(Request::Observe(challenge)) => encode_observe_response(self.observe(challenge)),
            Err(_) => encode_protocol_error(),
        }
    }
}

/// Bounded thread-per-connection TLS listener. Each connection carries exactly
/// one framed request and one response; no unbounded request loop or buffering.
pub struct WitnessRpcServer {
    service: Arc<WitnessRpcService>,
    tls: Arc<ServerConfig>,
    max_connections: usize,
    io_timeout: Duration,
}

impl WitnessRpcServer {
    pub fn new(
        service: WitnessRpcService,
        certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
        max_connections: usize,
        io_timeout: Duration,
    ) -> Result<Self, WitnessRpcError> {
        if max_connections == 0
            || max_connections > MAX_CONNECTIONS_HARD_LIMIT
            || io_timeout.is_zero()
        {
            return Err(WitnessRpcError::InvalidServerConfiguration);
        }
        let certificate_key = certificate_ed25519_key(&certificate_der)?;
        if certificate_key != service.witness_public_key() {
            return Err(WitnessRpcError::WrongWitnessIdentity);
        }
        let certificate = CertificateDer::from(certificate_der);
        let private_key = PrivateKeyDer::Pkcs8(private_key_der.into());
        let tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .map_err(|_| WitnessRpcError::InvalidTlsConfiguration)?;
        Ok(Self {
            service: Arc::new(service),
            tls: Arc::new(tls),
            max_connections,
            io_timeout,
        })
    }

    /// Blocks until shutdown becomes true or the listener fails. The listener
    /// is nonblocking so shutdown is observed without a signal-handler runtime.
    /// Accepted connections finish independently.
    pub fn serve(
        &self,
        listener: TcpListener,
        shutdown: &AtomicBool,
    ) -> Result<(), WitnessRpcError> {
        listener
            .set_nonblocking(true)
            .map_err(|_| WitnessRpcError::Io)?;
        let active = Arc::new(AtomicUsize::new(0));
        while !shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((socket, _peer)) => {
                    if active.load(Ordering::Acquire) >= self.max_connections {
                        drop(socket);
                        continue;
                    }
                    active.fetch_add(1, Ordering::AcqRel);
                    let guard = ConnectionGuard(Arc::clone(&active));
                    let service = Arc::clone(&self.service);
                    let tls = Arc::clone(&self.tls);
                    let timeout = self.io_timeout;
                    let spawn = thread::Builder::new()
                        .name("loom-witness-rpc".to_owned())
                        .spawn(move || {
                            let _guard = guard;
                            let _ = serve_connection(socket, service, tls, timeout);
                        });
                    if spawn.is_err() {
                        // The moved guard is dropped with the failed closure.
                        continue;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(WitnessRpcError::Io),
            }
        }
        Ok(())
    }
}

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Synchronous TLS client adapter for the existing WitnessEndpoint
/// coordinator. Each operation opens a fresh TLS connection with bounded IO.
pub struct TlsWitnessEndpoint {
    address: SocketAddr,
    tls: Arc<ClientConfig>,
    witness_key_id: [u8; 32],
    io_timeout: Duration,
}

impl TlsWitnessEndpoint {
    /// certificate_der must be provisioned out-of-band and its Ed25519
    /// subject key must equal the Root-pinned Witness key. The certificate SAN
    /// must contain loom-witness.local.
    pub fn new(
        address: SocketAddr,
        certificate_der: Vec<u8>,
        expected_witness_key: [u8; 32],
        io_timeout: Duration,
    ) -> Result<Self, WitnessRpcError> {
        if io_timeout.is_zero() {
            return Err(WitnessRpcError::InvalidServerConfiguration);
        }
        if certificate_ed25519_key(&certificate_der)? != expected_witness_key {
            return Err(WitnessRpcError::WrongWitnessIdentity);
        }
        let certificate = CertificateDer::from(certificate_der);
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate)
            .map_err(|_| WitnessRpcError::InvalidTlsConfiguration)?;
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let key_id = TrustedWitnessForSpike::from_public_key(expected_witness_key).key_id;
        Ok(Self {
            address,
            tls: Arc::new(tls),
            witness_key_id: key_id,
            io_timeout,
        })
    }

    fn transact(&self, request: &[u8]) -> Result<Vec<u8>, WitnessEndpointError> {
        let socket = TcpStream::connect_timeout(&self.address, self.io_timeout)
            .map_err(|_| WitnessEndpointError::Unavailable)?;
        socket
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| WitnessEndpointError::Unavailable)?;
        socket
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| WitnessEndpointError::Unavailable)?;
        socket
            .set_nodelay(true)
            .map_err(|_| WitnessEndpointError::Unavailable)?;
        let server_name = ServerName::try_from(TLS_SERVER_NAME.to_owned())
            .map_err(|_| WitnessEndpointError::Protocol)?;
        let connection = ClientConnection::new(Arc::clone(&self.tls), server_name)
            .map_err(|_| WitnessEndpointError::Protocol)?;
        let mut tls = StreamOwned::new(connection, socket);
        write_frame(&mut tls, request).map_err(|_| WitnessEndpointError::Unavailable)?;
        read_frame(&mut tls).map_err(|_| WitnessEndpointError::Unavailable)
    }
}

impl WitnessEndpoint for TlsWitnessEndpoint {
    fn witness_key_id(&self) -> [u8; 32] {
        self.witness_key_id
    }

    fn append(
        &self,
        signed: SignedAppend,
        _client_now_ms: u64,
    ) -> Result<(), WitnessEndpointError> {
        // The server ignores client wall-clock input and validates against its
        // own clock. The coordinator still prevalidates the event locally.
        let request = encode_append_request(signed);
        let response = self.transact(&request)?;
        decode_append_response(&response)
    }

    fn observe(
        &self,
        challenge: QuorumChallenge,
        _client_now_ms: u64,
    ) -> Result<SignedQuorumObservation, WitnessEndpointError> {
        let request = encode_observe_request(challenge);
        let response = self.transact(&request)?;
        let observation = decode_observe_response(&response)?;
        if observation.witness_key_id != self.witness_key_id
            || observation.observation.challenge != challenge
        {
            return Err(WitnessEndpointError::Protocol);
        }
        Ok(observation)
    }
}

#[derive(Clone, Copy)]
enum Request {
    Append(SignedAppend),
    Observe(QuorumChallenge),
}

fn encode_append_request(signed: SignedAppend) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + SIGNED_APPEND_BYTES);
    out.extend_from_slice(REQUEST_MAGIC);
    out.push(OP_APPEND);
    out.extend_from_slice(&signed.encode());
    out
}

fn encode_observe_request(challenge: QuorumChallenge) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + CHALLENGE_BYTES);
    out.extend_from_slice(REQUEST_MAGIC);
    out.push(OP_OBSERVE);
    encode_challenge(&mut out, challenge);
    out
}

fn decode_request(bytes: &[u8]) -> Result<Request, WitnessRpcError> {
    if bytes.len() < 5 || &bytes[..4] != REQUEST_MAGIC {
        return Err(WitnessRpcError::InvalidMessage);
    }
    match bytes[4] {
        OP_APPEND if bytes.len() == 5 + SIGNED_APPEND_BYTES => SignedAppend::decode(&bytes[5..])
            .map(Request::Append)
            .map_err(|_| WitnessRpcError::InvalidMessage),
        OP_OBSERVE if bytes.len() == 5 + CHALLENGE_BYTES => decode_challenge(&bytes[5..])
            .map(Request::Observe)
            .map_err(|_| WitnessRpcError::InvalidMessage),
        _ => Err(WitnessRpcError::InvalidMessage),
    }
}

fn encode_challenge(out: &mut Vec<u8>, challenge: QuorumChallenge) {
    out.extend_from_slice(&challenge.nonce);
    out.extend_from_slice(challenge.expected_space.as_bytes());
    out.extend_from_slice(challenge.expected_resource.as_bytes());
    out.extend_from_slice(&challenge.expected_writer_epoch.to_be_bytes());
}

fn decode_challenge(bytes: &[u8]) -> Result<QuorumChallenge, WitnessRpcError> {
    if bytes.len() != CHALLENGE_BYTES {
        return Err(WitnessRpcError::InvalidMessage);
    }
    let mut pos = 0;
    Ok(QuorumChallenge {
        nonce: take(bytes, &mut pos)?,
        expected_space: SpaceId::from_bytes(take(bytes, &mut pos)?),
        expected_resource: ResourceId::from_bytes(take(bytes, &mut pos)?),
        expected_writer_epoch: u64::from_be_bytes(take(bytes, &mut pos)?),
    })
}

fn encode_observation(observation: &SignedQuorumObservation) -> Vec<u8> {
    let mut out = Vec::with_capacity(OBSERVATION_BYTES);
    out.extend_from_slice(&observation.witness_key_id);
    encode_challenge(&mut out, observation.observation.challenge);
    out.extend_from_slice(&observation.observation.generation.to_be_bytes());
    let high_water = observation.observation.high_water;
    out.extend_from_slice(high_water.space.as_bytes());
    out.extend_from_slice(high_water.resource.as_bytes());
    out.extend_from_slice(&high_water.writer_epoch.to_be_bytes());
    out.extend_from_slice(&high_water.sequence.to_be_bytes());
    out.extend_from_slice(&high_water.policy_head);
    out.extend_from_slice(&high_water.revocation_root);
    out.extend_from_slice(&observation.signature);
    out
}

fn decode_observation(bytes: &[u8]) -> Result<SignedQuorumObservation, WitnessRpcError> {
    if bytes.len() != OBSERVATION_BYTES {
        return Err(WitnessRpcError::InvalidMessage);
    }
    let mut pos = 0;
    let witness_key_id = take(bytes, &mut pos)?;
    let challenge = decode_challenge(
        bytes
            .get(pos..pos + CHALLENGE_BYTES)
            .ok_or(WitnessRpcError::InvalidMessage)?,
    )?;
    pos += CHALLENGE_BYTES;
    let generation = u64::from_be_bytes(take(bytes, &mut pos)?);
    let high_water = QuorumHighWater {
        space: SpaceId::from_bytes(take(bytes, &mut pos)?),
        resource: ResourceId::from_bytes(take(bytes, &mut pos)?),
        writer_epoch: u64::from_be_bytes(take(bytes, &mut pos)?),
        sequence: u64::from_be_bytes(take(bytes, &mut pos)?),
        policy_head: take(bytes, &mut pos)?,
        revocation_root: take(bytes, &mut pos)?,
    };
    let signature = take(bytes, &mut pos)?;
    let observation = QuorumObservation {
        challenge,
        generation,
        high_water,
    };
    Ok(SignedQuorumObservation {
        witness_key_id,
        observation,
        signature,
    })
}

fn take<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], WitnessRpcError> {
    let end = pos.checked_add(N).ok_or(WitnessRpcError::InvalidMessage)?;
    let value = bytes
        .get(*pos..end)
        .ok_or(WitnessRpcError::InvalidMessage)?;
    *pos = end;
    value
        .try_into()
        .map_err(|_| WitnessRpcError::InvalidMessage)
}

fn encode_append_response(result: Result<(), AppendError>) -> Vec<u8> {
    let (status, code) = match result {
        Ok(()) => (0, 0),
        Err(AppendError::Storage) => (1, 1),
        Err(AppendError::InvalidRecord) => (1, 2),
        Err(AppendError::InvalidSignature) => (1, 3),
        Err(AppendError::WrongTrust) => (1, 4),
        Err(AppendError::Expired) => (1, 5),
        Err(AppendError::Conflict | AppendError::Fork(_)) => (1, 6),
    };
    vec![
        RESPONSE_MAGIC[0],
        RESPONSE_MAGIC[1],
        RESPONSE_MAGIC[2],
        RESPONSE_MAGIC[3],
        status,
        code,
    ]
}

fn decode_append_response(bytes: &[u8]) -> Result<(), WitnessEndpointError> {
    if bytes.len() != 6 || &bytes[..4] != RESPONSE_MAGIC {
        return Err(WitnessEndpointError::Protocol);
    }
    match (bytes[4], bytes[5]) {
        (0, 0) => Ok(()),
        (1, 1) => Err(WitnessEndpointError::Rejected(AppendError::Storage)),
        (1, 2) => Err(WitnessEndpointError::Rejected(AppendError::InvalidRecord)),
        (1, 3) => Err(WitnessEndpointError::Rejected(
            AppendError::InvalidSignature,
        )),
        (1, 4) => Err(WitnessEndpointError::Rejected(AppendError::WrongTrust)),
        (1, 5) => Err(WitnessEndpointError::Rejected(AppendError::Expired)),
        (1, 6) => Err(WitnessEndpointError::Rejected(AppendError::Conflict)),
        _ => Err(WitnessEndpointError::Protocol),
    }
}

fn encode_observe_response(result: Result<SignedQuorumObservation, AppendError>) -> Vec<u8> {
    match result {
        Ok(observation) => {
            let mut out = Vec::with_capacity(5 + OBSERVATION_BYTES);
            out.extend_from_slice(RESPONSE_MAGIC);
            out.push(0);
            out.extend_from_slice(&encode_observation(&observation));
            out
        }
        Err(AppendError::WrongTrust) => vec![
            RESPONSE_MAGIC[0],
            RESPONSE_MAGIC[1],
            RESPONSE_MAGIC[2],
            RESPONSE_MAGIC[3],
            1,
            4,
        ],
        Err(_) => vec![
            RESPONSE_MAGIC[0],
            RESPONSE_MAGIC[1],
            RESPONSE_MAGIC[2],
            RESPONSE_MAGIC[3],
            1,
            1,
        ],
    }
}

fn decode_observe_response(bytes: &[u8]) -> Result<SignedQuorumObservation, WitnessEndpointError> {
    if bytes.len() == 6 && &bytes[..4] == RESPONSE_MAGIC && bytes[4] == 1 {
        return Err(match bytes[5] {
            4 => WitnessEndpointError::Rejected(AppendError::WrongTrust),
            _ => WitnessEndpointError::Rejected(AppendError::Storage),
        });
    }
    if bytes.len() != 5 + OBSERVATION_BYTES || &bytes[..4] != RESPONSE_MAGIC || bytes[4] != 0 {
        return Err(WitnessEndpointError::Protocol);
    }
    decode_observation(&bytes[5..]).map_err(|_| WitnessEndpointError::Protocol)
}

fn encode_protocol_error() -> Vec<u8> {
    vec![
        RESPONSE_MAGIC[0],
        RESPONSE_MAGIC[1],
        RESPONSE_MAGIC[2],
        RESPONSE_MAGIC[3],
        1,
        2,
    ]
}

fn certificate_ed25519_key(der: &[u8]) -> Result<[u8; 32], WitnessRpcError> {
    let (remaining, certificate) =
        X509Certificate::from_der(der).map_err(|_| WitnessRpcError::InvalidCertificate)?;
    if !remaining.is_empty()
        || certificate.public_key().algorithm.algorithm.to_id_string() != "1.3.101.112"
        || certificate.signature_algorithm.algorithm.to_id_string() != "1.3.101.112"
    {
        return Err(WitnessRpcError::InvalidCertificate);
    }
    certificate
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| WitnessRpcError::InvalidCertificate)
}

fn serve_connection(
    socket: TcpStream,
    service: Arc<WitnessRpcService>,
    tls_config: Arc<ServerConfig>,
    io_timeout: Duration,
) -> Result<(), WitnessRpcError> {
    socket
        .set_read_timeout(Some(io_timeout))
        .map_err(|_| WitnessRpcError::Io)?;
    socket
        .set_write_timeout(Some(io_timeout))
        .map_err(|_| WitnessRpcError::Io)?;
    socket.set_nodelay(true).map_err(|_| WitnessRpcError::Io)?;
    let connection =
        ServerConnection::new(tls_config).map_err(|_| WitnessRpcError::InvalidTlsConfiguration)?;
    let mut tls = StreamOwned::new(connection, socket);
    let request = read_frame(&mut tls)?;
    let response = service.process(&request);
    write_frame(&mut tls, &response)
}

fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, WitnessRpcError> {
    let mut prefix = Vec::with_capacity(MAX_PREFIX_BYTES);
    let mut length = 0_u64;
    let mut complete = false;
    for index in 0..MAX_PREFIX_BYTES {
        let mut byte = [0_u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|_| WitnessRpcError::Io)?;
        prefix.push(byte[0]);
        length |= u64::from(byte[0] & 0x7f) << (7 * index);
        if byte[0] & 0x80 == 0 {
            if index > 0 && byte[0] == 0 {
                return Err(WitnessRpcError::InvalidFrame);
            }
            complete = true;
            break;
        }
    }
    if !complete || length > MAX_FRAME_BYTES as u64 {
        return Err(WitnessRpcError::InvalidFrame);
    }
    let mut payload = vec![0_u8; length as usize];
    reader
        .read_exact(&mut payload)
        .map_err(|_| WitnessRpcError::Io)?;
    prefix.extend_from_slice(&payload);
    let (decoded, remaining) = decode_frame(&prefix).map_err(|_| WitnessRpcError::InvalidFrame)?;
    if !remaining.is_empty() {
        return Err(WitnessRpcError::InvalidFrame);
    }
    Ok(decoded.to_vec())
}

fn write_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), WitnessRpcError> {
    let encoded = encode_frame(payload).map_err(|_| WitnessRpcError::InvalidFrame)?;
    writer
        .write_all(&encoded)
        .and_then(|_| writer.flush())
        .map_err(|_| WitnessRpcError::Io)
}

fn unix_time_ms() -> Result<u64, WitnessRpcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WitnessRpcError::Io)?
        .as_millis()
        .try_into()
        .map_err(|_| WitnessRpcError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_crypto::space_trust::{
        ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
        trust_manifest_transcript, verify_resource_trust_for_spike,
    };
    use loom_store::{
        remote_witness_quorum::{WitnessClientError, WitnessQuorumClient},
        witness_append::{AppendRequest, ReadMutation, append_transcript},
    };
    use loom_types::{PeerId, ResourceId, SpaceId};
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use std::{fs, net::TcpListener};

    static NEXT_DB: AtomicUsize = AtomicUsize::new(0);

    fn temp_db() -> std::path::PathBuf {
        let id = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "loom-witness-rpc-{}-{id}.sqlite",
            std::process::id()
        ))
    }

    fn now_ms() -> u64 {
        unix_time_ms().unwrap()
    }

    fn fixture(
        first_witness_key: &SigningKey,
        second_witness_key: &SigningKey,
    ) -> (VerifiedResourceTrust, SigningKey) {
        let now = now_ms();
        let root_key = SigningKey::from_bytes(&[30; 32]);
        let owner_key = SigningKey::from_bytes(&[11; 32]);
        let root_pin = ExternallyPinnedRootForSpike {
            space: SpaceId::from_bytes([1; 16]),
            public_key: root_key.verifying_key().to_bytes(),
            key_epoch: 7,
        };
        let manifest = ResourceTrustManifest {
            space: root_pin.space,
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner_key.verifying_key().to_bytes(),
            owner_key_epoch: 3,
            witness_public_keys: [
                first_witness_key.verifying_key().to_bytes(),
                second_witness_key.verifying_key().to_bytes(),
            ],
            writer_epoch: 1,
            root_key_epoch: 7,
            issued_at_ms: now.saturating_sub(1_000),
            expires_at_ms: now.saturating_add(3_600_000),
        };
        let signed = SignedResourceTrust {
            manifest,
            signature: root_key
                .sign(&trust_manifest_transcript(&manifest))
                .to_bytes(),
        };
        (
            verify_resource_trust_for_spike(&root_pin, &signed, now).unwrap(),
            owner_key,
        )
    }

    fn tls_identity(seed: [u8; 32]) -> (SigningKey, Vec<u8>, Vec<u8>) {
        // RFC 8410 Ed25519 PKCS#8 PrivateKeyInfo with a 32-byte seed.
        let mut private_key = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        private_key.extend_from_slice(&seed);
        let pair = KeyPair::from_der(&private_key).unwrap();
        let signer = SigningKey::from_bytes(&seed);
        let params = CertificateParams::new(vec![TLS_SERVER_NAME.to_owned()]).unwrap();
        let certificate = params.self_signed(&pair).unwrap();
        (signer, certificate.der().to_vec(), private_key)
    }

    fn genesis(trust: &VerifiedResourceTrust) -> QuorumHighWater {
        QuorumHighWater {
            space: trust.space(),
            resource: trust.resource(),
            writer_epoch: trust.writer_epoch(),
            sequence: 0,
            policy_head: [0; 32],
            revocation_root: [0; 32],
        }
    }

    fn signed_append_for_state(
        trust: &VerifiedResourceTrust,
        owner: &SigningKey,
        current: QuorumHighWater,
        peer_byte: u8,
        allow: bool,
        now: u64,
    ) -> SignedAppend {
        let request = AppendRequest {
            manifest: trust.manifest_commitment(),
            expected_generation: current.sequence,
            previous_head: current.policy_head,
            mutation: ReadMutation {
                peer: PeerId::from_digest([peer_byte; 32]),
                key_epoch: 1,
                member_epoch: 1,
                allow,
            },
            issued_at_ms: now.saturating_sub(1),
            expires_at_ms: now.saturating_add(60_000),
        };
        SignedAppend {
            request,
            owner_signature: owner.sign(&append_transcript(&request)).to_bytes(),
        }
    }

    fn signed_append(trust: &VerifiedResourceTrust, owner: &SigningKey, now: u64) -> SignedAppend {
        signed_append_for_state(trust, owner, genesis(trust), 41, true, now)
    }

    fn start_server(
        trust: VerifiedResourceTrust,
        signer: SigningKey,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        log: WitnessLog,
    ) -> (SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let service = WitnessRpcService::new(trust, signer, log).unwrap();
        let server =
            WitnessRpcServer::new(service, certificate, private_key, 8, Duration::from_secs(3))
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || server.serve(listener, &server_shutdown).unwrap());
        (address, shutdown, handle)
    }

    #[test]
    fn remote_tls_append_and_challenge_observation_roundtrip() {
        let (witness_signer, certificate, private_key) = tls_identity([21; 32]);
        let second_witness_signer = SigningKey::from_bytes(&[22; 32]);
        let (trust, owner) = fixture(&witness_signer, &second_witness_signer);
        let db = temp_db();
        let _ = fs::remove_file(&db);
        let log = WitnessLog::create(&db, trust).unwrap();
        let service = WitnessRpcService::new(trust, witness_signer.clone(), log).unwrap();
        let server = WitnessRpcServer::new(
            service,
            certificate.clone(),
            private_key,
            8,
            Duration::from_secs(3),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let thread = thread::spawn(move || server.serve(listener, &server_shutdown).unwrap());

        let endpoint = TlsWitnessEndpoint::new(
            address,
            certificate,
            witness_signer.verifying_key().to_bytes(),
            Duration::from_secs(3),
        )
        .unwrap();
        let now = now_ms();
        let signed = signed_append(&trust, &owner, now);
        endpoint.append(signed, now).unwrap();

        let challenge = QuorumChallenge {
            nonce: [99; 32],
            expected_space: trust.space(),
            expected_resource: trust.resource(),
            expected_writer_epoch: trust.writer_epoch(),
        };
        let receipt = endpoint.observe(challenge, now).unwrap();
        assert_eq!(receipt.witness_key_id, endpoint.witness_key_id());
        assert_eq!(receipt.observation.challenge, challenge);
        assert_eq!(receipt.observation.high_water.sequence, 1);

        shutdown.store(true, Ordering::Release);
        thread.join().unwrap();
        let _ = fs::remove_file(db);
    }

    #[test]
    fn two_remote_witnesses_confirm_and_exact_retry_recovers_partial_commit() {
        let (signer_a, certificate_a, private_key_a) = tls_identity([21; 32]);
        let (signer_b, certificate_b, private_key_b) = tls_identity([22; 32]);
        let (trust, owner) = fixture(&signer_a, &signer_b);
        let db_a = temp_db();
        let db_b = temp_db();
        let _ = fs::remove_file(&db_a);
        let _ = fs::remove_file(&db_b);
        let log_a = WitnessLog::create(&db_a, trust).unwrap();
        let log_b = WitnessLog::create(&db_b, trust).unwrap();

        let (address_a, shutdown_a, thread_a) = start_server(
            trust,
            signer_a.clone(),
            certificate_a.clone(),
            private_key_a,
            log_a,
        );
        let (address_b, shutdown_b, thread_b) = start_server(
            trust,
            signer_b.clone(),
            certificate_b.clone(),
            private_key_b.clone(),
            log_b,
        );
        let endpoint_a = TlsWitnessEndpoint::new(
            address_a,
            certificate_a,
            signer_a.verifying_key().to_bytes(),
            Duration::from_secs(3),
        )
        .unwrap();
        let endpoint_b = TlsWitnessEndpoint::new(
            address_b,
            certificate_b.clone(),
            signer_b.verifying_key().to_bytes(),
            Duration::from_secs(3),
        )
        .unwrap();
        let client = WitnessQuorumClient::new(trust, &endpoint_a, &endpoint_b).unwrap();
        let now = now_ms();
        let first_event = signed_append_for_state(&trust, &owner, genesis(&trust), 41, true, now);
        let first = client
            .append_and_confirm(
                first_event,
                genesis(&trust),
                0,
                QuorumChallenge {
                    nonce: [101; 32],
                    expected_space: trust.space(),
                    expected_resource: trust.resource(),
                    expected_writer_epoch: trust.writer_epoch(),
                },
                now,
            )
            .unwrap();
        let current = first.high_water();
        let minimum_generation = first.generation();

        // Stop Witness B after A has already accepted the next event. The
        // coordinator must not claim success while the second endpoint is down.
        let second_event = signed_append_for_state(&trust, &owner, current, 42, false, now);
        shutdown_b.store(true, Ordering::Release);
        thread_b.join().unwrap();
        let partial = client.append_and_confirm(
            second_event,
            current,
            minimum_generation,
            QuorumChallenge {
                nonce: [102; 32],
                expected_space: trust.space(),
                expected_resource: trust.resource(),
                expected_writer_epoch: trust.writer_epoch(),
            },
            now,
        );
        assert_eq!(partial, Err(WitnessClientError::WitnessUnavailable));

        // Reopen B's durable log and retry the identical signed event. A's
        // duplicate is idempotent; B commits; fresh observations then agree.
        let reopened_b = WitnessLog::open(&db_b, trust).unwrap();
        let (address_b2, shutdown_b2, thread_b2) = start_server(
            trust,
            signer_b.clone(),
            certificate_b.clone(),
            private_key_b,
            reopened_b,
        );
        let endpoint_b2 = TlsWitnessEndpoint::new(
            address_b2,
            certificate_b,
            signer_b.verifying_key().to_bytes(),
            Duration::from_secs(3),
        )
        .unwrap();
        let retry_client = WitnessQuorumClient::new(trust, &endpoint_a, &endpoint_b2).unwrap();
        let confirmed = retry_client
            .append_and_confirm(
                second_event,
                current,
                minimum_generation,
                QuorumChallenge {
                    nonce: [103; 32],
                    expected_space: trust.space(),
                    expected_resource: trust.resource(),
                    expected_writer_epoch: trust.writer_epoch(),
                },
                now,
            )
            .unwrap();
        assert_eq!(confirmed.generation(), 2);
        assert_eq!(confirmed.high_water().sequence, 2);
        assert_ne!(
            confirmed.high_water().revocation_root,
            current.revocation_root
        );

        shutdown_a.store(true, Ordering::Release);
        shutdown_b2.store(true, Ordering::Release);
        thread_a.join().unwrap();
        thread_b2.join().unwrap();
        let _ = fs::remove_file(db_a);
        let _ = fs::remove_file(db_b);
    }

    #[test]
    fn tls_certificate_must_match_root_pinned_witness_key() {
        let (_signer, certificate, _) = tls_identity([23; 32]);
        let wrong = SigningKey::from_bytes(&[55; 32]);
        let result = TlsWitnessEndpoint::new(
            "127.0.0.1:9".parse().unwrap(),
            certificate,
            wrong.verifying_key().to_bytes(),
            Duration::from_secs(1),
        );
        assert!(matches!(result, Err(WitnessRpcError::WrongWitnessIdentity)));
    }

    #[test]
    fn observation_codec_roundtrips_all_signed_fields() {
        let observation = SignedQuorumObservation {
            witness_key_id: [1; 32],
            observation: QuorumObservation {
                challenge: QuorumChallenge {
                    nonce: [2; 32],
                    expected_space: SpaceId::from_bytes([3; 16]),
                    expected_resource: ResourceId::from_bytes([4; 16]),
                    expected_writer_epoch: 5,
                },
                generation: 6,
                high_water: QuorumHighWater {
                    space: SpaceId::from_bytes([3; 16]),
                    resource: ResourceId::from_bytes([4; 16]),
                    writer_epoch: 5,
                    sequence: 7,
                    policy_head: [8; 32],
                    revocation_root: [9; 32],
                },
            },
            signature: [10; 64],
        };
        let encoded = encode_observation(&observation);
        assert_eq!(encoded.len(), OBSERVATION_BYTES);
        let decoded = decode_observation(&encoded).unwrap();
        assert_eq!(decoded.witness_key_id, observation.witness_key_id);
        assert_eq!(
            decoded.observation.challenge,
            observation.observation.challenge
        );
        assert_eq!(
            decoded.observation.generation,
            observation.observation.generation
        );
        assert_eq!(
            decoded.observation.high_water,
            observation.observation.high_water
        );
        assert_eq!(decoded.signature, observation.signature);
    }
}
