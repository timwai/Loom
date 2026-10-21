//! Deliberately public fixture keys, used ONLY by tests and the lab executable.
use ed25519_dalek::{Signer, SigningKey};
use loom_crypto::{membership::*, owner_authority::issuer_key_id, space_trust::*};
use loom_identity::signed_membership::SignedMembershipVerifier;
use loom_store::{challenge_witness_quorum::*, witness_append::*};
use loom_transport::secure_channel::*;
use loom_types::{ResourceId, SpaceId};
use loom_wire::security_event::*;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}
pub fn space() -> SpaceId {
    SpaceId::from_bytes([101; 16])
}
pub fn resource() -> ResourceId {
    ResourceId::from_bytes([102; 16])
}
pub const CONTENT: &[u8] = b"LOOM-L002-PRIVATE-FILE-CANARY\nowner approved snapshot\n";
pub type LabResult<T> = Result<T, Box<dyn std::error::Error>>;

pub struct Fixture {
    pub directory: PathBuf,
    pub trust: VerifiedResourceTrust,
    pub owner: SigningKey,
    pub witness_keys: [SigningKey; 2],
    pub start: u64,
}
impl Fixture {
    pub fn enroll(directory: &Path) -> LabResult<Self> {
        fs::create_dir(directory)?;
        fs::write(directory.join("start"), (now() - 1000).to_string())?;
        for name in ["a", "b"] {
            let key = KeyPair::generate_for(&PKCS_ED25519)?;
            let cert = CertificateParams::new(vec!["loom-peer.local".into()])?.self_signed(&key)?;
            fs::write(directory.join(format!("{name}.pem")), key.serialize_pem())?;
            fs::write(directory.join(format!("{name}.der")), cert.der())?;
        }
        fs::write(directory.join("approved.txt"), CONTENT)?;
        let f = Self::load(directory)?;
        for name in ["policy", "witness-a", "witness-b"] {
            WitnessLog::create(&f.path(name), f.trust).map_err(|e| format!("create {e:?}"))?;
        }
        Ok(f)
    }
    pub fn load(directory: &Path) -> LabResult<Self> {
        let start = fs::read_to_string(directory.join("start"))?.parse::<u64>()?;
        let root = SigningKey::from_bytes(&[111; 32]);
        let owner = SigningKey::from_bytes(&[112; 32]);
        let witness_keys = [113, 114].map(|v| SigningKey::from_bytes(&[v; 32]));
        let manifest = ResourceTrustManifest {
            space: space(),
            resource: resource(),
            owner_public_key: owner.verifying_key().to_bytes(),
            owner_key_epoch: 2,
            witness_public_keys: witness_keys
                .each_ref()
                .map(|k| k.verifying_key().to_bytes()),
            writer_epoch: 3,
            root_key_epoch: 1,
            issued_at_ms: start,
            expires_at_ms: start + 3_600_000,
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
            now(),
        )
        .map_err(|e| format!("trust {e:?}"))?;
        Ok(Self {
            directory: directory.into(),
            trust,
            owner,
            witness_keys,
            start,
        })
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.directory.join(format!("{name}.sqlite"))
    }
    pub fn log(&self, name: &str) -> WitnessLog {
        WitnessLog::open(&self.path(name), self.trust).unwrap()
    }
    pub fn signed(&self, history: &WitnessHistory, peer: &Peer, allow: bool) -> SignedAppend {
        let request = AppendRequest {
            manifest: self.trust.manifest_commitment(),
            expected_generation: history.high_water().sequence,
            previous_head: history.high_water().policy_head,
            mutation: ReadMutation {
                peer: peer.credential.peer(),
                key_epoch: peer.credential.key_epoch(),
                member_epoch: peer.credential.member_epoch(),
                allow,
            },
            issued_at_ms: self.start,
            expires_at_ms: self.start + 3_600_000,
        };
        SignedAppend {
            request,
            owner_signature: self.owner.sign(&append_transcript(&request)).to_bytes(),
        }
    }
    pub fn commit_all(&self, peer: &Peer, allow: bool) -> SignedAppend {
        let history = self.log("policy").history().unwrap();
        let signed = self.signed(&history, peer, allow);
        for name in ["policy", "witness-a", "witness-b"] {
            self.log(name).append(signed, now()).unwrap();
        }
        signed
    }
    pub fn replies(
        &self,
        challenge: QuorumChallenge,
    ) -> Result<Vec<SignedQuorumObservation>, loom_core::lan_read::ReadError> {
        ["witness-a", "witness-b"]
            .into_iter()
            .enumerate()
            .map(|(i, name)| {
                WitnessLog::open(&self.path(name), self.trust)
                    .and_then(|mut l| l.observe(&self.witness_keys[i], challenge, now()))
                    .map_err(|_| loom_core::lan_read::ReadError::Quorum)
            })
            .collect()
    }
    pub fn peer(&self, name: &str) -> Peer {
        self.peer_at_epochs(name, 5, 6)
    }
    pub fn peer_at_epochs(&self, name: &str, key_epoch: u64, member_epoch: u64) -> Peer {
        let key = KeyPair::from_pem(
            &fs::read_to_string(self.directory.join(format!("{name}.pem"))).unwrap(),
        )
        .unwrap();
        let cert = fs::read(self.directory.join(format!("{name}.der")))
            .unwrap()
            .into();
        let root = SigningKey::from_bytes(&[111; 32]);
        let writer = SigningKey::from_bytes(&[115; 32]);
        let delegation = MembershipWriterDelegation {
            space: space(),
            root_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_epoch: 4,
            issued_at_ms: self.start,
            expires_at_ms: self.start + 3_600_000,
        };
        let event = CanonicalSecurityEvent {
            kind: EventKind::MembershipGrant,
            space_id: *space().as_bytes(),
            signer_key_id: issuer_key_id(&delegation.writer_public_key),
            issuer_epoch: 4,
            issued_at_ms: self.start,
            expires_at_ms: self.start + 3_600_000,
            seq: 1,
            payload: membership_payload(
                key.public_key_raw().try_into().unwrap(),
                key_epoch,
                member_epoch,
            ),
        };
        let bytes = encode_security_event(&event).unwrap();
        let credential = verify_membership(
            &ExternallyPinnedRootForSpike {
                space: space(),
                public_key: root.verifying_key().to_bytes(),
                key_epoch: 1,
            },
            &SignedMembershipWriter {
                delegation,
                root_signature: root
                    .sign(&membership_writer_transcript(&delegation))
                    .to_bytes(),
            },
            MembershipRequirements {
                writer_epoch: 4,
                sequence: 1,
            },
            &bytes,
            &writer.sign(&signing_input(&bytes).unwrap()).to_bytes(),
            now(),
        )
        .unwrap();
        Peer {
            cert,
            key: key.serialize_der(),
            credential,
            verifier: SignedMembershipVerifier::new(credential),
        }
    }
}
pub struct Peer {
    pub cert: CertificateDer<'static>,
    pub key: Vec<u8>,
    pub credential: VerifiedMembership,
    pub verifier: SignedMembershipVerifier,
}
impl Peer {
    pub fn identity(&self) -> LocalTlsIdentity {
        LocalTlsIdentity {
            certificate: self.cert.clone(),
            private_key: PrivateKeyDer::Pkcs8(self.key.clone().into()),
            key_epoch: self.credential.key_epoch(),
        }
    }
    pub fn context(&self) -> SecurePeerContext {
        SecurePeerContext {
            expected_remote: PinnedPeer::new(self.cert.clone(), self.credential.key_epoch())
                .unwrap(),
            space_id: space(),
        }
    }
}
