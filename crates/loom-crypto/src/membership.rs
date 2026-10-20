//! Candidate Root -> MembershipWriter -> signed member chain.
//!
//! Pins, the exact current sequence and the clock must come from independently
//! authenticated state. This verifier does not provide enrollment, revocation
//! synchronization, rollback resistance or a ResourceOwner permission.
use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::{PeerId, SpaceId};
use loom_wire::security_event::{EventKind, decode_security_event, signing_input};
use sha2::{Digest, Sha256};

use crate::owner_authority::issuer_key_id;
use crate::space_trust::ExternallyPinnedRootForSpike;

const WRITER_DOMAIN: &[u8] = b"LOOM:MEMBERSHIP-WRITER:V1\0";

#[derive(Clone, Copy, Debug)]
pub struct MembershipWriterDelegation {
    pub space: SpaceId,
    pub root_epoch: u64,
    pub writer_public_key: [u8; 32],
    pub writer_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

pub struct SignedMembershipWriter {
    pub delegation: MembershipWriterDelegation,
    pub root_signature: [u8; 64],
}

/// Current epoch and sequence are external freshness requirements, never taken
/// from the received credential. The delegation is membership-only.
#[derive(Clone, Copy, Debug)]
pub struct MembershipRequirements {
    pub writer_epoch: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipError {
    InvalidRoot,
    InvalidDelegation,
    InvalidSignature,
    InvalidScope,
    InvalidEpoch,
    InvalidSequence,
    InvalidTime,
    InvalidPayload,
    NonCanonical,
    WrongKind,
}

/// Authenticated credential fields only. No Resource/ServiceOpen permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedMembership {
    root_public_key: [u8; 32],
    root_epoch: u64,
    space: SpaceId,
    peer: PeerId,
    key_epoch: u64,
    member_epoch: u64,
    sequence: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl VerifiedMembership {
    pub fn root_identity(&self) -> ([u8; 32], u64) {
        (self.root_public_key, self.root_epoch)
    }
    pub fn validity_interval(&self) -> (u64, u64) {
        (self.issued_at_ms, self.expires_at_ms)
    }
    pub fn space(&self) -> SpaceId {
        self.space
    }
    pub fn peer(&self) -> PeerId {
        self.peer
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn member_epoch(&self) -> u64 {
        self.member_epoch
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn valid_at(&self, now_ms: u64) -> bool {
        self.issued_at_ms <= now_ms && now_ms < self.expires_at_ms
    }
}

pub fn peer_id_for_public_key(public_key: &[u8; 32]) -> PeerId {
    let mut digest = Sha256::new();
    digest.update(b"LOOM:PEER-ID:V1\0");
    digest.update(public_key);
    PeerId::from_digest(digest.finalize().into())
}

pub fn membership_writer_transcript(d: &MembershipWriterDelegation) -> Vec<u8> {
    let mut out = WRITER_DOMAIN.to_vec();
    out.extend_from_slice(d.space.as_bytes());
    out.extend_from_slice(&d.root_epoch.to_be_bytes());
    out.extend_from_slice(&d.writer_public_key);
    out.extend_from_slice(&d.writer_epoch.to_be_bytes());
    out.extend_from_slice(&d.issued_at_ms.to_be_bytes());
    out.extend_from_slice(&d.expires_at_ms.to_be_bytes());
    out
}

/// Typed MembershipGrant payload: Ed25519 key[32], key epoch u64 BE, member
/// epoch u64 BE. The enclosing canonical event authenticates scope/time/seq.
pub fn membership_payload(key: [u8; 32], key_epoch: u64, member_epoch: u64) -> Vec<u8> {
    let mut out = key.to_vec();
    out.extend_from_slice(&key_epoch.to_be_bytes());
    out.extend_from_slice(&member_epoch.to_be_bytes());
    out
}

pub fn verify_membership(
    root: &ExternallyPinnedRootForSpike,
    signed_writer: &SignedMembershipWriter,
    requirements: MembershipRequirements,
    canonical: &[u8],
    signature: &[u8],
    now_ms: u64,
) -> Result<VerifiedMembership, MembershipError> {
    let d = signed_writer.delegation;
    if root.key_epoch == 0 || d.root_epoch != root.key_epoch {
        return Err(MembershipError::InvalidRoot);
    }
    if d.space != root.space {
        return Err(MembershipError::InvalidScope);
    }
    if d.writer_epoch == 0 || d.writer_epoch != requirements.writer_epoch {
        return Err(MembershipError::InvalidEpoch);
    }
    if requirements.sequence == 0 {
        return Err(MembershipError::InvalidSequence);
    }
    if d.issued_at_ms >= d.expires_at_ms || now_ms < d.issued_at_ms || now_ms >= d.expires_at_ms {
        return Err(MembershipError::InvalidTime);
    }
    let root_key =
        VerifyingKey::from_bytes(&root.public_key).map_err(|_| MembershipError::InvalidRoot)?;
    let writer = VerifyingKey::from_bytes(&d.writer_public_key)
        .map_err(|_| MembershipError::InvalidDelegation)?;
    if root_key.is_weak() || writer.is_weak() || d.writer_public_key == root.public_key {
        return Err(MembershipError::InvalidDelegation);
    }
    root_key
        .verify_strict(
            &membership_writer_transcript(&d),
            &Signature::from_bytes(&signed_writer.root_signature),
        )
        .map_err(|_| MembershipError::InvalidSignature)?;
    let event = decode_security_event(canonical).map_err(|_| MembershipError::NonCanonical)?;
    if event.kind != EventKind::MembershipGrant {
        return Err(MembershipError::WrongKind);
    }
    if event.space_id != *root.space.as_bytes()
        || event.signer_key_id != issuer_key_id(&d.writer_public_key)
    {
        return Err(MembershipError::InvalidScope);
    }
    if event.issuer_epoch != requirements.writer_epoch {
        return Err(MembershipError::InvalidEpoch);
    }
    if event.seq != requirements.sequence {
        return Err(MembershipError::InvalidSequence);
    }
    if event.issued_at_ms < d.issued_at_ms
        || event.expires_at_ms > d.expires_at_ms
        || now_ms < event.issued_at_ms
        || now_ms >= event.expires_at_ms
    {
        return Err(MembershipError::InvalidTime);
    }
    if event.payload.len() != 48 {
        return Err(MembershipError::InvalidPayload);
    }
    let key: [u8; 32] = event.payload[..32]
        .try_into()
        .map_err(|_| MembershipError::InvalidPayload)?;
    let member_key = VerifyingKey::from_bytes(&key).map_err(|_| MembershipError::InvalidPayload)?;
    let key_epoch = u64::from_be_bytes(
        event.payload[32..40]
            .try_into()
            .map_err(|_| MembershipError::InvalidPayload)?,
    );
    let member_epoch = u64::from_be_bytes(
        event.payload[40..48]
            .try_into()
            .map_err(|_| MembershipError::InvalidPayload)?,
    );
    if member_key.is_weak() || key_epoch == 0 || member_epoch == 0 {
        return Err(MembershipError::InvalidPayload);
    }
    let signature =
        Signature::from_slice(signature).map_err(|_| MembershipError::InvalidSignature)?;
    writer
        .verify_strict(
            &signing_input(canonical).map_err(|_| MembershipError::NonCanonical)?,
            &signature,
        )
        .map_err(|_| MembershipError::InvalidSignature)?;
    Ok(VerifiedMembership {
        root_public_key: root.public_key,
        root_epoch: root.key_epoch,
        space: root.space,
        peer: peer_id_for_public_key(&key),
        key_epoch,
        member_epoch,
        sequence: event.seq,
        issued_at_ms: event.issued_at_ms,
        expires_at_ms: event.expires_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_wire::security_event::{CanonicalSecurityEvent, encode_security_event};

    struct Fixture {
        root: ExternallyPinnedRootForSpike,
        writer: SignedMembershipWriter,
        requirements: MembershipRequirements,
        event: CanonicalSecurityEvent,
        signer: SigningKey,
    }
    impl Fixture {
        fn new() -> Self {
            let root = SigningKey::from_bytes(&[31; 32]);
            let signer = SigningKey::from_bytes(&[32; 32]);
            let peer = SigningKey::from_bytes(&[33; 32]);
            let pin = ExternallyPinnedRootForSpike {
                space: SpaceId::from_bytes([1; 16]),
                public_key: root.verifying_key().to_bytes(),
                key_epoch: 2,
            };
            let delegation = MembershipWriterDelegation {
                space: pin.space,
                root_epoch: 2,
                writer_public_key: signer.verifying_key().to_bytes(),
                writer_epoch: 3,
                issued_at_ms: 100,
                expires_at_ms: 1000,
            };
            Self {
                root: pin,
                writer: SignedMembershipWriter {
                    delegation,
                    root_signature: root
                        .sign(&membership_writer_transcript(&delegation))
                        .to_bytes(),
                },
                requirements: MembershipRequirements {
                    writer_epoch: 3,
                    sequence: 7,
                },
                event: CanonicalSecurityEvent {
                    kind: EventKind::MembershipGrant,
                    space_id: *pin.space.as_bytes(),
                    signer_key_id: issuer_key_id(&delegation.writer_public_key),
                    issuer_epoch: 3,
                    issued_at_ms: 200,
                    expires_at_ms: 800,
                    seq: 7,
                    payload: membership_payload(peer.verifying_key().to_bytes(), 4, 19),
                },
                signer,
            }
        }
        fn verify(&self, now: u64) -> Result<VerifiedMembership, MembershipError> {
            let bytes = encode_security_event(&self.event).unwrap();
            let sig = self.signer.sign(&signing_input(&bytes).unwrap()).to_bytes();
            verify_membership(
                &self.root,
                &self.writer,
                self.requirements,
                &bytes,
                &sig,
                now,
            )
        }
    }

    #[test]
    fn root_delegates_only_membership_and_epochs_remain_distinct() {
        let f = Fixture::new();
        let value = f.verify(250).unwrap();
        assert_eq!(
            (value.key_epoch(), value.member_epoch(), value.sequence()),
            (4, 19, 7)
        );
        assert_eq!(
            value.peer(),
            peer_id_for_public_key(&SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes())
        );
        assert!(value.valid_at(799));
        assert!(!value.valid_at(800));
        assert!(!value.valid_at(199));
    }
    #[test]
    fn substituted_root_and_modified_delegation_refused() {
        let mut f = Fixture::new();
        f.root.public_key = SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes();
        assert_eq!(f.verify(250), Err(MembershipError::InvalidSignature));
        let mut f = Fixture::new();
        f.writer.delegation.expires_at_ms += 1;
        assert_eq!(f.verify(250), Err(MembershipError::InvalidSignature));
    }
    #[test]
    fn wrong_space_writer_and_exact_epochs_refused() {
        let mut f = Fixture::new();
        f.event.space_id = [9; 16];
        assert_eq!(f.verify(250), Err(MembershipError::InvalidScope));
        let mut f = Fixture::new();
        f.event.signer_key_id = [9; 32];
        assert_eq!(f.verify(250), Err(MembershipError::InvalidScope));
        let mut f = Fixture::new();
        f.event.issuer_epoch += 1;
        assert_eq!(f.verify(250), Err(MembershipError::InvalidEpoch));
        let mut f = Fixture::new();
        f.root.key_epoch += 1;
        assert_eq!(f.verify(250), Err(MembershipError::InvalidRoot));
        let mut f = Fixture::new();
        f.requirements.writer_epoch += 1;
        assert_eq!(f.verify(250), Err(MembershipError::InvalidEpoch));
    }
    #[test]
    fn stale_or_future_sequence_and_zero_requirement_refused() {
        for seq in [0, 6, 8, u64::MAX] {
            let mut f = Fixture::new();
            f.requirements.sequence = seq;
            assert_eq!(f.verify(250), Err(MembershipError::InvalidSequence));
        }
    }
    #[test]
    fn validity_is_half_open_and_bounded_by_delegation() {
        for now in [0, 99, 199, 800, 1000, u64::MAX] {
            assert_eq!(
                Fixture::new().verify(now),
                Err(MembershipError::InvalidTime)
            );
        }
        for (issued, expires) in [(99, 800), (200, 1001)] {
            let mut f = Fixture::new();
            f.event.issued_at_ms = issued;
            f.event.expires_at_ms = expires;
            assert_eq!(f.verify(250), Err(MembershipError::InvalidTime));
        }
    }
    #[test]
    fn wrong_kind_length_and_invalid_member_key_refused() {
        let mut f = Fixture::new();
        f.event.kind = EventKind::OwnerGrant;
        assert_eq!(f.verify(250), Err(MembershipError::WrongKind));
        for n in [0, 47, 49] {
            let mut f = Fixture::new();
            f.event.payload.resize(n, 0);
            assert_eq!(f.verify(250), Err(MembershipError::InvalidPayload));
        }
        let mut f = Fixture::new();
        f.event.payload[..32].fill(0);
        assert_eq!(f.verify(250), Err(MembershipError::InvalidPayload));
        let mut f = Fixture::new();
        f.event.payload[32..40].fill(0);
        assert_eq!(f.verify(250), Err(MembershipError::InvalidPayload));
        let mut f = Fixture::new();
        f.event.payload[40..48].fill(0);
        assert_eq!(f.verify(250), Err(MembershipError::InvalidPayload));
    }
    #[test]
    fn bad_signature_trailing_bytes_and_truncated_cbor_refused() {
        let f = Fixture::new();
        let mut bytes = encode_security_event(&f.event).unwrap();
        let mut sig = f.signer.sign(&signing_input(&bytes).unwrap()).to_bytes();
        sig[0] ^= 1;
        assert_eq!(
            verify_membership(&f.root, &f.writer, f.requirements, &bytes, &sig, 250),
            Err(MembershipError::InvalidSignature)
        );
        assert_eq!(
            verify_membership(&f.root, &f.writer, f.requirements, &bytes, &sig[..63], 250),
            Err(MembershipError::InvalidSignature)
        );
        bytes.push(0);
        assert_eq!(
            verify_membership(&f.root, &f.writer, f.requirements, &bytes, &sig, 250),
            Err(MembershipError::NonCanonical)
        );
        for end in 0..bytes.len() - 1 {
            assert!(
                verify_membership(&f.root, &f.writer, f.requirements, &bytes[..end], &sig, 250)
                    .is_err()
            );
        }
    }
}
