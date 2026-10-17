//! L-001G proof-of-structure: a Root key-rotation certificate is signed
//! by BOTH the old, externally pinned Root and the proposed new Root key.
//! This does not make a disk backup or a caller-supplied Root pin trustworthy.

use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::SpaceId;

use crate::space_trust::ExternallyPinnedRootForSpike;

const ROTATION_DOMAIN: &[u8] = b"LOOM:ROOT-ROTATION:V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootRotation {
    pub space: SpaceId,
    pub previous_key: [u8; 32],
    pub next_key: [u8; 32],
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct DualSignedRootRotation {
    pub rotation: RootRotation,
    pub previous_signature: [u8; 64],
    pub next_signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootRotationError {
    WrongSpaceOrRoot,
    InvalidEpoch,
    ReusedKey,
    Expired,
    InvalidPreviousSignature,
    InvalidNextSignature,
}

pub fn rotation_transcript(rotation: &RootRotation) -> Vec<u8> {
    let mut out = Vec::with_capacity(ROTATION_DOMAIN.len() + 16 + 32 + 32 + 32);
    out.extend_from_slice(ROTATION_DOMAIN);
    out.extend_from_slice(rotation.space.as_bytes());
    out.extend_from_slice(&rotation.previous_key);
    out.extend_from_slice(&rotation.next_key);
    out.extend_from_slice(&rotation.previous_epoch.to_be_bytes());
    out.extend_from_slice(&rotation.next_epoch.to_be_bytes());
    out.extend_from_slice(&rotation.issued_at_ms.to_be_bytes());
    out.extend_from_slice(&rotation.expires_at_ms.to_be_bytes());
    out
}

/// Advancing an *external pin* must be performed through an independently
/// trusted, atomic, rollback-resistant store. The returned pin alone is not
/// durable and MUST NEVER be accepted from a network-provided certificate.
pub fn verify_root_rotation_for_spike(
    trusted_previous: &ExternallyPinnedRootForSpike,
    proposal: &DualSignedRootRotation,
    now_ms: u64,
) -> Result<ExternallyPinnedRootForSpike, RootRotationError> {
    let r = proposal.rotation;
    if r.space != trusted_previous.space || r.previous_key != trusted_previous.public_key {
        return Err(RootRotationError::WrongSpaceOrRoot);
    }
    if r.previous_epoch != trusted_previous.key_epoch
        || r.previous_epoch == 0
        || r.previous_epoch.checked_add(1) != Some(r.next_epoch)
    {
        return Err(RootRotationError::InvalidEpoch);
    }
    if r.previous_key == r.next_key {
        return Err(RootRotationError::ReusedKey);
    }
    if r.issued_at_ms > now_ms || now_ms >= r.expires_at_ms || r.issued_at_ms >= r.expires_at_ms {
        return Err(RootRotationError::Expired);
    }
    let previous = VerifyingKey::from_bytes(&r.previous_key)
        .map_err(|_| RootRotationError::InvalidPreviousSignature)?;
    let next = VerifyingKey::from_bytes(&r.next_key)
        .map_err(|_| RootRotationError::InvalidNextSignature)?;
    let transcript = rotation_transcript(&r);
    previous
        .verify_strict(
            &transcript,
            &Signature::from_bytes(&proposal.previous_signature),
        )
        .map_err(|_| RootRotationError::InvalidPreviousSignature)?;
    next.verify_strict(
        &transcript,
        &Signature::from_bytes(&proposal.next_signature),
    )
    .map_err(|_| RootRotationError::InvalidNextSignature)?;
    Ok(ExternallyPinnedRootForSpike {
        space: r.space,
        public_key: r.next_key,
        key_epoch: r.next_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (ExternallyPinnedRootForSpike, DualSignedRootRotation) {
        let old_key = SigningKey::from_bytes(&[30; 32]);
        let new_key = SigningKey::from_bytes(&[31; 32]);
        let trusted = ExternallyPinnedRootForSpike {
            space: SpaceId::from_bytes([1; 16]),
            public_key: old_key.verifying_key().to_bytes(),
            key_epoch: 7,
        };
        let rotation = RootRotation {
            space: trusted.space,
            previous_key: trusted.public_key,
            next_key: new_key.verifying_key().to_bytes(),
            previous_epoch: 7,
            next_epoch: 8,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let transcript = rotation_transcript(&rotation);
        (
            trusted,
            DualSignedRootRotation {
                rotation,
                previous_signature: old_key.sign(&transcript).to_bytes(),
                next_signature: new_key.sign(&transcript).to_bytes(),
            },
        )
    }

    #[test]
    fn both_root_keys_must_confirm_rotation() {
        let (previous, certificate) = fixture();
        let next = verify_root_rotation_for_spike(&previous, &certificate, 150).unwrap();
        assert_eq!(next.public_key, certificate.rotation.next_key);
        assert_eq!(next.key_epoch, 8);
        assert_eq!(next.space, previous.space);
        // An old transition cannot be replayed as the next transition.
        assert_eq!(
            verify_root_rotation_for_spike(&next, &certificate, 150).unwrap_err(),
            RootRotationError::WrongSpaceOrRoot
        );
    }

    #[test]
    fn forged_old_or_new_signature_rejected() {
        let (trusted, mut proposal) = fixture();
        proposal.previous_signature[0] ^= 1;
        assert_eq!(
            verify_root_rotation_for_spike(&trusted, &proposal, 150).unwrap_err(),
            RootRotationError::InvalidPreviousSignature
        );
        let (trusted, mut proposal) = fixture();
        proposal.next_signature[0] ^= 1;
        assert_eq!(
            verify_root_rotation_for_spike(&trusted, &proposal, 150).unwrap_err(),
            RootRotationError::InvalidNextSignature
        );
    }

    #[test]
    fn changes_to_epoch_space_or_successor_key_fail() {
        let (trusted, mut proposal) = fixture();
        proposal.rotation.next_epoch = 9;
        assert_eq!(
            verify_root_rotation_for_spike(&trusted, &proposal, 150).unwrap_err(),
            RootRotationError::InvalidEpoch
        );
        let (trusted, mut proposal) = fixture();
        proposal.rotation.space = SpaceId::from_bytes([2; 16]);
        assert_eq!(
            verify_root_rotation_for_spike(&trusted, &proposal, 150).unwrap_err(),
            RootRotationError::WrongSpaceOrRoot
        );
        let (trusted, mut proposal) = fixture();
        proposal.rotation.next_key = proposal.rotation.previous_key;
        assert_eq!(
            verify_root_rotation_for_spike(&trusted, &proposal, 150).unwrap_err(),
            RootRotationError::ReusedKey
        );
    }

    #[test]
    fn expired_or_future_dated_rotation_rejected() {
        let (trusted, proposal) = fixture();
        assert_eq!(
            verify_root_rotation_for_spike(&trusted, &proposal, 99).unwrap_err(),
            RootRotationError::Expired
        );
        assert_eq!(
            verify_root_rotation_for_spike(&trusted, &proposal, 300).unwrap_err(),
            RootRotationError::Expired
        );
    }

    #[test]
    fn substituted_previously_pinned_key_is_not_accepted() {
        let (mut trusted, proposal) = fixture();
        trusted.public_key = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_root_rotation_for_spike(&trusted, &proposal, 150).unwrap_err(),
            RootRotationError::WrongSpaceOrRoot
        );
    }
}
