//! L-ADR-21 candidate: two independently pinned Ed25519 checkpoint witnesses.
//! Valid signatures do NOT establish that witnesses were provisioned honestly,
//! are online, or represent globally current state. NO admission permits here.

use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::{ResourceId, SpaceId};
use sha2::{Digest, Sha256};

const CHECKPOINT_DOMAIN: &[u8] = b"LOOM:CHECKPOINT:V1\0";
const WITNESS_KEY_DOMAIN: &[u8] = b"LOOM:WITNESS-KEY:V1\0";
const REVOKE_CHAIN_DOMAIN: &[u8] = b"LOOM:REVOKE-CHAIN:V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub space: SpaceId,
    /// In this PoC a resource is one chain. This is not the full writer chain.
    pub resource: ResourceId,
    pub writer_epoch: u64,
    pub seq: u64,
    pub head_hash: [u8; 32],
    pub revocation_root: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct TrustedWitnessForSpike {
    pub public_key: [u8; 32],
    /// A caller must obtain this from external authenticated configuration.
    /// It MUST NOT be learned from an untrusted Relay or the SQLite backup.
    pub key_id: [u8; 32],
}

impl TrustedWitnessForSpike {
    pub fn from_public_key(public_key: [u8; 32]) -> Self {
        let mut hash = Sha256::new();
        hash.update(WITNESS_KEY_DOMAIN);
        hash.update(public_key);
        Self {
            public_key,
            key_id: hash.finalize().into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SignedCheckpoint {
    pub witness_key_id: [u8; 32],
    pub checkpoint: Checkpoint,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    MissingOrDuplicateWitness,
    UntrustedSigner,
    InvalidSignature,
    InvalidScope,
    InvalidEpoch,
    CheckpointConflict,
    StaleEvidence,
}

/// Can only be produced by signature- and agreement-checking code.
/// Does NOT imply that a resource access is authorized.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedWitnessCheckpoint {
    checkpoint: Checkpoint,
}

impl VerifiedWitnessCheckpoint {
    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }
}

/// Deterministic signing transcript. All integer fields are fixed-width
/// unsigned big-endian, every byte is domain-separated and field position fixed.
pub fn checkpoint_transcript(checkpoint: &Checkpoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + 16 + 16 + 8 * 4 + 64);
    out.extend_from_slice(CHECKPOINT_DOMAIN);
    out.extend_from_slice(checkpoint.space.as_bytes());
    out.extend_from_slice(checkpoint.resource.as_bytes());
    out.extend_from_slice(&checkpoint.writer_epoch.to_be_bytes());
    out.extend_from_slice(&checkpoint.seq.to_be_bytes());
    out.extend_from_slice(&checkpoint.head_hash);
    out.extend_from_slice(&checkpoint.revocation_root);
    out.extend_from_slice(&checkpoint.issued_at_ms.to_be_bytes());
    out.extend_from_slice(&checkpoint.expires_at_ms.to_be_bytes());
    out
}

/// Compute chain root from an append-only sequence of raw signed evidence.
/// START = [0; 32]
/// NEXT = SHA256(domain || previous_root || seq(u64BE) || len(u32BE) || evidence)
///
/// A DB backup cannot invent the *later* root from a signed witness unless it
/// can reproduce those later evidence records. Hashing alone is not authority.
pub fn append_revocation_root(
    previous: [u8; 32],
    seq: u64,
    signed_evidence: &[u8],
) -> Option<[u8; 32]> {
    let len = u32::try_from(signed_evidence.len()).ok()?;
    if seq == 0 || signed_evidence.is_empty() || signed_evidence.len() > 64 * 1024 {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(REVOKE_CHAIN_DOMAIN);
    hash.update(previous);
    hash.update(seq.to_be_bytes());
    hash.update(len.to_be_bytes());
    hash.update(signed_evidence);
    Some(hash.finalize().into())
}

/// Validates two independently configured *different* keys and their signatures.
/// A single signer cannot satisfy both slots. Disagreement fails closed.
/// No remote authority or membership trust is inferred from this function.
pub fn verify_two_witnesses(
    trusted: &[TrustedWitnessForSpike],
    signed: &[SignedCheckpoint],
    expected_space: SpaceId,
    expected_resource: ResourceId,
    now_ms: u64,
) -> Result<VerifiedWitnessCheckpoint, WitnessError> {
    if trusted.len() != 2
        || signed.len() != 2
        || trusted[0].public_key == trusted[1].public_key
        || trusted[0].key_id == trusted[1].key_id
        || trusted
            .iter()
            .any(|w| TrustedWitnessForSpike::from_public_key(w.public_key).key_id != w.key_id)
    {
        return Err(WitnessError::MissingOrDuplicateWitness);
    }

    let mut checked: [Option<Checkpoint>; 2] = [None, None];
    for (slot, witness) in trusted.iter().enumerate() {
        let matches: Vec<&SignedCheckpoint> = signed
            .iter()
            .filter(|s| s.witness_key_id == witness.key_id)
            .collect();
        if matches.len() != 1 {
            return Err(WitnessError::MissingOrDuplicateWitness);
        }
        let receipt = matches[0];
        let cp = receipt.checkpoint;
        if cp.space != expected_space || cp.resource != expected_resource {
            return Err(WitnessError::InvalidScope);
        }
        if cp.writer_epoch == 0 {
            return Err(WitnessError::InvalidEpoch);
        }
        if cp.issued_at_ms > now_ms
            || cp.expires_at_ms <= now_ms
            || cp.issued_at_ms >= cp.expires_at_ms
        {
            return Err(WitnessError::StaleEvidence);
        }
        let public = VerifyingKey::from_bytes(&witness.public_key)
            .map_err(|_| WitnessError::UntrustedSigner)?;
        public
            .verify_strict(
                &checkpoint_transcript(&cp),
                &Signature::from_bytes(&receipt.signature),
            )
            .map_err(|_| WitnessError::InvalidSignature)?;
        checked[slot] = Some(cp);
    }
    let first = checked[0].ok_or(WitnessError::MissingOrDuplicateWitness)?;
    let second = checked[1].ok_or(WitnessError::MissingOrDuplicateWitness)?;
    if first != second {
        return Err(WitnessError::CheckpointConflict);
    }
    Ok(VerifiedWitnessCheckpoint { checkpoint: first })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub(super) fn fixture(
        seq: u64,
        root: [u8; 32],
    ) -> ([TrustedWitnessForSpike; 2], [SignedCheckpoint; 2]) {
        let a = SigningKey::from_bytes(&[21; 32]);
        let b = SigningKey::from_bytes(&[22; 32]);
        let cp = Checkpoint {
            space: SpaceId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            writer_epoch: 1,
            seq,
            head_hash: root,
            revocation_root: root,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let ta = TrustedWitnessForSpike::from_public_key(a.verifying_key().to_bytes());
        let tb = TrustedWitnessForSpike::from_public_key(b.verifying_key().to_bytes());
        let aa = SignedCheckpoint {
            witness_key_id: ta.key_id,
            checkpoint: cp,
            signature: a.sign(&checkpoint_transcript(&cp)).to_bytes(),
        };
        let bb = SignedCheckpoint {
            witness_key_id: tb.key_id,
            checkpoint: cp,
            signature: b.sign(&checkpoint_transcript(&cp)).to_bytes(),
        };
        ([ta, tb], [aa, bb])
    }

    fn verify(
        pins: &[TrustedWitnessForSpike],
        signed: &[SignedCheckpoint],
    ) -> Result<VerifiedWitnessCheckpoint, WitnessError> {
        verify_two_witnesses(
            pins,
            signed,
            SpaceId::from_bytes([1; 16]),
            ResourceId::from_bytes([2; 16]),
            150,
        )
    }

    #[test]
    fn independent_signatures_verify_but_do_not_mint_access() {
        let (trusted, signed) = fixture(2, [9; 32]);
        let cp = verify(&trusted, &signed).unwrap().checkpoint();
        assert_eq!(cp.seq, 2);
        assert_eq!(cp.revocation_root, [9; 32]);
    }

    #[test]
    fn duplicate_witness_or_missing_witness_cannot_fake_quorum() {
        let (mut trusted, mut signed) = fixture(1, [7; 32]);
        trusted[1] = trusted[0];
        assert_eq!(
            verify(&trusted, &signed).unwrap_err(),
            WitnessError::MissingOrDuplicateWitness
        );
        let (trusted, _) = fixture(1, [7; 32]);
        signed[1] = signed[0];
        assert_eq!(
            verify(&trusted, &signed).unwrap_err(),
            WitnessError::MissingOrDuplicateWitness
        );
        assert_eq!(
            verify(&trusted, &signed[..1]).unwrap_err(),
            WitnessError::MissingOrDuplicateWitness
        );
    }

    #[test]
    fn tampering_wrong_scope_and_expiry_rejected() {
        let (pins, mut signed) = fixture(2, [8; 32]);
        signed[0].signature[5] ^= 1;
        assert_eq!(
            verify(&pins, &signed).unwrap_err(),
            WitnessError::InvalidSignature
        );

        let (pins, mut signed) = fixture(2, [8; 32]);
        signed[0].checkpoint.space = SpaceId::from_bytes([55; 16]);
        assert_eq!(
            verify(&pins, &signed).unwrap_err(),
            WitnessError::InvalidScope
        );

        let (pins, signed) = fixture(2, [8; 32]);
        assert_eq!(
            verify_two_witnesses(
                &pins,
                &signed,
                signed[0].checkpoint.space,
                signed[0].checkpoint.resource,
                301
            )
            .unwrap_err(),
            WitnessError::StaleEvidence
        );
    }

    #[test]
    fn conflicting_valid_signatures_freeze_instead_of_selecting_lower_seq() {
        let (pins, mut signed) = fixture(2, [8; 32]);
        let b = SigningKey::from_bytes(&[22; 32]);
        signed[1].checkpoint.seq = 3;
        signed[1].signature = b
            .sign(&checkpoint_transcript(&signed[1].checkpoint))
            .to_bytes();
        assert_eq!(
            verify(&pins, &signed).unwrap_err(),
            WitnessError::CheckpointConflict
        );
    }

    #[test]
    fn witness_id_binding_detects_substitution() {
        let (mut pins, signed) = fixture(2, [1; 32]);
        pins[0].key_id = pins[1].key_id;
        assert_eq!(
            verify(&pins, &signed).unwrap_err(),
            WitnessError::MissingOrDuplicateWitness
        );
    }

    #[test]
    fn deterministic_revocation_roots_are_epoch_sensitive() {
        let one = append_revocation_root([0; 32], 1, b"event-one").unwrap();
        let two = append_revocation_root(one, 2, b"event-two").unwrap();
        assert_ne!(one, two);
        assert_ne!(
            one,
            append_revocation_root([0; 32], 2, b"event-one").unwrap()
        );
        assert!(append_revocation_root([0; 32], 0, b"event").is_none());
        assert!(append_revocation_root([0; 32], 1, b"").is_none());
    }
}
