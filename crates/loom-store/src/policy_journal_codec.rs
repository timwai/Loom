//! Candidate binary event envelope for a unified resource policy journal.
//! Every persisted event is cryptographically verified again during replay.
//! This is NOT a network authorization protocol or an accepted wire format.

use loom_crypto::owner_authority::{
    OwnerVerifiedRevocation, replay_persisted_owner_revocation_for_spike,
};
use loom_crypto::owner_lifecycle::{
    DelegateCancellation, DualSignedOwnerTransfer, OwnerTransfer, ResourceOwnerLifecycle,
    SignedDelegateCancellation, cancellation_transcript, owner_transfer_transcript,
};
use loom_crypto::space_trust::{
    ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
    trust_manifest_transcript, verify_resource_trust_for_spike,
};
use loom_types::{ResourceId, SpaceId};

use crate::StoreError;

pub(crate) const KIND_REVOKE: u8 = 1;
pub(crate) const KIND_CANCEL: u8 = 2;
pub(crate) const KIND_TRANSFER: u8 = 3;
pub(crate) const MAX_EVIDENCE: usize = 64 * 1024;

pub enum NewPolicyEvent<'a> {
    Revoke(&'a OwnerVerifiedRevocation),
    Cancel(&'a SignedDelegateCancellation),
    Transfer {
        transfer: &'a DualSignedOwnerTransfer,
        successor_manifest: &'a SignedResourceTrust,
    },
}

pub(crate) fn encode_event(input: NewPolicyEvent<'_>) -> (u8, Vec<u8>) {
    match input {
        NewPolicyEvent::Revoke(proof) => (KIND_REVOKE, proof.persistence_bytes()),
        NewPolicyEvent::Cancel(signed) => {
            let mut evidence = cancellation_transcript(&signed.cancellation);
            evidence.extend_from_slice(&signed.signature);
            (KIND_CANCEL, evidence)
        }
        NewPolicyEvent::Transfer {
            transfer,
            successor_manifest,
        } => {
            let mut evidence = owner_transfer_transcript(&transfer.transfer);
            evidence.extend_from_slice(&transfer.old_owner_signature);
            evidence.extend_from_slice(&transfer.next_owner_signature);
            evidence.extend_from_slice(&trust_manifest_transcript(&successor_manifest.manifest));
            evidence.extend_from_slice(&successor_manifest.signature);
            (KIND_TRANSFER, evidence)
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        let end = self.offset.checked_add(N).ok_or(StoreError::Conflict)?;
        let value: [u8; N] = self
            .bytes
            .get(self.offset..end)
            .ok_or(StoreError::Conflict)?
            .try_into()
            .map_err(|_| StoreError::Conflict)?;
        self.offset = end;
        Ok(value)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), StoreError> {
        let end = self
            .offset
            .checked_add(expected.len())
            .ok_or(StoreError::Conflict)?;
        if self.bytes.get(self.offset..end) != Some(expected) {
            return Err(StoreError::Conflict);
        }
        self.offset = end;
        Ok(())
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn done(&self) -> Result<(), StoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }
}

const CANCEL_DOMAIN: &[u8] = b"LOOM:DELEGATE-CANCEL:V1\0";
const TRANSFER_DOMAIN: &[u8] = b"LOOM:OWNER-TRANSFER:V1\0";
const MANIFEST_DOMAIN: &[u8] = b"LOOM:RESOURCE-TRUST:V1\0";

fn decode_cancel(bytes: &[u8]) -> Result<SignedDelegateCancellation, StoreError> {
    let mut r = Cursor::new(bytes);
    r.expect(CANCEL_DOMAIN)?;
    let cancellation = DelegateCancellation {
        space: SpaceId::from_bytes(r.take::<16>()?),
        resource: ResourceId::from_bytes(r.take::<16>()?),
        owner_public_key: r.take::<32>()?,
        owner_epoch: r.u64()?,
        delegate_key_id: r.take::<32>()?,
        delegate_epoch: r.u64()?,
        sequence: r.u64()?,
        issued_at_ms: r.u64()?,
        expires_at_ms: r.u64()?,
    };
    let signature = r.take::<64>()?;
    r.done()?;
    if cancellation_transcript(&cancellation) != bytes[..bytes.len() - 64] {
        return Err(StoreError::Conflict);
    }
    Ok(SignedDelegateCancellation {
        cancellation,
        signature,
    })
}

fn decode_transfer(
    bytes: &[u8],
) -> Result<(DualSignedOwnerTransfer, SignedResourceTrust), StoreError> {
    let mut r = Cursor::new(bytes);
    r.expect(TRANSFER_DOMAIN)?;
    let transfer = OwnerTransfer {
        space: SpaceId::from_bytes(r.take::<16>()?),
        resource: ResourceId::from_bytes(r.take::<16>()?),
        prior_manifest: r.take::<32>()?,
        successor_manifest: r.take::<32>()?,
        previous_owner_public_key: r.take::<32>()?,
        successor_owner_public_key: r.take::<32>()?,
        previous_owner_epoch: r.u64()?,
        successor_owner_epoch: r.u64()?,
        sequence: r.u64()?,
        issued_at_ms: r.u64()?,
        expires_at_ms: r.u64()?,
    };
    let old_owner_signature = r.take::<64>()?;
    let next_owner_signature = r.take::<64>()?;
    r.expect(MANIFEST_DOMAIN)?;
    let manifest = ResourceTrustManifest {
        space: SpaceId::from_bytes(r.take::<16>()?),
        resource: ResourceId::from_bytes(r.take::<16>()?),
        owner_public_key: r.take::<32>()?,
        owner_key_epoch: r.u64()?,
        witness_public_keys: [r.take::<32>()?, r.take::<32>()?],
        writer_epoch: r.u64()?,
        root_key_epoch: r.u64()?,
        issued_at_ms: r.u64()?,
        expires_at_ms: r.u64()?,
    };
    let signature = r.take::<64>()?;
    r.done()?;
    let signed_transfer = DualSignedOwnerTransfer {
        transfer,
        old_owner_signature,
        next_owner_signature,
    };
    if !bytes.starts_with(&owner_transfer_transcript(&transfer)) {
        return Err(StoreError::Conflict);
    }
    // Re-encoding is intentionally strict, so schema changes do not silently
    // reinterpret bytes already persisted to the journal.
    let mut reconstructed = owner_transfer_transcript(&transfer);
    reconstructed.extend_from_slice(&old_owner_signature);
    reconstructed.extend_from_slice(&next_owner_signature);
    reconstructed.extend_from_slice(&trust_manifest_transcript(&manifest));
    reconstructed.extend_from_slice(&signature);
    if reconstructed != bytes {
        return Err(StoreError::Conflict);
    }
    Ok((
        signed_transfer,
        SignedResourceTrust {
            manifest,
            signature,
        },
    ))
}

/// Replay an event after all earlier policy operations have been validated.
/// The Root pin is an externally supplied *candidate*; authentication of that
/// pin and an independent high-water checkpoint remain separate P0 gates.
pub(crate) fn replay_event(
    state: &mut ResourceOwnerLifecycle,
    root_pin: &ExternallyPinnedRootForSpike,
    kind: u8,
    evidence: &[u8],
) -> Result<(), StoreError> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE {
        return Err(StoreError::Conflict);
    }
    match kind {
        KIND_REVOKE => {
            let proof =
                replay_persisted_owner_revocation_for_spike(&state.current_owner(), evidence)
                    .map_err(|_| StoreError::Conflict)?;
            state
                .apply_delegated_revocation(&proof)
                .map_err(|_| StoreError::Conflict)
        }
        KIND_CANCEL => {
            let signed = decode_cancel(evidence)?;
            state
                .cancel_delegate(&signed, signed.cancellation.issued_at_ms)
                .map_err(|_| StoreError::Conflict)
        }
        KIND_TRANSFER => {
            let (transfer, signed_successor) = decode_transfer(evidence)?;
            let successor = verify_resource_trust_for_spike(
                root_pin,
                &signed_successor,
                transfer.transfer.issued_at_ms,
            )
            .map_err(|_| StoreError::Conflict)?;
            state
                .transfer_owner(&transfer, successor, transfer.transfer.issued_at_ms)
                .map_err(|_| StoreError::Conflict)
        }
        _ => Err(StoreError::Conflict),
    }
}
