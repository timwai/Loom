//! L-001G: external, rollback-resistant high-water anchor *interface*.
//! No OS-backed AnchorProvider is implemented. A caller-supplied, rollbackable
//! in-memory/file value is NOT equivalent to an independently trusted anchor.
//! Even successful comparison produces NO resource admission permit.

use loom_crypto::space_trust::VerifiedResourceTrust;
use loom_crypto::witness_checkpoint::Checkpoint;
use loom_types::{ResourceId, SpaceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HighWaterRecord {
    pub space: SpaceId,
    pub resource: ResourceId,
    pub root_public_key: [u8; 32],
    pub root_key_epoch: u64,
    pub resource_manifest_hash: [u8; 32],
    pub writer_epoch: u64,
    pub seq: u64,
    pub revocation_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HighWaterError {
    Unavailable,
    MissingIndependentAnchor,
    RootOrManifestMismatch,
    EpochMismatch,
    Rollback,
    Divergence,
    CompareAndSwapConflict,
    PersistenceUncertain,
    ExpiredManifest,
}

impl HighWaterRecord {
    /// Must be provisioned into actual trusted, independent storage by an
    /// authorized onboarding flow, NOT generated from a remote discovery reply.
    pub fn initial(trust: &VerifiedResourceTrust) -> Self {
        Self {
            space: trust.space(),
            resource: trust.resource(),
            root_public_key: trust.root_public_key(),
            root_key_epoch: trust.root_key_epoch(),
            resource_manifest_hash: trust.manifest_commitment(),
            writer_epoch: trust.writer_epoch(),
            seq: 0,
            revocation_root: [0; 32],
        }
    }
}

/// The implementor MUST provide an authenticated storage domain independent
/// of the SQLite snapshot, an atomic CAS + durable flush, and rollback
/// resistance. The interface alone provides NONE of those guarantees.
pub trait IndependentHighWaterAnchor: Send + Sync {
    fn read(&self, space: SpaceId, resource: ResourceId)
    -> Result<HighWaterRecord, HighWaterError>;

    fn compare_and_advance(
        &self,
        expected: HighWaterRecord,
        next: HighWaterRecord,
    ) -> Result<(), HighWaterError>;
}

/// Verify a *previously authenticated, independent* high-water record against
/// this Root-signed resource manifest and current two-witness checkpoint.
pub fn checked_high_water_update(
    trust: &VerifiedResourceTrust,
    cp: Checkpoint,
    current: HighWaterRecord,
    now_ms: u64,
) -> Result<HighWaterRecord, HighWaterError> {
    if !trust.valid_at(now_ms) {
        return Err(HighWaterError::ExpiredManifest);
    }
    if cp.space != trust.space()
        || cp.resource != trust.resource()
        || current.space != trust.space()
        || current.resource != trust.resource()
    {
        return Err(HighWaterError::RootOrManifestMismatch);
    }
    if current.root_public_key != trust.root_public_key()
        || current.root_key_epoch != trust.root_key_epoch()
        || current.resource_manifest_hash != trust.manifest_commitment()
    {
        // Deliberately fails closed across Root rollover/Owner transfer until
        // a separate signed and atomically persisted migration is defined.
        return Err(HighWaterError::RootOrManifestMismatch);
    }
    if cp.writer_epoch != trust.writer_epoch() || current.writer_epoch != trust.writer_epoch() {
        return Err(HighWaterError::EpochMismatch);
    }
    if cp.seq == 0 && (cp.head_hash != [0; 32] || cp.revocation_root != [0; 32]) {
        return Err(HighWaterError::Divergence);
    }
    if cp.seq < current.seq {
        return Err(HighWaterError::Rollback);
    }
    if cp.seq == current.seq && cp.revocation_root != current.revocation_root {
        return Err(HighWaterError::Divergence);
    }
    Ok(HighWaterRecord {
        seq: cp.seq,
        revocation_root: cp.revocation_root,
        ..current
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_crypto::space_trust::{
        ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
        trust_manifest_transcript, verify_resource_trust_for_spike,
    };
    use std::sync::Mutex;

    struct TestAnchor(Mutex<HighWaterRecord>);

    impl IndependentHighWaterAnchor for TestAnchor {
        fn read(
            &self,
            space: SpaceId,
            resource: ResourceId,
        ) -> Result<HighWaterRecord, HighWaterError> {
            let record = *self.0.lock().map_err(|_| HighWaterError::Unavailable)?;
            if record.space != space || record.resource != resource {
                return Err(HighWaterError::MissingIndependentAnchor);
            }
            Ok(record)
        }
        fn compare_and_advance(
            &self,
            expected: HighWaterRecord,
            next: HighWaterRecord,
        ) -> Result<(), HighWaterError> {
            let mut guard = self.0.lock().map_err(|_| HighWaterError::Unavailable)?;
            if *guard != expected {
                return Err(HighWaterError::CompareAndSwapConflict);
            }
            if next.seq < guard.seq {
                return Err(HighWaterError::Rollback);
            }
            *guard = next;
            Ok(())
        }
    }

    fn trust() -> VerifiedResourceTrust {
        let root = SigningKey::from_bytes(&[30; 32]);
        let owner = SigningKey::from_bytes(&[11; 32]);
        let w1 = SigningKey::from_bytes(&[21; 32]);
        let w2 = SigningKey::from_bytes(&[22; 32]);
        let root_pin = ExternallyPinnedRootForSpike {
            space: SpaceId::from_bytes([1; 16]),
            public_key: root.verifying_key().to_bytes(),
            key_epoch: 7,
        };
        let manifest = ResourceTrustManifest {
            space: root_pin.space,
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner.verifying_key().to_bytes(),
            owner_key_epoch: 3,
            witness_public_keys: [w1.verifying_key().to_bytes(), w2.verifying_key().to_bytes()],
            writer_epoch: 1,
            root_key_epoch: 7,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let signed = SignedResourceTrust {
            manifest,
            signature: root.sign(&trust_manifest_transcript(&manifest)).to_bytes(),
        };
        verify_resource_trust_for_spike(&root_pin, &signed, 150).unwrap()
    }

    fn cp(trust: &VerifiedResourceTrust, seq: u64, root: [u8; 32]) -> Checkpoint {
        Checkpoint {
            space: trust.space(),
            resource: trust.resource(),
            writer_epoch: trust.writer_epoch(),
            seq,
            head_hash: root,
            revocation_root: root,
            issued_at_ms: 100,
            expires_at_ms: 300,
        }
    }

    #[test]
    fn advances_only_from_external_record_and_never_decreases() {
        let trust = trust();
        let store = TestAnchor(Mutex::new(HighWaterRecord::initial(&trust)));
        let old = store.read(trust.space(), trust.resource()).unwrap();
        let next = checked_high_water_update(&trust, cp(&trust, 1, [4; 32]), old, 150).unwrap();
        store.compare_and_advance(old, next).unwrap();
        assert_eq!(
            checked_high_water_update(&trust, cp(&trust, 0, [0; 32]), next, 150),
            Err(HighWaterError::Rollback)
        );
        assert_eq!(
            checked_high_water_update(&trust, cp(&trust, 1, [5; 32]), next, 150),
            Err(HighWaterError::Divergence)
        );
    }

    #[test]
    fn concurrent_stale_writer_must_fail_atomic_compare_and_swap() {
        let trust = trust();
        let store = TestAnchor(Mutex::new(HighWaterRecord::initial(&trust)));
        let old = store.read(trust.space(), trust.resource()).unwrap();
        let next = checked_high_water_update(&trust, cp(&trust, 1, [4; 32]), old, 150).unwrap();
        store.compare_and_advance(old, next).unwrap();
        assert_eq!(
            store.compare_and_advance(old, old),
            Err(HighWaterError::CompareAndSwapConflict)
        );
    }

    #[test]
    fn reject_replaced_root_manifest_epoch_and_scope() {
        let trust = trust();
        let old = HighWaterRecord::initial(&trust);
        let mut replaced_root = old;
        replaced_root.root_public_key = [8; 32];
        assert_eq!(
            checked_high_water_update(&trust, cp(&trust, 0, [0; 32]), replaced_root, 150),
            Err(HighWaterError::RootOrManifestMismatch)
        );
        let mut wrong_manifest = old;
        wrong_manifest.resource_manifest_hash = [7; 32];
        assert_eq!(
            checked_high_water_update(&trust, cp(&trust, 0, [0; 32]), wrong_manifest, 150),
            Err(HighWaterError::RootOrManifestMismatch)
        );
        let mut wrong_epoch = old;
        wrong_epoch.writer_epoch += 1;
        assert_eq!(
            checked_high_water_update(&trust, cp(&trust, 0, [0; 32]), wrong_epoch, 150),
            Err(HighWaterError::EpochMismatch)
        );
        assert_eq!(
            checked_high_water_update(&trust, cp(&trust, 0, [0; 32]), old, 301),
            Err(HighWaterError::ExpiredManifest)
        );
    }

    #[test]
    fn missing_anchor_is_not_equivalent_to_genesis() {
        struct Absent;
        impl IndependentHighWaterAnchor for Absent {
            fn read(
                &self,
                _space: SpaceId,
                _resource: ResourceId,
            ) -> Result<HighWaterRecord, HighWaterError> {
                Err(HighWaterError::MissingIndependentAnchor)
            }
            fn compare_and_advance(
                &self,
                _expected: HighWaterRecord,
                _next: HighWaterRecord,
            ) -> Result<(), HighWaterError> {
                Err(HighWaterError::MissingIndependentAnchor)
            }
        }
        let trust = trust();
        assert_eq!(
            Absent.read(trust.space(), trust.resource()),
            Err(HighWaterError::MissingIndependentAnchor)
        );
    }
}
