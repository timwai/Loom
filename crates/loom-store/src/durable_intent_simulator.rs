//! L-001S deterministic crash simulator for a *hypothetical* independent
//! durable Prepared-intent store and monotonic counter. NEVER production I/O.
//!
//! This model distinguishes volatile staged writes from durable media and
//! makes every protocol boundary fail before/after durable effects. An ordinary
//! file/SQLite store would NOT satisfy real independent anti-rollback trust.
//! No keys, TPM NV commands, network admission or ServiceOpen exist here.

use crate::tpm_counter_binding::{
    BindingError, CandidateIntentStore, CandidateMonotonicCounter, Committed,
    PinnedCounterIdentity, Prepared, StoredBinding,
};
use crate::unified_policy_anchor::UnifiedPolicyHighWater;
use std::sync::{Arc, Mutex, MutexGuard};

/// A single failure, injected exactly at the named model boundary.
/// After injection the process must "reboot" before any further I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashPoint {
    PrepareBeforeWrite,
    PrepareBeforeSync,
    PrepareAfterSync,
    IncrementBeforeWrite,
    IncrementAfterWrite,
    FinalizeBeforeWrite,
    FinalizeBeforeSync,
    FinalizeAfterSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableImage {
    pub nv_counter: u64,
    pub intent: StoredBinding,
}

/// This struct is an executable *media abstraction*, not persistent OS I/O.
/// `disk` and `nv_counter` survive simulated reboot; `pending` does not.
struct Medium {
    identity: PinnedCounterIdentity,
    disk: StoredBinding,
    pending: Option<StoredBinding>,
    nv_counter: u64,
    crash_at: Option<CrashPoint>,
    quarantined: bool,
    generation: u64,
}

impl Medium {
    fn inject(&mut self, point: CrashPoint) -> Result<(), BindingError> {
        if self.crash_at == Some(point) {
            self.crash_at = None;
            self.quarantined = true;
            return Err(BindingError::PersistenceUncertain);
        }
        Ok(())
    }

    fn check(&self, generation: u64) -> Result<(), BindingError> {
        if self.quarantined || self.generation != generation {
            return Err(BindingError::PersistenceUncertain);
        }
        Ok(())
    }
}

/// Explicitly test-only. Enrollment must come from independent trusted
/// provisioning; a real deployment MUST NOT construct a trusted high-water
/// from backed-up SQLite content or this simulator.
#[derive(Clone)]
pub struct CrashRecoverySimulator {
    medium: Arc<Mutex<Medium>>,
}

impl CrashRecoverySimulator {
    pub fn enrolled_for_test(initial: Committed) -> Self {
        Self {
            medium: Arc::new(Mutex::new(Medium {
                identity: initial.identity,
                disk: StoredBinding::Committed(initial),
                pending: None,
                nv_counter: initial.counter,
                crash_at: None,
                quarantined: false,
                generation: 0,
            })),
        }
    }

    fn medium(&self) -> Result<MutexGuard<'_, Medium>, BindingError> {
        self.medium
            .lock()
            .map_err(|_| BindingError::PersistenceUncertain)
    }

    /// Return handles bound to this boot generation. Old handles reject I/O
    /// after a reboot rather than silently resuming a crashed transaction.
    pub fn handles(
        &self,
    ) -> Result<
        (
            Arc<dyn CandidateMonotonicCounter>,
            Arc<dyn CandidateIntentStore>,
        ),
        BindingError,
    > {
        let generation = self.medium()?.generation;
        let handle = MediaHandle {
            medium: Arc::clone(&self.medium),
            generation,
        };
        Ok((Arc::new(handle.clone()), Arc::new(handle)))
    }

    pub fn fail_once(&self, point: CrashPoint) -> Result<(), BindingError> {
        let mut disk = self.medium()?;
        if disk.quarantined || disk.crash_at.is_some() || disk.pending.is_some() {
            return Err(BindingError::PersistenceUncertain);
        }
        disk.crash_at = Some(point);
        Ok(())
    }

    /// Simulates power loss: only the volatile staging area is erased.
    /// The NV count and acknowledged durable intent image survive.
    pub fn reboot(&self) -> Result<(), BindingError> {
        let mut disk = self.medium()?;
        disk.generation = disk
            .generation
            .checked_add(1)
            .ok_or(BindingError::PersistenceUncertain)?;
        disk.pending = None;
        disk.quarantined = false;
        disk.crash_at = None;
        Ok(())
    }

    pub fn durable_image(&self) -> Result<DurableImage, BindingError> {
        let disk = self.medium()?;
        Ok(DurableImage {
            nv_counter: disk.nv_counter,
            intent: disk.disk,
        })
    }

    /// Adversarial backup restore: changes only the untrusted intent image,
    /// never the non-rollbackable NV observation. Test behavior, NOT a repair.
    pub fn restore_untrusted_intent_for_test(
        &self,
        old: StoredBinding,
    ) -> Result<(), BindingError> {
        let mut disk = self.medium()?;
        if !disk.quarantined && disk.pending.is_some() {
            return Err(BindingError::PersistenceUncertain);
        }
        disk.disk = old;
        disk.pending = None;
        disk.generation = disk
            .generation
            .checked_add(1)
            .ok_or(BindingError::PersistenceUncertain)?;
        disk.quarantined = false;
        disk.crash_at = None;
        Ok(())
    }
}

#[derive(Clone)]
struct MediaHandle {
    medium: Arc<Mutex<Medium>>,
    generation: u64,
}

impl MediaHandle {
    fn lock(&self) -> Result<MutexGuard<'_, Medium>, BindingError> {
        let disk = self
            .medium
            .lock()
            .map_err(|_| BindingError::PersistenceUncertain)?;
        disk.check(self.generation)?;
        Ok(disk)
    }
}

impl CandidateMonotonicCounter for MediaHandle {
    fn identity(&self) -> PinnedCounterIdentity {
        // A stale handle's immutable public identity conveys no permission.
        self.medium
            .lock()
            .map(|disk| disk.identity)
            .unwrap_or(PinnedCounterIdentity {
                device_binding: [0; 32],
                nv_index: 0,
            })
    }

    fn read(&self) -> Result<u64, BindingError> {
        Ok(self.lock()?.nv_counter)
    }

    fn increment(&self) -> Result<(), BindingError> {
        let mut disk = self.lock()?;
        // A durable Prepared intent is mandatory before the irreversible NV
        // write. A volatile "prepared" write alone must never be sufficient.
        let StoredBinding::Prepared(intent) = disk.disk else {
            return Err(BindingError::JournalUnavailable);
        };
        if disk.pending.is_some() || intent.before.counter != disk.nv_counter {
            return Err(BindingError::CounterMismatch);
        }
        disk.inject(CrashPoint::IncrementBeforeWrite)?;
        disk.nv_counter = disk
            .nv_counter
            .checked_add(1)
            .ok_or(BindingError::CounterOverflow)?;
        disk.inject(CrashPoint::IncrementAfterWrite)?;
        Ok(())
    }
}

fn after_policy(intent: Prepared) -> UnifiedPolicyHighWater {
    UnifiedPolicyHighWater {
        policy_sequence: intent.after_sequence,
        policy_head: intent.after_head,
        revocation_root: intent.after_revocation_root,
        current_manifest: intent.after_manifest,
        ..intent.before.policy
    }
}

impl CandidateIntentStore for MediaHandle {
    fn load(&self) -> Result<StoredBinding, BindingError> {
        Ok(self.lock()?.disk)
    }

    fn prepare(&self, expected: Committed, next: Prepared) -> Result<(), BindingError> {
        let mut disk = self.lock()?;
        if disk.disk != StoredBinding::Committed(expected)
            || next.before != expected
            || expected.identity != disk.identity
            || expected.counter != disk.nv_counter
            || disk.pending.is_some()
        {
            return Err(BindingError::PersistenceUncertain);
        }
        disk.inject(CrashPoint::PrepareBeforeWrite)?;
        disk.pending = Some(StoredBinding::Prepared(next));
        disk.inject(CrashPoint::PrepareBeforeSync)?;
        // Simulates a *durability barrier*; not an actual fsync.
        disk.disk = disk.pending.take().ok_or(BindingError::PersistenceUncertain)?;
        disk.inject(CrashPoint::PrepareAfterSync)?;
        Ok(())
    }

    fn finalize(&self, expected: Prepared) -> Result<(), BindingError> {
        let mut disk = self.lock()?;
        let next_counter = expected
            .before
            .counter
            .checked_add(1)
            .ok_or(BindingError::CounterOverflow)?;
        if disk.disk != StoredBinding::Prepared(expected)
            || disk.pending.is_some()
            || expected.before.identity != disk.identity
            || disk.nv_counter != next_counter
        {
            return Err(BindingError::PersistenceUncertain);
        }
        disk.inject(CrashPoint::FinalizeBeforeWrite)?;
        disk.pending = Some(StoredBinding::Committed(Committed {
            identity: expected.before.identity,
            counter: next_counter,
            policy: after_policy(expected),
        }));
        disk.inject(CrashPoint::FinalizeBeforeSync)?;
        disk.disk = disk.pending.take().ok_or(BindingError::PersistenceUncertain)?;
        disk.inject(CrashPoint::FinalizeAfterSync)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm_counter_binding::{Diagnostic, inspect_counter};
    use crate::unified_policy_anchor::UnifiedPolicyHighWater;
    use loom_crypto::space_trust::{
        ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
        trust_manifest_transcript, verify_resource_trust_for_spike,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use loom_types::{ResourceId, SpaceId};

    fn seeded() -> (CrashRecoverySimulator, Committed, Prepared) {
        let root = SigningKey::from_bytes(&[30; 32]);
        let owner = SigningKey::from_bytes(&[11; 32]);
        let pin = ExternallyPinnedRootForSpike {
            space: SpaceId::from_bytes([1; 16]),
            public_key: root.verifying_key().to_bytes(),
            key_epoch: 7,
        };
        let manifest = ResourceTrustManifest {
            space: pin.space,
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner.verifying_key().to_bytes(),
            owner_key_epoch: 3,
            witness_public_keys: [
                SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes(),
                SigningKey::from_bytes(&[22; 32]).verifying_key().to_bytes(),
            ],
            writer_epoch: 1,
            root_key_epoch: 7,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let signed = SignedResourceTrust {
            manifest,
            signature: root.sign(&trust_manifest_transcript(&manifest)).to_bytes(),
        };
        let trust = verify_resource_trust_for_spike(&pin, &signed, 150).unwrap();
        let binding = Committed {
            identity: PinnedCounterIdentity {
                device_binding: [55; 32],
                nv_index: 0x0180_0111,
            },
            counter: 9,
            policy: UnifiedPolicyHighWater::initial(&trust),
        };
        let next = Prepared {
            before: binding,
            after_sequence: 1,
            after_head: [77; 32],
            after_revocation_root: [88; 32],
            after_manifest: trust.manifest_commitment(),
        };
        (CrashRecoverySimulator::enrolled_for_test(binding), binding, next)
    }

    #[test]
    fn every_crash_boundary_has_one_durable_outcome() {
        for point in [
            CrashPoint::PrepareBeforeWrite,
            CrashPoint::PrepareBeforeSync,
            CrashPoint::PrepareAfterSync,
            CrashPoint::IncrementBeforeWrite,
            CrashPoint::IncrementAfterWrite,
            CrashPoint::FinalizeBeforeWrite,
            CrashPoint::FinalizeBeforeSync,
            CrashPoint::FinalizeAfterSync,
        ] {
            let (media, original, next) = seeded();
            let (counter, intent) = media.handles().unwrap();
            media.fail_once(point).unwrap();
            let failure = match point {
                CrashPoint::PrepareBeforeWrite
                | CrashPoint::PrepareBeforeSync
                | CrashPoint::PrepareAfterSync => intent.prepare(original, next),
                CrashPoint::IncrementBeforeWrite | CrashPoint::IncrementAfterWrite => {
                    intent.prepare(original, next).unwrap();
                    counter.increment()
                }
                CrashPoint::FinalizeBeforeWrite
                | CrashPoint::FinalizeBeforeSync
                | CrashPoint::FinalizeAfterSync => {
                    intent.prepare(original, next).unwrap();
                    counter.increment().unwrap();
                    intent.finalize(next)
                }
            };
            assert_eq!(failure, Err(BindingError::PersistenceUncertain));
            assert_eq!(counter.read(), Err(BindingError::PersistenceUncertain));
            media.reboot().unwrap();
            let after = media.durable_image().unwrap();
            let expected_count = if matches!(
                point,
                CrashPoint::IncrementAfterWrite
                    | CrashPoint::FinalizeBeforeWrite
                    | CrashPoint::FinalizeBeforeSync
                    | CrashPoint::FinalizeAfterSync
            ) {
                10
            } else {
                9
            };
            assert_eq!(after.nv_counter, expected_count);
            let expected_binding = match point {
                CrashPoint::PrepareBeforeWrite | CrashPoint::PrepareBeforeSync => {
                    StoredBinding::Committed(original)
                }
                CrashPoint::FinalizeAfterSync => StoredBinding::Committed(Committed {
                    identity: original.identity,
                    counter: 10,
                    policy: after_policy(next),
                }),
                _ => StoredBinding::Prepared(next),
            };
            assert_eq!(after.intent, expected_binding);
            let diagnostic = inspect_counter(original.identity, after.nv_counter, after.intent).unwrap();
            if expected_binding == StoredBinding::Prepared(next) {
                assert_eq!(
                    diagnostic,
                    if expected_count == 10 {
                        Diagnostic::IncrementNeedsSignedRecheck
                    } else {
                        Diagnostic::IntentBeforeIncrement
                    }
                );
            } else {
                assert_eq!(diagnostic, Diagnostic::MatchingCounterOnly);
            }
            // Old pre-crash handles cannot be reused after reboot.
            assert_eq!(counter.read(), Err(BindingError::PersistenceUncertain));
        }
    }

    #[test]
    fn nv_increment_without_durable_prepared_intent_is_refused() {
        let (media, original, next) = seeded();
        let (counter, intent) = media.handles().unwrap();
        assert_eq!(counter.increment(), Err(BindingError::JournalUnavailable));
        assert_eq!(media.durable_image().unwrap().nv_counter, 9);
        media.fail_once(CrashPoint::PrepareBeforeSync).unwrap();
        assert_eq!(
            intent.prepare(original, next),
            Err(BindingError::PersistenceUncertain)
        );
        media.reboot().unwrap();
        let (counter, _) = media.handles().unwrap();
        assert_eq!(counter.increment(), Err(BindingError::JournalUnavailable));
    }

    #[test]
    fn external_restore_does_not_reset_nonrollbackable_counter() {
        let (media, initial, next) = seeded();
        let (counter, intent) = media.handles().unwrap();
        intent.prepare(initial, next).unwrap();
        counter.increment().unwrap();
        intent.finalize(next).unwrap();
        media.reboot().unwrap();
        media
            .restore_untrusted_intent_for_test(StoredBinding::Committed(initial))
            .unwrap();
        let image = media.durable_image().unwrap();
        assert_eq!(image.nv_counter, 10);
        assert_eq!(
            inspect_counter(initial.identity, image.nv_counter, image.intent),
            Err(BindingError::CounterMismatch)
        );
    }

    #[test]
    fn wrong_finalize_or_stale_boot_handle_cannot_rewrite_disk() {
        let (media, old, next) = seeded();
        let (counter, intent) = media.handles().unwrap();
        assert_eq!(intent.finalize(next), Err(BindingError::PersistenceUncertain));
        intent.prepare(old, next).unwrap();
        media.reboot().unwrap();
        assert_eq!(counter.increment(), Err(BindingError::PersistenceUncertain));
        assert_eq!(intent.finalize(next), Err(BindingError::PersistenceUncertain));
        let (_, restarted_intent) = media.handles().unwrap();
        assert_eq!(restarted_intent.finalize(next), Err(BindingError::PersistenceUncertain));
        assert_eq!(media.durable_image().unwrap().intent, StoredBinding::Prepared(next));
    }
}
