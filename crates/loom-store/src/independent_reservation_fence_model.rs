//! L-001AA: independent *logical* reservation-fence persistence oracle.
//!
//! This is volatile in-process state that survives a SIMULATED reboot.
//! NO actual TPM NV, trusted storage, signer enrollment, verified journal
//! signatures, physical power-cut atomicity, or production authorization.
//! All journal views MUST be authenticated elsewhere before they are input
//! to this model; a missing cross-process append notification is a NO-GO.

use crate::tpm_counter_binding::BindingError;
use loom_types::{ResourceId, SpaceId};
use std::sync::{Arc, Mutex, MutexGuard};

/// Model input ONLY. Not a signed proof merely because of its type name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalView {
    pub space: SpaceId,
    pub resource: ResourceId,
    pub root_public_key: [u8; 32],
    pub root_epoch: u64,
    pub genesis_manifest: [u8; 32],
    pub writer_epoch: u64,
    pub sequence: u64,
    pub policy_head: [u8; 32],
    pub revocation_root: [u8; 32],
    pub owner_manifest: [u8; 32],
}

impl JournalView {
    fn is_successor_of(&self, old: Self) -> bool {
        self.space == old.space
            && self.resource == old.resource
            && self.root_public_key == old.root_public_key
            && self.root_epoch == old.root_epoch
            && self.genesis_manifest == old.genesis_manifest
            && self.writer_epoch == old.writer_epoch
            && old.sequence.checked_add(1) == Some(self.sequence)
            && self.policy_head != old.policy_head
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FencePhase {
    Idle,
    Reserved {
        ticket: u64,
        view: JournalView,
    },
    Prepared {
        ticket: u64,
        view: JournalView,
        signed_intent_digest: [u8; 32],
    },
    StalePrepared {
        ticket: u64,
        view: JournalView,
        signed_intent_digest: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FenceImage {
    pub generation: u64,
    pub journal: JournalView,
    pub phase: FencePhase,
}

/// One-shot simulated power-loss, before/after the "durable" model commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceCrash {
    ReserveBefore,
    ReserveAfter,
    PrepareBefore,
    PrepareAfter,
    AppendBefore,
    AppendAfter,
}

struct Inner {
    image: FenceImage,
    boot: u64,
    halted: bool,
    fault: Option<FenceCrash>,
}

impl Inner {
    fn check(&self, boot: u64) -> Result<(), BindingError> {
        if self.halted || self.boot != boot {
            return Err(BindingError::PersistenceUncertain);
        }
        Ok(())
    }

    fn cut(&mut self, target: FenceCrash) -> Result<(), BindingError> {
        if self.fault == Some(target) {
            self.fault = None;
            self.halted = true;
            return Err(BindingError::PersistenceUncertain);
        }
        Ok(())
    }

    fn commit(
        &mut self,
        image: FenceImage,
        before: FenceCrash,
        after: FenceCrash,
    ) -> Result<(), BindingError> {
        self.cut(before)?;
        self.image = image;
        self.cut(after)
    }
}

/// Exactly one logical independent medium shared by all model writers.
/// `Arc<Mutex<...>>` is NOT a physically separate nonrollbackable medium.
#[derive(Clone)]
pub struct ReservationFenceSimulator {
    inner: Arc<Mutex<Inner>>,
}

impl ReservationFenceSimulator {
    pub fn enrolled_for_test(initial: JournalView) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                image: FenceImage {
                    generation: 0,
                    journal: initial,
                    phase: FencePhase::Idle,
                },
                boot: 0,
                halted: false,
                fault: None,
            })),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, BindingError> {
        self.inner
            .lock()
            .map_err(|_| BindingError::PersistenceUncertain)
    }

    /// Old handles are boot-bound and fail closed after reboot.
    pub fn handle(&self) -> Result<ReservationFenceHandle, BindingError> {
        let boot = self.lock()?.boot;
        Ok(ReservationFenceHandle {
            inner: Arc::clone(&self.inner),
            boot,
        })
    }

    /// Simulated crash: the image is retained but the boot epoch changes.
    pub fn reboot(&self) -> Result<(), BindingError> {
        let mut inner = self.lock()?;
        inner.boot = inner
            .boot
            .checked_add(1)
            .ok_or(BindingError::CounterOverflow)?;
        inner.halted = false;
        inner.fault = None;
        Ok(())
    }

    pub fn fail_once(&self, point: FenceCrash) -> Result<(), BindingError> {
        let mut inner = self.lock()?;
        if inner.halted || inner.fault.is_some() {
            return Err(BindingError::PersistenceUncertain);
        }
        inner.fault = Some(point);
        Ok(())
    }

    /// Test-only inspection of simulated retained state, including on crash.
    pub fn retained_image_for_test(&self) -> Result<FenceImage, BindingError> {
        Ok(self.lock()?.image)
    }
}

/// A single boot of the hypothetical independent CAS device.
#[derive(Clone)]
pub struct ReservationFenceHandle {
    inner: Arc<Mutex<Inner>>,
    boot: u64,
}

impl ReservationFenceHandle {
    fn lock(&self) -> Result<MutexGuard<'_, Inner>, BindingError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| BindingError::PersistenceUncertain)?;
        inner.check(self.boot)?;
        Ok(inner)
    }

    pub fn observe(&self) -> Result<FenceImage, BindingError> {
        Ok(self.lock()?.image)
    }

    /// Reserve only an exact externally verified current journal view;
    /// two writers cannot reserve one generation. The *local* signed
    /// history must still be independently rechecked before any real CAS.
    pub fn reserve(&self, expected: FenceImage) -> Result<u64, BindingError> {
        let mut inner = self.lock()?;
        if inner.image != expected || expected.phase != FencePhase::Idle {
            return Err(BindingError::PersistenceUncertain);
        }
        let next = expected
            .generation
            .checked_add(1)
            .ok_or(BindingError::CounterOverflow)?;
        let changed = FenceImage {
            generation: next,
            journal: expected.journal,
            phase: FencePhase::Reserved {
                ticket: next,
                view: expected.journal,
            },
        };
        inner.commit(changed, FenceCrash::ReserveBefore, FenceCrash::ReserveAfter)?;
        Ok(next)
    }

    /// The caller must supply a *previously strictly verified* canonical
    /// signed Intent digest from the pinned key and independent NV state.
    /// This model does not authenticate the digest or write any hardware.
    pub fn publish_prepared(
        &self,
        expected: FenceImage,
        ticket: u64,
        signed_intent_digest: [u8; 32],
    ) -> Result<(), BindingError> {
        let mut inner = self.lock()?;
        if inner.image != expected
            || expected.phase
                != (FencePhase::Reserved {
                    ticket,
                    view: expected.journal,
                })
            || signed_intent_digest == [0; 32]
        {
            return Err(BindingError::BrokenIntent);
        }
        let changed = FenceImage {
            generation: expected
                .generation
                .checked_add(1)
                .ok_or(BindingError::CounterOverflow)?,
            journal: expected.journal,
            phase: FencePhase::Prepared {
                ticket,
                view: expected.journal,
                signed_intent_digest,
            },
        };
        inner.commit(changed, FenceCrash::PrepareBefore, FenceCrash::PrepareAfter)
    }

    /// ALL policy writers must notify this authoritative model *and* pass
    /// independently verified signed history. A direct SQLite bypass makes
    /// this model unsafe: an absent notification is undetectable here.
    pub fn observed_signed_append(
        &self,
        expected: FenceImage,
        successor: JournalView,
    ) -> Result<(), BindingError> {
        let mut inner = self.lock()?;
        if inner.image != expected || !successor.is_successor_of(expected.journal) {
            return Err(BindingError::InvalidPolicyTransition);
        }
        let phase = match expected.phase {
            FencePhase::Idle | FencePhase::Reserved { .. } => FencePhase::Idle,
            FencePhase::Prepared {
                ticket,
                view,
                signed_intent_digest,
            }
            | FencePhase::StalePrepared {
                ticket,
                view,
                signed_intent_digest,
            } => FencePhase::StalePrepared {
                ticket,
                view,
                signed_intent_digest,
            },
        };
        let changed = FenceImage {
            generation: expected
                .generation
                .checked_add(1)
                .ok_or(BindingError::CounterOverflow)?,
            journal: successor,
            phase,
        };
        inner.commit(changed, FenceCrash::AppendBefore, FenceCrash::AppendAfter)
    }

    // The model intentionally has NO automatic recovery method that could
    // authorize ambiguous Prepared. A reviewed witness/counter/hardware
    // reconciliation procedure must be introduced before such an API.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn genesis() -> JournalView {
        JournalView {
            space: SpaceId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            root_public_key: [30; 32],
            root_epoch: 7,
            genesis_manifest: [24; 32],
            writer_epoch: 1,
            sequence: 1,
            policy_head: [42; 32],
            revocation_root: [48; 32],
            owner_manifest: [45; 32],
        }
    }

    fn signed_successor(old: JournalView) -> JournalView {
        JournalView {
            sequence: old.sequence + 1,
            policy_head: [66; 32],
            revocation_root: [77; 32],
            ..old
        }
    }

    #[test]
    fn two_phase_reservation_prepared_is_retained_across_reboot() {
        let model = ReservationFenceSimulator::enrolled_for_test(genesis());
        let first = model.handle().unwrap();
        let original = first.observe().unwrap();
        let ticket = first.reserve(original).unwrap();
        let reserved = first.observe().unwrap();
        assert_eq!(reserved.generation, 1);
        first.publish_prepared(reserved, ticket, [88; 32]).unwrap();
        assert_eq!(
            first.observe().unwrap().phase,
            FencePhase::Prepared {
                ticket,
                view: genesis(),
                signed_intent_digest: [88; 32],
            }
        );
        model.reboot().unwrap();
        assert_eq!(first.observe(), Err(BindingError::PersistenceUncertain));
        let rebooted = model.handle().unwrap();
        assert_eq!(rebooted.observe().unwrap().generation, 2);
        assert_eq!(
            rebooted.reserve(rebooted.observe().unwrap()),
            Err(BindingError::PersistenceUncertain)
        );
    }

    #[test]
    fn signed_append_invalidates_outstanding_ticket() {
        let model = ReservationFenceSimulator::enrolled_for_test(genesis());
        let handle = model.handle().unwrap();
        let ticket = handle.reserve(handle.observe().unwrap()).unwrap();
        let reserved = handle.observe().unwrap();
        handle
            .observed_signed_append(reserved, signed_successor(genesis()))
            .unwrap();
        assert_eq!(
            handle.publish_prepared(reserved, ticket, [88; 32]),
            Err(BindingError::BrokenIntent)
        );
        let updated = handle.observe().unwrap();
        assert_eq!(updated.journal.sequence, 2);
        assert_eq!(updated.phase, FencePhase::Idle);
        assert_eq!(updated.generation, 2);
    }

    #[test]
    fn emergency_append_after_prepared_is_stale_not_authorized() {
        let model = ReservationFenceSimulator::enrolled_for_test(genesis());
        let handle = model.handle().unwrap();
        let ticket = handle.reserve(handle.observe().unwrap()).unwrap();
        handle
            .publish_prepared(handle.observe().unwrap(), ticket, [99; 32])
            .unwrap();
        handle
            .observed_signed_append(handle.observe().unwrap(), signed_successor(genesis()))
            .unwrap();
        assert!(matches!(
            handle.observe().unwrap().phase,
            FencePhase::StalePrepared { .. }
        ));
        model.reboot().unwrap();
        let later = model.handle().unwrap();
        assert!(matches!(
            later.observe().unwrap().phase,
            FencePhase::StalePrepared { .. }
        ));
        assert_eq!(
            later.reserve(later.observe().unwrap()),
            Err(BindingError::PersistenceUncertain)
        );
    }

    #[test]
    fn all_six_crash_boundaries_preserve_only_authoritative_image() {
        for cut in [
            FenceCrash::ReserveBefore,
            FenceCrash::ReserveAfter,
            FenceCrash::PrepareBefore,
            FenceCrash::PrepareAfter,
            FenceCrash::AppendBefore,
            FenceCrash::AppendAfter,
        ] {
            let model = ReservationFenceSimulator::enrolled_for_test(genesis());
            let boot = model.handle().unwrap();
            let original = boot.observe().unwrap();
            let result = match cut {
                FenceCrash::ReserveBefore | FenceCrash::ReserveAfter => {
                    model.fail_once(cut).unwrap();
                    boot.reserve(original).map(|_| ())
                }
                FenceCrash::PrepareBefore | FenceCrash::PrepareAfter => {
                    let ticket = boot.reserve(original).unwrap();
                    model.fail_once(cut).unwrap();
                    boot.publish_prepared(boot.observe().unwrap(), ticket, [91; 32])
                }
                FenceCrash::AppendBefore | FenceCrash::AppendAfter => {
                    boot.reserve(original).unwrap();
                    model.fail_once(cut).unwrap();
                    boot.observed_signed_append(
                        boot.observe().unwrap(),
                        signed_successor(genesis()),
                    )
                }
            };
            assert_eq!(result, Err(BindingError::PersistenceUncertain));
            assert_eq!(boot.observe(), Err(BindingError::PersistenceUncertain));
            let survived = model.retained_image_for_test().unwrap();
            model.reboot().unwrap();
            assert_eq!(model.handle().unwrap().observe(), Ok(survived));
            let expected_generation = match cut {
                FenceCrash::ReserveBefore => 0,
                FenceCrash::ReserveAfter | FenceCrash::PrepareBefore | FenceCrash::AppendBefore => 1,
                FenceCrash::PrepareAfter | FenceCrash::AppendAfter => 2,
            };
            assert_eq!(survived.generation, expected_generation);
        }
    }

    #[test]
    fn stale_snapshot_double_reserve_and_replay_digest_are_denied() {
        let model = ReservationFenceSimulator::enrolled_for_test(genesis());
        let a = model.handle().unwrap();
        let b = model.handle().unwrap();
        let old = a.observe().unwrap();
        let t = a.reserve(old).unwrap();
        assert_eq!(b.reserve(old), Err(BindingError::PersistenceUncertain));
        let expected = a.observe().unwrap();
        assert_eq!(
            a.publish_prepared(expected, t, [0; 32]),
            Err(BindingError::BrokenIntent)
        );
        a.publish_prepared(expected, t, [1; 32]).unwrap();
        assert_eq!(
            b.publish_prepared(expected, t, [1; 32]),
            Err(BindingError::BrokenIntent)
        );
    }

    #[test]
    fn rejects_policy_fork_device_scope_change_and_sequence_regression() {
        let model = ReservationFenceSimulator::enrolled_for_test(genesis());
        let writer = model.handle().unwrap();
        let old = writer.observe().unwrap();
        let mut fork = signed_successor(genesis());
        fork.policy_head = genesis().policy_head;
        assert_eq!(
            writer.observed_signed_append(old, fork),
            Err(BindingError::InvalidPolicyTransition)
        );
        fork = signed_successor(genesis());
        fork.root_public_key = [99; 32];
        assert_eq!(
            writer.observed_signed_append(old, fork),
            Err(BindingError::InvalidPolicyTransition)
        );
        fork = signed_successor(genesis());
        fork.sequence = 1;
        assert_eq!(
            writer.observed_signed_append(old, fork),
            Err(BindingError::InvalidPolicyTransition)
        );
        assert_eq!(writer.observe(), Ok(old));
    }

    #[test]
    fn competing_threads_have_single_linearized_reservation_winner() {
        let model = ReservationFenceSimulator::enrolled_for_test(genesis());
        let old = model.handle().unwrap().observe().unwrap();
        let a = model.handle().unwrap();
        let b = model.handle().unwrap();
        let t1 = thread::spawn(move || a.reserve(old));
        let t2 = thread::spawn(move || b.reserve(old));
        let results = [t1.join().unwrap(), t2.join().unwrap()];
        assert_eq!(results.iter().filter(|x| x.is_ok()).count(), 1);
        assert_eq!(model.handle().unwrap().observe().unwrap().generation, 1);
    }

    #[test]
    fn unnotified_external_writer_is_not_detectable_by_model() {
        let model = ReservationFenceSimulator::enrolled_for_test(genesis());
        let h = model.handle().unwrap();
        let initial = h.observe().unwrap();
        let ticket = h.reserve(initial).unwrap();
        // This is a NEGATIVE test: a raw SQLite writer advanced a real
        // journal, but the hypothetical independent device saw no callback.
        // The model can accept a stale Prepared. Production cannot rely
        // on optional callbacks and must enforce external writer fencing.
        let external_actual_journal = signed_successor(genesis());
        h.publish_prepared(h.observe().unwrap(), ticket, [81; 32])
            .unwrap();
        assert_ne!(h.observe().unwrap().journal, external_actual_journal);
        assert!(matches!(
            h.observe().unwrap().phase,
            FencePhase::Prepared { .. }
        ));
    }
}
