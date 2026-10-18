//! L-001V: simulated signed Prepared/Committed write protocol and replay-fence
//! compare-and-advance. This is an IN-PROCESS model, not trusted persistence.
//!
//! No real TPM2 NV writes, durable atomicity across media, key enrollment,
//! trusted monotonic replay fence, hardware-backed signing or ServiceOpen.
//! A signer signs outside the model CAS lock; stale signatures must fail CAS.

use crate::authenticated_intent_read_gate::{
    CandidateSignedIntentReader, CandidateTrustedIntentReader,
};
use crate::authenticated_intent_record::{
    ExternalReplayFence, ExternalSignerPin, IntentRecord, signed_record_digest, signing_preimage,
    verify_signed_record,
};
use crate::tpm_counter_binding::{
    BindingError, CandidateIntentStore, CandidateMonotonicCounter, Committed,
    PinnedCounterIdentity, Prepared, StoredBinding,
};
use std::sync::{Arc, Mutex, MutexGuard};

/// Production adapters would need a separately enrolled, hardware-controlled
/// signing identity. Only test implementations exist in this project.
pub trait CandidateExternalIntentSigner: Send + Sync {
    fn sign(&self, canonical_preimage: &[u8]) -> Result<[u8; 64], BindingError>;
}

/// Boot-scoped trait handles used by the candidate counter protocol.
pub type CandidateWriteHandles = (
    Arc<dyn CandidateMonotonicCounter>,
    Arc<dyn CandidateIntentStore>,
);

/// Read-only sources for the independently verifying L-001U adapter.
pub type CandidateReadSources = (
    Arc<dyn CandidateSignedIntentReader>,
    Arc<dyn CandidateTrustedIntentReader>,
);

/// A one-shot simulated crash; both BEFORE and AFTER outcomes return an
/// ambiguous error, and writes are quarantined until reboot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteCrashPoint {
    PrepareBeforeCas,
    PrepareAfterCas,
    CounterBeforeWrite,
    CounterAfterWrite,
    FinalizeBeforeCas,
    FinalizeAfterCas,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedMediaImage {
    pub signed_frame: Vec<u8>,
    pub fence: ExternalReplayFence,
    pub counter: u64,
}

struct State {
    frame: Vec<u8>,
    pin: ExternalSignerPin,
    fence: ExternalReplayFence,
    counter: u64,
    signer: Arc<dyn CandidateExternalIntentSigner>,
    generation: u64,
    halted: bool,
    fault: Option<WriteCrashPoint>,
}

impl State {
    fn check(&self, generation: u64) -> Result<(), BindingError> {
        if self.halted || self.generation != generation {
            return Err(BindingError::PersistenceUncertain);
        }
        Ok(())
    }

    fn inject(&mut self, at: WriteCrashPoint) -> Result<(), BindingError> {
        if self.fault == Some(at) {
            self.fault = None;
            self.halted = true;
            return Err(BindingError::PersistenceUncertain);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Snapshot {
    frame: Vec<u8>,
    pin: ExternalSignerPin,
    fence: ExternalReplayFence,
    counter: u64,
    generation: u64,
    signer: Arc<dyn CandidateExternalIntentSigner>,
}

/// The word "durable" below means ONLY survives simulated reboot. Both
/// authenticated frame+fence and NV count are ordinary process memory.
#[derive(Clone)]
pub struct AuthenticatedWriteSimulator {
    state: Arc<Mutex<State>>,
}

impl AuthenticatedWriteSimulator {
    /// Test fixture enrollment. The signed initial record, pin and replay
    /// floor are externally supplied: this constructor is NOT trusted setup.
    pub fn enrolled_for_test(
        frame: Vec<u8>,
        pin: ExternalSignerPin,
        fence: ExternalReplayFence,
        counter: u64,
        signer: Arc<dyn CandidateExternalIntentSigner>,
    ) -> Result<Self, BindingError> {
        let verified = verify_signed_record(&frame, &pin, fence, counter)
            .map_err(|_| BindingError::BrokenIntent)?;
        if verified.record().record_sequence != fence.minimum_record_sequence
            || verified.digest() != fence.last_record_digest
        {
            return Err(BindingError::BrokenIntent);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                frame,
                pin,
                fence,
                counter,
                signer,
                generation: 0,
                halted: false,
                fault: None,
            })),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, BindingError> {
        self.state
            .lock()
            .map_err(|_| BindingError::PersistenceUncertain)
    }

    /// Independent trait handles for existing candidate journal-bound path.
    pub fn handles(&self) -> Result<CandidateWriteHandles, BindingError> {
        let generation = self.lock()?.generation;
        let h = Arc::new(WriteHandle {
            state: Arc::clone(&self.state),
            generation,
        });
        Ok((h.clone(), h))
    }

    /// A read-only view still passes through L-001U's strict double-read gate.
    pub fn read_sources(&self) -> Result<CandidateReadSources, BindingError> {
        let generation = self.lock()?.generation;
        let h = Arc::new(WriteHandle {
            state: Arc::clone(&self.state),
            generation,
        });
        Ok((h.clone(), h))
    }

    pub fn fail_once(&self, at: WriteCrashPoint) -> Result<(), BindingError> {
        let mut state = self.lock()?;
        if state.halted || state.fault.is_some() {
            return Err(BindingError::PersistenceUncertain);
        }
        state.fault = Some(at);
        Ok(())
    }

    /// Simulated power loss invalidates all prior handles; signed image and
    /// fence plus the NV count survive, even after an after-CAS error.
    pub fn reboot(&self) -> Result<(), BindingError> {
        let mut state = self.lock()?;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(BindingError::PersistenceUncertain)?;
        state.halted = false;
        state.fault = None;
        Ok(())
    }

    pub fn image(&self) -> Result<SignedMediaImage, BindingError> {
        let state = self.lock()?;
        Ok(SignedMediaImage {
            signed_frame: state.frame.clone(),
            fence: state.fence,
            counter: state.counter,
        })
    }

    /// Emulates replacing an ordinary storage backup. The authenticated
    /// independent replay fence and NV count remain untouched.
    pub fn restore_untrusted_frame_for_test(&self, older: Vec<u8>) -> Result<(), BindingError> {
        let mut state = self.lock()?;
        state.frame = older;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(BindingError::PersistenceUncertain)?;
        state.halted = false;
        state.fault = None;
        Ok(())
    }
}

#[derive(Clone)]
struct WriteHandle {
    state: Arc<Mutex<State>>,
    generation: u64,
}

#[derive(Clone, Copy)]
enum Transition {
    Prepare,
    Finalize,
}

impl WriteHandle {
    fn lock(&self) -> Result<MutexGuard<'_, State>, BindingError> {
        let state = self
            .state
            .lock()
            .map_err(|_| BindingError::PersistenceUncertain)?;
        state.check(self.generation)?;
        Ok(state)
    }

    fn snapshot(&self) -> Result<(Snapshot, StoredBinding), BindingError> {
        let state = self.lock()?;
        let current = verify_signed_record(&state.frame, &state.pin, state.fence, state.counter)
            .map_err(|_| BindingError::BrokenIntent)?;
        // No valid write operation may start from a higher unpinned record
        // than the fence; an independently authenticated fence must match
        // the exact current signed record.
        if current.record().record_sequence != state.fence.minimum_record_sequence
            || current.digest() != state.fence.last_record_digest
        {
            return Err(BindingError::BrokenIntent);
        }
        Ok((
            Snapshot {
                frame: state.frame.clone(),
                pin: state.pin,
                fence: state.fence,
                counter: state.counter,
                generation: state.generation,
                signer: Arc::clone(&state.signer),
            },
            current.record().binding,
        ))
    }

    /// Sign outside the exclusive CAS region. The final compare includes
    /// *all* old snapshot fields and count; a competing writer cannot
    /// silently commit a stale Prepared or Committed record.
    fn transition(
        &self,
        old: StoredBinding,
        next: StoredBinding,
        step: Transition,
    ) -> Result<(), BindingError> {
        let (snapshot, seen) = self.snapshot()?;
        if seen != old {
            return Err(BindingError::PersistenceUncertain);
        }
        match (step, old, next) {
            (Transition::Prepare, StoredBinding::Committed(before), StoredBinding::Prepared(p))
                if p.before == before && before.counter == snapshot.counter => {}
            (Transition::Finalize, StoredBinding::Prepared(p), StoredBinding::Committed(c))
                if c.identity == p.before.identity
                    && c.policy.current_manifest == p.after_manifest
                    && c.policy.policy_sequence == p.after_sequence
                    && c.policy.policy_head == p.after_head
                    && c.policy.revocation_root == p.after_revocation_root
                    && c.policy.space == p.before.policy.space
                    && c.policy.resource == p.before.policy.resource
                    && c.policy.root_public_key == p.before.policy.root_public_key
                    && c.policy.root_key_epoch == p.before.policy.root_key_epoch
                    && c.policy.genesis_manifest == p.before.policy.genesis_manifest
                    && c.policy.writer_epoch == p.before.policy.writer_epoch
                    && p.before.counter.checked_add(1) == Some(c.counter)
                    && c.counter == snapshot.counter => {}
            _ => return Err(BindingError::BrokenIntent),
        }

        let new_seq = snapshot
            .fence
            .minimum_record_sequence
            .checked_add(1)
            .ok_or(BindingError::CounterOverflow)?;
        let record = IntentRecord {
            record_sequence: new_seq,
            signer_epoch: snapshot.pin.signer_epoch,
            signer_public_key: snapshot.pin.signer_public_key,
            binding: next,
        };
        let mut new_frame = signing_preimage(&record).map_err(|_| BindingError::BrokenIntent)?;
        let sig = snapshot.signer.sign(&new_frame)?;
        new_frame.extend_from_slice(&sig);
        let fence = ExternalReplayFence {
            minimum_record_sequence: new_seq,
            minimum_counter: snapshot.counter,
            last_record_digest: signed_record_digest(&new_frame),
        };
        let confirmed = verify_signed_record(&new_frame, &snapshot.pin, fence, snapshot.counter)
            .map_err(|_| BindingError::BrokenIntent)?;
        if confirmed.record().binding != next {
            return Err(BindingError::BrokenIntent);
        }

        let mut state = self.lock()?;
        if state.frame != snapshot.frame
            || state.pin != snapshot.pin
            || state.fence != snapshot.fence
            || state.counter != snapshot.counter
            || state.generation != snapshot.generation
        {
            return Err(BindingError::PersistenceUncertain);
        }
        let (before, after) = match step {
            Transition::Prepare => (
                WriteCrashPoint::PrepareBeforeCas,
                WriteCrashPoint::PrepareAfterCas,
            ),
            Transition::Finalize => (
                WriteCrashPoint::FinalizeBeforeCas,
                WriteCrashPoint::FinalizeAfterCas,
            ),
        };
        state.inject(before)?;
        // A *single simulated atomic CAS* updates signed frame and fence.
        // Real hardware must prove equivalent semantics across domains.
        state.frame = new_frame;
        state.fence = fence;
        state.inject(after)?;
        Ok(())
    }
}

impl CandidateIntentStore for WriteHandle {
    fn load(&self) -> Result<StoredBinding, BindingError> {
        Ok(self.snapshot()?.1)
    }

    fn prepare(&self, expected: Committed, next: Prepared) -> Result<(), BindingError> {
        self.transition(
            StoredBinding::Committed(expected),
            StoredBinding::Prepared(next),
            Transition::Prepare,
        )
    }

    fn finalize(&self, expected: Prepared) -> Result<(), BindingError> {
        let updated = Committed {
            identity: expected.before.identity,
            counter: expected
                .before
                .counter
                .checked_add(1)
                .ok_or(BindingError::CounterOverflow)?,
            policy: crate::unified_policy_anchor::UnifiedPolicyHighWater {
                policy_sequence: expected.after_sequence,
                policy_head: expected.after_head,
                revocation_root: expected.after_revocation_root,
                current_manifest: expected.after_manifest,
                ..expected.before.policy
            },
        };
        self.transition(
            StoredBinding::Prepared(expected),
            StoredBinding::Committed(updated),
            Transition::Finalize,
        )
    }
}

impl CandidateMonotonicCounter for WriteHandle {
    fn identity(&self) -> PinnedCounterIdentity {
        self.state
            .lock()
            .map(|state| state.pin.device)
            .unwrap_or(PinnedCounterIdentity {
                device_binding: [0; 32],
                nv_index: 0,
            })
    }

    fn read(&self) -> Result<u64, BindingError> {
        Ok(self.lock()?.counter)
    }

    fn increment(&self) -> Result<(), BindingError> {
        let mut state = self.lock()?;
        let verified = verify_signed_record(&state.frame, &state.pin, state.fence, state.counter)
            .map_err(|_| BindingError::BrokenIntent)?;
        let StoredBinding::Prepared(prepared) = verified.record().binding else {
            return Err(BindingError::PersistenceUncertain);
        };
        if prepared.before.counter != state.counter {
            return Err(BindingError::CounterMismatch);
        }
        state.inject(WriteCrashPoint::CounterBeforeWrite)?;
        state.counter = state
            .counter
            .checked_add(1)
            .ok_or(BindingError::CounterOverflow)?;
        state.inject(WriteCrashPoint::CounterAfterWrite)?;
        Ok(())
    }
}

impl CandidateSignedIntentReader for WriteHandle {
    fn read_frame(&self) -> Result<Vec<u8>, BindingError> {
        Ok(self.lock()?.frame.clone())
    }
}

impl CandidateTrustedIntentReader for WriteHandle {
    fn read_trust(&self) -> Result<(ExternalSignerPin, ExternalReplayFence), BindingError> {
        let state = self.lock()?;
        Ok((state.pin, state.fence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated_intent_read_gate::AuthenticatedReadOnlyIntent;
    use crate::tpm_counter_binding::Diagnostic;
    use crate::unified_policy_anchor::UnifiedPolicyHighWater;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_types::{ResourceId, SpaceId};
    use std::sync::mpsc;
    use std::thread;

    struct TestSigner(SigningKey);

    impl CandidateExternalIntentSigner for TestSigner {
        fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], BindingError> {
            Ok(self.0.sign(bytes).to_bytes())
        }
    }

    fn base() -> (
        SigningKey,
        ExternalSignerPin,
        Committed,
        Vec<u8>,
        ExternalReplayFence,
    ) {
        let signing_key = SigningKey::from_bytes(&[51; 32]);
        let policy = UnifiedPolicyHighWater {
            space: SpaceId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            root_public_key: [31; 32],
            root_key_epoch: 7,
            genesis_manifest: [21; 32],
            current_manifest: [21; 32],
            writer_epoch: 1,
            policy_sequence: 0,
            policy_head: [0; 32],
            revocation_root: [0; 32],
        };
        let device = PinnedCounterIdentity {
            device_binding: [42; 32],
            nv_index: 0x0180_0111,
        };
        let committed = Committed {
            identity: device,
            counter: 9,
            policy,
        };
        let pin = ExternalSignerPin {
            signer_public_key: signing_key.verifying_key().to_bytes(),
            signer_epoch: 2,
            device,
            space: policy.space,
            resource: policy.resource,
            root_public_key: policy.root_public_key,
            root_key_epoch: policy.root_key_epoch,
            genesis_manifest: policy.genesis_manifest,
            writer_epoch: policy.writer_epoch,
        };
        let record = IntentRecord {
            record_sequence: 1,
            signer_epoch: 2,
            signer_public_key: pin.signer_public_key,
            binding: StoredBinding::Committed(committed),
        };
        let mut initial = signing_preimage(&record).unwrap();
        let sig = signing_key.sign(&initial).to_bytes();
        initial.extend_from_slice(&sig);
        let fence = ExternalReplayFence {
            minimum_record_sequence: 1,
            minimum_counter: 9,
            last_record_digest: signed_record_digest(&initial),
        };
        (signing_key, pin, committed, initial, fence)
    }

    fn fixture() -> (AuthenticatedWriteSimulator, Committed, Prepared) {
        let (key, pin, committed, frame, fence) = base();
        let simulator = AuthenticatedWriteSimulator::enrolled_for_test(
            frame,
            pin,
            fence,
            9,
            Arc::new(TestSigner(key)),
        )
        .unwrap();
        let prepared = Prepared {
            before: committed,
            after_sequence: 1,
            after_head: [66; 32],
            after_revocation_root: [77; 32],
            after_manifest: committed.policy.current_manifest,
        };
        (simulator, committed, prepared)
    }

    #[test]
    fn successful_signed_prepare_counter_finalize_advances_fence_twice() {
        let (model, before, prepared) = fixture();
        let (counter, intent) = model.handles().unwrap();
        assert_eq!(intent.load(), Ok(StoredBinding::Committed(before)));
        intent.prepare(before, prepared).unwrap();
        let first = model.image().unwrap();
        assert_eq!(first.fence.minimum_record_sequence, 2);
        assert_eq!(intent.load(), Ok(StoredBinding::Prepared(prepared)));
        counter.increment().unwrap();
        intent.finalize(prepared).unwrap();
        let last = model.image().unwrap();
        assert_eq!(last.fence.minimum_record_sequence, 3);
        assert_eq!(last.fence.minimum_counter, 10);
        assert_eq!(last.counter, 10);
        assert_ne!(
            first.fence.last_record_digest,
            last.fence.last_record_digest
        );
        let committed = intent.load().unwrap();
        let StoredBinding::Committed(committed) = committed else {
            panic!("finalization failed");
        };
        assert_eq!(committed.policy.policy_sequence, 1);
        assert_eq!(committed.policy.policy_head, [66; 32]);
        assert_eq!(counter.increment(), Err(BindingError::PersistenceUncertain));

        let (raw, trusted) = model.read_sources().unwrap();
        let readonly = AuthenticatedReadOnlyIntent::new(before.identity, counter, raw, trusted);
        assert_eq!(readonly.load(), Ok(StoredBinding::Committed(committed)));
        assert_eq!(
            readonly.inspect_read().unwrap().diagnostic(),
            Diagnostic::MatchingCounterOnly
        );
    }

    #[test]
    fn all_six_crash_boundaries_preserve_a_checkable_state() {
        for cut in [
            WriteCrashPoint::PrepareBeforeCas,
            WriteCrashPoint::PrepareAfterCas,
            WriteCrashPoint::CounterBeforeWrite,
            WriteCrashPoint::CounterAfterWrite,
            WriteCrashPoint::FinalizeBeforeCas,
            WriteCrashPoint::FinalizeAfterCas,
        ] {
            let (model, before, prepared) = fixture();
            let (counter, intent) = model.handles().unwrap();
            model.fail_once(cut).unwrap();
            let result = match cut {
                WriteCrashPoint::PrepareBeforeCas | WriteCrashPoint::PrepareAfterCas => {
                    intent.prepare(before, prepared)
                }
                WriteCrashPoint::CounterBeforeWrite | WriteCrashPoint::CounterAfterWrite => {
                    intent.prepare(before, prepared).unwrap();
                    counter.increment()
                }
                WriteCrashPoint::FinalizeBeforeCas | WriteCrashPoint::FinalizeAfterCas => {
                    intent.prepare(before, prepared).unwrap();
                    counter.increment().unwrap();
                    intent.finalize(prepared)
                }
            };
            assert_eq!(result, Err(BindingError::PersistenceUncertain));
            assert_eq!(intent.load(), Err(BindingError::PersistenceUncertain));
            model.reboot().unwrap();
            let (counter, intent) = model.handles().unwrap();
            let image = model.image().unwrap();
            let expected_counter = if matches!(
                cut,
                WriteCrashPoint::CounterAfterWrite
                    | WriteCrashPoint::FinalizeBeforeCas
                    | WriteCrashPoint::FinalizeAfterCas
            ) {
                10
            } else {
                9
            };
            assert_eq!(image.counter, expected_counter);
            assert_eq!(counter.read(), Ok(expected_counter));
            let expected_sequence = match cut {
                WriteCrashPoint::PrepareBeforeCas => 1,
                WriteCrashPoint::FinalizeAfterCas => 3,
                _ => 2,
            };
            assert_eq!(image.fence.minimum_record_sequence, expected_sequence);
            let binding = intent.load().unwrap();
            match cut {
                WriteCrashPoint::PrepareBeforeCas => {
                    assert_eq!(binding, StoredBinding::Committed(before));
                }
                WriteCrashPoint::FinalizeAfterCas => {
                    assert!(matches!(binding, StoredBinding::Committed(_)));
                }
                _ => assert_eq!(binding, StoredBinding::Prepared(prepared)),
            }
        }
    }

    #[test]
    fn restoring_old_signed_frame_cannot_rollback_authentic_fence() {
        let (model, before, prepared) = fixture();
        let old = model.image().unwrap().signed_frame;
        let (counter, intent) = model.handles().unwrap();
        intent.prepare(before, prepared).unwrap();
        counter.increment().unwrap();
        intent.finalize(prepared).unwrap();
        model.restore_untrusted_frame_for_test(old).unwrap();
        let (_, intent) = model.handles().unwrap();
        assert_eq!(intent.load(), Err(BindingError::BrokenIntent));
        assert_eq!(model.image().unwrap().counter, 10);
        assert_eq!(model.image().unwrap().fence.minimum_record_sequence, 3);
    }

    #[test]
    fn rejected_signatures_and_malformed_transitions_do_not_change_fence() {
        struct RefusingSigner;
        impl CandidateExternalIntentSigner for RefusingSigner {
            fn sign(&self, _: &[u8]) -> Result<[u8; 64], BindingError> {
                Err(BindingError::PersistenceUncertain)
            }
        }
        let (_key, pin, before, frame, fence) = base();
        let model = AuthenticatedWriteSimulator::enrolled_for_test(
            frame,
            pin,
            fence,
            9,
            Arc::new(RefusingSigner),
        )
        .unwrap();
        let (_, intent) = model.handles().unwrap();
        let mut candidate = fixture().2;
        candidate.before = before;
        assert_eq!(
            intent.prepare(before, candidate),
            Err(BindingError::PersistenceUncertain)
        );
        assert_eq!(model.image().unwrap().fence, fence);
        let (model, before, mut candidate) = fixture();
        let (_, intent) = model.handles().unwrap();
        candidate.after_sequence = 0;
        assert_eq!(
            intent.prepare(before, candidate),
            Err(BindingError::BrokenIntent)
        );
        assert_eq!(model.image().unwrap().fence.minimum_record_sequence, 1);
    }

    struct PausingSigner {
        key: SigningKey,
        first: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl CandidateExternalIntentSigner for PausingSigner {
        fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], BindingError> {
            let notify = self
                .first
                .lock()
                .map_err(|_| BindingError::PersistenceUncertain)?
                .take();
            if let Some(notify) = notify {
                notify
                    .send(())
                    .map_err(|_| BindingError::PersistenceUncertain)?;
                self.release
                    .lock()
                    .map_err(|_| BindingError::PersistenceUncertain)?
                    .recv()
                    .map_err(|_| BindingError::PersistenceUncertain)?;
            }
            Ok(self.key.sign(bytes).to_bytes())
        }
    }

    #[test]
    fn competing_concurrent_prepare_cannot_publish_stale_signature() {
        let (key, pin, before, frame, fence) = base();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let model = AuthenticatedWriteSimulator::enrolled_for_test(
            frame,
            pin,
            fence,
            9,
            Arc::new(PausingSigner {
                key,
                first: Mutex::new(Some(entered_tx)),
                release: Mutex::new(release_rx),
            }),
        )
        .unwrap();
        let candidate = Prepared {
            before,
            after_sequence: 1,
            after_head: [66; 32],
            after_revocation_root: [77; 32],
            after_manifest: before.policy.current_manifest,
        };
        let (_, first) = model.handles().unwrap();
        let (_, second) = model.handles().unwrap();
        let pending = thread::spawn(move || first.prepare(before, candidate));
        entered_rx.recv().unwrap();
        second.prepare(before, candidate).unwrap();
        release_tx.send(()).unwrap();
        assert_eq!(
            pending.join().unwrap(),
            Err(BindingError::PersistenceUncertain)
        );
        let image = model.image().unwrap();
        assert_eq!(image.fence.minimum_record_sequence, 2);
        assert_eq!(
            model.handles().unwrap().1.load(),
            Ok(StoredBinding::Prepared(candidate))
        );
    }

    #[test]
    fn stale_handle_after_reboot_and_repeated_nv_increment_fail() {
        let (model, before, prepared) = fixture();
        let (counter, intent) = model.handles().unwrap();
        intent.prepare(before, prepared).unwrap();
        counter.increment().unwrap();
        assert_eq!(counter.increment(), Err(BindingError::CounterMismatch));
        model.reboot().unwrap();
        assert_eq!(counter.read(), Err(BindingError::PersistenceUncertain));
        assert_eq!(intent.load(), Err(BindingError::PersistenceUncertain));
        let (new_counter, new_intent) = model.handles().unwrap();
        assert_eq!(new_counter.read(), Ok(10));
        assert_eq!(new_intent.load(), Ok(StoredBinding::Prepared(prepared)));
    }
}
