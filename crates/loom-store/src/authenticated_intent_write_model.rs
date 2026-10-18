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
    /// Signed key-epoch rotation before committing new trusted pin + fence.
    RotateBeforeCas,
    /// New signed record and trusted pin + fence are already published.
    RotateAfterCas,
}

/// An OUT-OF-BAND signer enrollment approval *fixture*. Construction of
/// this value is NOT a trusted authorization procedure. A real external
/// provider must independently authenticate the signer transition and
/// make its approval nonreplayable across resets, hosts and processes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulatedRotationApproval {
    pub expected_pin: ExternalSignerPin,
    pub expected_fence: ExternalReplayFence,
    pub successor_public_key: [u8; 32],
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

    /// Simulated rotation with an externally approved successor signer.
    /// A signer call is deliberately outside the model's exclusive CAS lock.
    /// Calling this is NEVER proof that a real platform enrolled the key.
    pub fn rotate_signer_for_test(
        &self,
        approval: SimulatedRotationApproval,
        successor: Arc<dyn CandidateExternalIntentSigner>,
    ) -> Result<(), BindingError> {
        let generation = self.lock()?.generation;
        WriteHandle {
            state: Arc::clone(&self.state),
            generation,
        }
        .rotate(approval, successor)
    }

    /// Simulate external TPM clear/replacement: a reset/older NV count must
    /// fail all signed-record reads and writes rather than auto-enroll.
    pub fn reset_counter_for_test(&self, reduced_counter: u64) -> Result<(), BindingError> {
        let mut state = self.lock()?;
        if reduced_counter >= state.counter {
            return Err(BindingError::CounterMismatch);
        }
        state.counter = reduced_counter;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(BindingError::PersistenceUncertain)?;
        state.halted = false;
        state.fault = None;
        Ok(())
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

    /// A proposed *external* signer epoch update. The caller-supplied
    /// approval is a test fixture, not self-authorizing or signed by Loom.
    /// Only a fully committed slot may rotate: a Prepared intent must first
    /// complete its signed witness reconciliation. No key controls its own
    /// enrollment or recovery from reset.
    fn rotate(
        &self,
        approval: SimulatedRotationApproval,
        successor: Arc<dyn CandidateExternalIntentSigner>,
    ) -> Result<(), BindingError> {
        let (snapshot, binding) = self.snapshot()?;
        let StoredBinding::Committed(_) = binding else {
            return Err(BindingError::PersistenceUncertain);
        };
        if snapshot.pin != approval.expected_pin
            || snapshot.fence != approval.expected_fence
            || approval.successor_public_key == snapshot.pin.signer_public_key
        {
            return Err(BindingError::PersistenceUncertain);
        }
        let next_epoch = snapshot
            .pin
            .signer_epoch
            .checked_add(1)
            .ok_or(BindingError::CounterOverflow)?;
        let next_sequence = snapshot
            .fence
            .minimum_record_sequence
            .checked_add(1)
            .ok_or(BindingError::CounterOverflow)?;
        let mut next_pin = snapshot.pin;
        next_pin.signer_epoch = next_epoch;
        next_pin.signer_public_key = approval.successor_public_key;
        let record = IntentRecord {
            record_sequence: next_sequence,
            signer_epoch: next_epoch,
            signer_public_key: next_pin.signer_public_key,
            binding,
        };
        let mut frame = signing_preimage(&record).map_err(|_| BindingError::BrokenIntent)?;
        // No mutex or SQLite transaction is held across signing. Signing may
        // race with a concurrent writer; the later snapshot CAS rejects it.
        let signature = successor.sign(&frame)?;
        frame.extend_from_slice(&signature);
        let next_fence = ExternalReplayFence {
            minimum_record_sequence: next_sequence,
            minimum_counter: snapshot.counter,
            last_record_digest: signed_record_digest(&frame),
        };
        let validated = verify_signed_record(&frame, &next_pin, next_fence, snapshot.counter)
            .map_err(|_| BindingError::BrokenIntent)?;
        if validated.record().binding != binding {
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
        state.inject(WriteCrashPoint::RotateBeforeCas)?;
        // One in-process atomic model update, *not* physically independent
        // durable pin/fence/intent atomicity.
        state.frame = frame;
        state.fence = next_fence;
        state.pin = next_pin;
        state.signer = successor;
        state.inject(WriteCrashPoint::RotateAfterCas)?;
        Ok(())
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
        // The signed intent must ALREADY be fenced before the irreversible
        // increment. A valid signed future record not anchored by the
        // independent replay fence must never authorize advancing NV.
        if verified.record().record_sequence != state.fence.minimum_record_sequence
            || verified.digest() != state.fence.last_record_digest
        {
            return Err(BindingError::BrokenIntent);
        }
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
                WriteCrashPoint::RotateBeforeCas | WriteCrashPoint::RotateAfterCas => {
                    unreachable!("rotation cuts are tested separately")
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

    #[test]
    fn signed_prepared_ahead_of_authenticated_fence_cannot_increment_nv() {
        let (key, pin, before, frame, fence) = base();
        let model = AuthenticatedWriteSimulator::enrolled_for_test(
            frame,
            pin,
            fence,
            9,
            Arc::new(TestSigner(SigningKey::from_bytes(&[51; 32]))),
        )
        .unwrap();
        let intent = Prepared {
            before,
            after_sequence: 1,
            after_head: [66; 32],
            after_revocation_root: [77; 32],
            after_manifest: before.policy.current_manifest,
        };
        let candidate = IntentRecord {
            record_sequence: 2,
            signer_epoch: pin.signer_epoch,
            signer_public_key: pin.signer_public_key,
            binding: StoredBinding::Prepared(intent),
        };
        let mut future = signing_preimage(&candidate).unwrap();
        let signature = key.sign(&future).to_bytes();
        future.extend_from_slice(&signature);
        model.restore_untrusted_frame_for_test(future).unwrap();
        let (counter, store) = model.handles().unwrap();
        assert_eq!(store.load(), Err(BindingError::BrokenIntent));
        assert_eq!(counter.increment(), Err(BindingError::BrokenIntent));
        assert_eq!(model.image().unwrap().counter, 9);
        assert_eq!(model.image().unwrap().fence, fence);
    }

    #[test]
    fn different_signing_key_cannot_publish_under_existing_pin() {
        struct WrongSigner(SigningKey);
        impl CandidateExternalIntentSigner for WrongSigner {
            fn sign(&self, input: &[u8]) -> Result<[u8; 64], BindingError> {
                Ok(self.0.sign(input).to_bytes())
            }
        }
        let (_key, pin, before, frame, fence) = base();
        let model = AuthenticatedWriteSimulator::enrolled_for_test(
            frame,
            pin,
            fence,
            9,
            Arc::new(WrongSigner(SigningKey::from_bytes(&[67; 32]))),
        )
        .unwrap();
        let prepared = Prepared {
            before,
            after_sequence: 1,
            after_head: [66; 32],
            after_revocation_root: [77; 32],
            after_manifest: before.policy.current_manifest,
        };
        let (_, intent) = model.handles().unwrap();
        assert_eq!(
            intent.prepare(before, prepared),
            Err(BindingError::BrokenIntent)
        );
        assert_eq!(model.image().unwrap().fence, fence);
        assert_eq!(intent.load(), Ok(StoredBinding::Committed(before)));
    }

    fn rotation_approval(model: &AuthenticatedWriteSimulator) -> SimulatedRotationApproval {
        let state = model.state.lock().unwrap();
        SimulatedRotationApproval {
            expected_pin: state.pin,
            expected_fence: state.fence,
            successor_public_key: SigningKey::from_bytes(&[65; 32])
                .verifying_key()
                .to_bytes(),
        }
    }

    fn successor() -> Arc<dyn CandidateExternalIntentSigner> {
        Arc::new(TestSigner(SigningKey::from_bytes(&[65; 32])))
    }

    #[test]
    fn independently_approved_rotation_advances_signed_epoch_and_fence() {
        let (model, original, prepared) = fixture();
        let before = model.image().unwrap();
        let approval = rotation_approval(&model);
        model.rotate_signer_for_test(approval, successor()).unwrap();
        let after = model.image().unwrap();
        assert_eq!(after.counter, before.counter);
        assert_eq!(after.fence.minimum_counter, 9);
        assert_eq!(after.fence.minimum_record_sequence, 2);
        assert_ne!(after.fence.last_record_digest, before.fence.last_record_digest);
        let (counter, store) = model.handles().unwrap();
        assert_eq!(store.load(), Ok(StoredBinding::Committed(original)));
        let (raw, trust) = model.read_sources().unwrap();
        let verifier = AuthenticatedReadOnlyIntent::new(original.identity, counter, raw, trust);
        assert_eq!(verifier.load(), Ok(StoredBinding::Committed(original)));
        let (pin, _) = {
            let h = model.read_sources().unwrap().1;
            h.read_trust().unwrap()
        };
        assert_eq!(pin.signer_epoch, 3);
        assert_eq!(pin.signer_public_key, approval.successor_public_key);
        // Normal signed transitions continue under the new independently
        // enrolled key. The canonical old signer has no write access.
        store.prepare(original, prepared).unwrap();
        assert_eq!(model.image().unwrap().fence.minimum_record_sequence, 3);
    }

    #[test]
    fn rotation_failures_cannot_publish_old_or_wrong_key() {
        let (model, original, _) = fixture();
        let approved = rotation_approval(&model);
        let wrong = Arc::new(TestSigner(SigningKey::from_bytes(&[89; 32])));
        assert_eq!(
            model.rotate_signer_for_test(approved, wrong),
            Err(BindingError::BrokenIntent)
        );
        assert_eq!(model.image().unwrap().fence, approved.expected_fence);
        let mut forged = approved;
        forged.expected_pin.device.device_binding[0] ^= 1;
        assert_eq!(
            model.rotate_signer_for_test(forged, successor()),
            Err(BindingError::PersistenceUncertain)
        );
        let mut self_signed = approved;
        self_signed.successor_public_key = approved.expected_pin.signer_public_key;
        assert_eq!(
            model.rotate_signer_for_test(self_signed, successor()),
            Err(BindingError::PersistenceUncertain)
        );
        model.rotate_signer_for_test(approved, successor()).unwrap();
        assert_eq!(
            model.rotate_signer_for_test(approved, successor()),
            Err(BindingError::PersistenceUncertain)
        );
        assert_eq!(
            model.handles().unwrap().1.load(),
            Ok(StoredBinding::Committed(original))
        );
    }

    #[test]
    fn rotation_is_refused_while_prepared_requires_signed_recovery() {
        let (model, before, prepared) = fixture();
        let (_, store) = model.handles().unwrap();
        store.prepare(before, prepared).unwrap();
        let approval = rotation_approval(&model);
        assert_eq!(
            model.rotate_signer_for_test(approval, successor()),
            Err(BindingError::PersistenceUncertain)
        );
        let after = model.image().unwrap();
        assert_eq!(after.counter, 9);
        assert_eq!(after.fence.minimum_record_sequence, 2);
        assert_eq!(store.load(), Ok(StoredBinding::Prepared(prepared)));
    }

    #[test]
    fn rotation_before_and_after_cas_power_loss_are_distinguishable() {
        for point in [
            WriteCrashPoint::RotateBeforeCas,
            WriteCrashPoint::RotateAfterCas,
        ] {
            let (model, old, _) = fixture();
            let approval = rotation_approval(&model);
            model.fail_once(point).unwrap();
            assert_eq!(
                model.rotate_signer_for_test(approval, successor()),
                Err(BindingError::PersistenceUncertain)
            );
            assert_eq!(
                model.handles().unwrap().1.load(),
                Err(BindingError::PersistenceUncertain)
            );
            model.reboot().unwrap();
            let frame = model.image().unwrap();
            let (_, store) = model.handles().unwrap();
            assert_eq!(store.load(), Ok(StoredBinding::Committed(old)));
            match point {
                WriteCrashPoint::RotateBeforeCas => {
                    assert_eq!(frame.fence.minimum_record_sequence, 1);
                    assert_eq!(
                        model.read_sources().unwrap().1.read_trust().unwrap().0.signer_epoch,
                        2
                    );
                }
                WriteCrashPoint::RotateAfterCas => {
                    assert_eq!(frame.fence.minimum_record_sequence, 2);
                    assert_eq!(
                        model.read_sources().unwrap().1.read_trust().unwrap().0.signer_epoch,
                        3
                    );
                }
                _ => unreachable!(),
            }
            assert_eq!(frame.counter, 9);
        }
    }

    #[test]
    fn old_signed_frame_and_reset_device_never_reenroll_rotated_key() {
        let (model, old, _) = fixture();
        let saved_frame = model.image().unwrap().signed_frame;
        model
            .rotate_signer_for_test(rotation_approval(&model), successor())
            .unwrap();
        model.restore_untrusted_frame_for_test(saved_frame).unwrap();
        assert_eq!(
            model.handles().unwrap().1.load(),
            Err(BindingError::BrokenIntent)
        );

        let (model, old, next) = fixture();
        let (counter, store) = model.handles().unwrap();
        store.prepare(old, next).unwrap();
        counter.increment().unwrap();
        let fence = model.image().unwrap().fence;
        model.reset_counter_for_test(8).unwrap();
        assert_eq!(counter.read(), Err(BindingError::PersistenceUncertain));
        let (rebooted_counter, rebooted_store) = model.handles().unwrap();
        assert_eq!(rebooted_store.load(), Err(BindingError::BrokenIntent));
        assert_eq!(rebooted_counter.increment(), Err(BindingError::BrokenIntent));
        assert_eq!(model.image().unwrap().counter, 8);
        assert_eq!(model.image().unwrap().fence, fence);
    }

    #[test]
    fn concurrent_old_signing_must_not_block_rotation_or_publish_stale_record() {
        let (key, pin, original, signed, fence) = base();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let model = AuthenticatedWriteSimulator::enrolled_for_test(
            signed,
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
        let requested = Prepared {
            before: original,
            after_sequence: 1,
            after_head: [66; 32],
            after_revocation_root: [77; 32],
            after_manifest: original.policy.current_manifest,
        };
        let (_, handle) = model.handles().unwrap();
        let pending = thread::spawn(move || handle.prepare(original, requested));
        entered_rx.recv().unwrap();
        // Signing is suspended outside the model CAS lock. Rotation can win.
        model
            .rotate_signer_for_test(rotation_approval(&model), successor())
            .unwrap();
        release_tx.send(()).unwrap();
        assert_eq!(
            pending.join().unwrap(),
            Err(BindingError::PersistenceUncertain)
        );
        let (counter, current) = model.handles().unwrap();
        assert_eq!(counter.read(), Ok(9));
        assert_eq!(current.load(), Ok(StoredBinding::Committed(original)));
        assert_eq!(model.image().unwrap().fence.minimum_record_sequence, 2);
        current.prepare(original, requested).unwrap();
        assert_eq!(model.image().unwrap().fence.minimum_record_sequence, 3);
    }

    #[test]
    fn record_sequence_and_signer_epoch_overflow_refuse_rotation() {
        let (key, mut pin, original, _, _) = base();
        pin.signer_epoch = u64::MAX;
        let record = IntentRecord {
            record_sequence: 1,
            signer_epoch: pin.signer_epoch,
            signer_public_key: pin.signer_public_key,
            binding: StoredBinding::Committed(original),
        };
        let mut frame = signing_preimage(&record).unwrap();
        let sig = key.sign(&frame).to_bytes();
        frame.extend_from_slice(&sig);
        let fence = ExternalReplayFence {
            minimum_record_sequence: 1,
            minimum_counter: 9,
            last_record_digest: signed_record_digest(&frame),
        };
        let model = AuthenticatedWriteSimulator::enrolled_for_test(
            frame,
            pin,
            fence,
            9,
            Arc::new(TestSigner(key)),
        )
        .unwrap();
        assert_eq!(
            model.rotate_signer_for_test(rotation_approval(&model), successor()),
            Err(BindingError::CounterOverflow)
        );
        assert_eq!(model.image().unwrap().fence, fence);
    }

}
