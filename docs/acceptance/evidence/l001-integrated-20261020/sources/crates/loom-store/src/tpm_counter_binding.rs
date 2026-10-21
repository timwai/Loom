//! L-001O candidate: TPM counter / signed unified policy binding.
//! ONLY in-memory tests implement these I/O traits. This is NOT TPM NV code.
//! TPM counters cannot atomically store Root, Owner, witness or policy hashes.
//! Every mismatch, omitted intent or ambiguous write fails closed. No permit.

use crate::unified_policy_anchor::{
    UnifiedAnchorError, UnifiedPolicyHighWater, checked_unified_promotion,
};
use loom_crypto::space_trust::{VerifiedResourceTrust, verify_root_bound_witnesses};
use loom_crypto::witness_checkpoint::SignedCheckpoint;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedCounterIdentity {
    /// Enrolled out-of-band. An untrusted sysfs device name is not a pin.
    pub device_binding: [u8; 32],
    pub nv_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Committed {
    pub identity: PinnedCounterIdentity,
    pub counter: u64,
    pub policy: UnifiedPolicyHighWater,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prepared {
    pub before: Committed,
    /// Only those values allowed to advance under the same Root and Writer.
    /// The unchanged identity, genesis, and writer are inherited from before.
    pub after_sequence: u64,
    pub after_head: [u8; 32],
    pub after_revocation_root: [u8; 32],
    pub after_manifest: [u8; 32],
}

impl Prepared {
    fn new(before: Committed, next: UnifiedPolicyHighWater) -> Self {
        Self {
            before,
            after_sequence: next.policy_sequence,
            after_head: next.policy_head,
            after_revocation_root: next.revocation_root,
            after_manifest: next.current_manifest,
        }
    }

    fn after_policy(&self) -> UnifiedPolicyHighWater {
        UnifiedPolicyHighWater {
            policy_sequence: self.after_sequence,
            policy_head: self.after_head,
            revocation_root: self.after_revocation_root,
            current_manifest: self.after_manifest,
            ..self.before.policy
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredBinding {
    Missing,
    Committed(Committed),
    Prepared(Prepared),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Diagnostic {
    MatchingCounterOnly,
    IntentBeforeIncrement,
    IncrementNeedsSignedRecheck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    CounterUnavailable,
    JournalUnavailable,
    MissingBinding,
    WrongCounterIdentity,
    CounterMismatch,
    CounterOverflow,
    BrokenIntent,
    InvalidWitnesses,
    InvalidPolicyTransition,
    PersistenceUncertain,
}

pub trait CandidateMonotonicCounter: Send + Sync {
    fn identity(&self) -> PinnedCounterIdentity;
    fn read(&self) -> Result<u64, BindingError>;
    /// An error does NOT imply that the irreversible +1 did not occur.
    fn increment(&self) -> Result<(), BindingError>;
}

pub trait CandidateIntentStore: Send + Sync {
    fn load(&self) -> Result<StoredBinding, BindingError>;
    /// A production implementation would need durable fsync and writer
    /// serialization before increment is allowed. NOT provided here.
    fn prepare(&self, expected: Committed, next: Prepared) -> Result<(), BindingError>;
    fn finalize(&self, expected: Prepared) -> Result<(), BindingError>;
}

/// Exact external counter / local intent comparison, never authorization.
/// An older SQLite backup with a lower counter will be rejected.
pub fn inspect_counter(
    pin: PinnedCounterIdentity,
    observed: u64,
    saved: StoredBinding,
) -> Result<Diagnostic, BindingError> {
    match saved {
        StoredBinding::Missing => Err(BindingError::MissingBinding),
        StoredBinding::Committed(binding) => {
            if binding.identity != pin {
                return Err(BindingError::WrongCounterIdentity);
            }
            if binding.counter != observed {
                return Err(BindingError::CounterMismatch);
            }
            Ok(Diagnostic::MatchingCounterOnly)
        }
        StoredBinding::Prepared(intent) => {
            if intent.before.identity != pin {
                return Err(BindingError::WrongCounterIdentity);
            }
            let old = intent.before.policy;
            let new = intent.after_policy();
            if new.space != old.space
                || new.resource != old.resource
                || new.root_public_key != old.root_public_key
                || new.root_key_epoch != old.root_key_epoch
                || new.genesis_manifest != old.genesis_manifest
                || new.writer_epoch != old.writer_epoch
                || new.policy_sequence <= old.policy_sequence
            {
                return Err(BindingError::BrokenIntent);
            }
            let incremented = intent
                .before
                .counter
                .checked_add(1)
                .ok_or(BindingError::CounterOverflow)?;
            if observed == intent.before.counter {
                Ok(Diagnostic::IntentBeforeIncrement)
            } else if observed == incremented {
                Ok(Diagnostic::IncrementNeedsSignedRecheck)
            } else {
                Err(BindingError::CounterMismatch)
            }
        }
    }
}

/// Verifies both Root-selected witness signatures and full policy/revocation
/// commitments. The caller is STILL required to separately replay SQLite
/// signed history and check that it exactly matches this checkpoint.
fn witnessed_next(
    genesis: &VerifiedResourceTrust,
    current: &VerifiedResourceTrust,
    receipts: &[SignedCheckpoint],
    time_ms: u64,
    old: UnifiedPolicyHighWater,
) -> Result<UnifiedPolicyHighWater, BindingError> {
    let checked = verify_root_bound_witnesses(genesis, receipts, time_ms)
        .map_err(|_| BindingError::InvalidWitnesses)?;
    let next = checked_unified_promotion(genesis, current, checked.checkpoint(), old, time_ms)
        .map_err(|_: UnifiedAnchorError| BindingError::InvalidPolicyTransition)?;
    if next.policy_sequence <= old.policy_sequence {
        return Err(BindingError::InvalidPolicyTransition);
    }
    Ok(next)
}

/// Stages the intent before the irreversible increment. Never imports
/// a new anchor from a missing or restored SQLite database.
pub fn begin_candidate_advance(
    counter: &dyn CandidateMonotonicCounter,
    store: &dyn CandidateIntentStore,
    pin: PinnedCounterIdentity,
    genesis: &VerifiedResourceTrust,
    current: &VerifiedResourceTrust,
    receipts: &[SignedCheckpoint],
    now_ms: u64,
) -> Result<Diagnostic, BindingError> {
    if counter.identity() != pin {
        return Err(BindingError::WrongCounterIdentity);
    }
    let observed = counter.read()?;
    let prior = match store.load()? {
        StoredBinding::Committed(old) => {
            inspect_counter(pin, observed, StoredBinding::Committed(old))?;
            old
        }
        StoredBinding::Missing => return Err(BindingError::MissingBinding),
        StoredBinding::Prepared(_) => return Err(BindingError::PersistenceUncertain),
    };
    // Overflow must reject before writing a staged intent or touching TPM.
    prior
        .counter
        .checked_add(1)
        .ok_or(BindingError::CounterOverflow)?;
    let after = witnessed_next(genesis, current, receipts, now_ms, prior.policy)?;
    let intent = Prepared::new(prior, after);
    store.prepare(prior, intent)?;
    // Every error after this point leaves a state that needs inspection.
    counter.increment()?;
    if inspect_counter(pin, counter.read()?, StoredBinding::Prepared(intent))?
        != Diagnostic::IncrementNeedsSignedRecheck
    {
        return Err(BindingError::CounterMismatch);
    }
    store.finalize(intent)?;
    Ok(Diagnostic::MatchingCounterOnly)
}

/// On restart, re-check the TPM and the SAME signed witness evidence.
/// Never auto-increment a Prepared intent, never accept changed hashes.
pub fn reconcile_candidate_advance(
    counter: &dyn CandidateMonotonicCounter,
    store: &dyn CandidateIntentStore,
    pin: PinnedCounterIdentity,
    genesis: &VerifiedResourceTrust,
    current: &VerifiedResourceTrust,
    receipts: &[SignedCheckpoint],
    now_ms: u64,
) -> Result<Diagnostic, BindingError> {
    if counter.identity() != pin {
        return Err(BindingError::WrongCounterIdentity);
    }
    let slot = store.load()?;
    let state = inspect_counter(pin, counter.read()?, slot)?;
    if state != Diagnostic::IncrementNeedsSignedRecheck {
        return Ok(state);
    }
    let StoredBinding::Prepared(intent) = slot else {
        return Err(BindingError::BrokenIntent);
    };
    let expected = witnessed_next(genesis, current, receipts, now_ms, intent.before.policy)?;
    if expected != intent.after_policy() {
        return Err(BindingError::InvalidWitnesses);
    }
    store.finalize(intent)?;
    Ok(Diagnostic::MatchingCounterOnly)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_crypto::space_trust::{
        ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
        trust_manifest_transcript, verify_resource_trust_for_spike,
    };
    use loom_crypto::witness_checkpoint::{
        Checkpoint, TrustedWitnessForSpike, checkpoint_transcript,
    };
    use loom_types::{ResourceId, SpaceId};
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        None,
        StageFails,
        CounterErrorBefore,
        CounterErrorAfter,
        FinalizeFails,
    }
    struct Counter {
        identity: PinnedCounterIdentity,
        value: Mutex<u64>,
        fault: Mutex<Fault>,
    }
    impl CandidateMonotonicCounter for Counter {
        fn identity(&self) -> PinnedCounterIdentity {
            self.identity
        }
        fn read(&self) -> Result<u64, BindingError> {
            Ok(*self.value.lock().unwrap())
        }
        fn increment(&self) -> Result<(), BindingError> {
            let fault = *self.fault.lock().unwrap();
            if fault == Fault::CounterErrorBefore {
                return Err(BindingError::PersistenceUncertain);
            }
            let mut value = self.value.lock().unwrap();
            *value = value.checked_add(1).ok_or(BindingError::CounterOverflow)?;
            if fault == Fault::CounterErrorAfter {
                return Err(BindingError::PersistenceUncertain);
            }
            Ok(())
        }
    }
    struct Journal {
        state: Mutex<StoredBinding>,
        fault: Mutex<Fault>,
    }
    impl CandidateIntentStore for Journal {
        fn load(&self) -> Result<StoredBinding, BindingError> {
            Ok(*self.state.lock().unwrap())
        }
        fn prepare(&self, prior: Committed, staged: Prepared) -> Result<(), BindingError> {
            if *self.fault.lock().unwrap() == Fault::StageFails {
                return Err(BindingError::PersistenceUncertain);
            }
            let mut slot = self.state.lock().unwrap();
            if *slot != StoredBinding::Committed(prior) {
                return Err(BindingError::PersistenceUncertain);
            }
            *slot = StoredBinding::Prepared(staged);
            Ok(())
        }
        fn finalize(&self, prepared: Prepared) -> Result<(), BindingError> {
            if *self.fault.lock().unwrap() == Fault::FinalizeFails {
                return Err(BindingError::PersistenceUncertain);
            }
            let mut slot = self.state.lock().unwrap();
            if *slot != StoredBinding::Prepared(prepared) {
                return Err(BindingError::PersistenceUncertain);
            }
            *slot = StoredBinding::Committed(Committed {
                identity: prepared.before.identity,
                counter: prepared
                    .before
                    .counter
                    .checked_add(1)
                    .ok_or(BindingError::CounterOverflow)?,
                policy: prepared.after_policy(),
            });
            Ok(())
        }
    }
    fn fixture() -> (
        Counter,
        Journal,
        PinnedCounterIdentity,
        VerifiedResourceTrust,
        [SignedCheckpoint; 2],
    ) {
        let root = SigningKey::from_bytes(&[30; 32]);
        let owner = SigningKey::from_bytes(&[11; 32]);
        let witness_a = SigningKey::from_bytes(&[21; 32]);
        let witness_b = SigningKey::from_bytes(&[22; 32]);
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
                witness_a.verifying_key().to_bytes(),
                witness_b.verifying_key().to_bytes(),
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
        let checkpoint = Checkpoint {
            space: trust.space(),
            resource: trust.resource(),
            writer_epoch: trust.writer_epoch(),
            seq: 1,
            head_hash: [77; 32],
            revocation_root: [88; 32],
            issued_at_ms: 120,
            expires_at_ms: 250,
        };
        let transcript = checkpoint_transcript(&checkpoint);
        let receipts = [witness_a, witness_b].map(|key| SignedCheckpoint {
            witness_key_id: TrustedWitnessForSpike::from_public_key(key.verifying_key().to_bytes())
                .key_id,
            checkpoint,
            signature: key.sign(&transcript).to_bytes(),
        });
        let nv = PinnedCounterIdentity {
            device_binding: [3; 32],
            nv_index: 0x0180_0111,
        };
        let committed = Committed {
            identity: nv,
            counter: 17,
            policy: UnifiedPolicyHighWater::initial(&trust),
        };
        let counter = Counter {
            identity: nv,
            value: Mutex::new(17),
            fault: Mutex::new(Fault::None),
        };
        let journal = Journal {
            state: Mutex::new(StoredBinding::Committed(committed)),
            fault: Mutex::new(Fault::None),
        };
        (counter, journal, nv, trust, receipts)
    }
    fn begin(
        device: &Counter,
        journal: &Journal,
        pin: PinnedCounterIdentity,
        trust: &VerifiedResourceTrust,
        receipts: &[SignedCheckpoint],
    ) -> Result<Diagnostic, BindingError> {
        begin_candidate_advance(device, journal, pin, trust, trust, receipts, 150)
    }
    fn reconcile(
        device: &Counter,
        journal: &Journal,
        pin: PinnedCounterIdentity,
        trust: &VerifiedResourceTrust,
        receipts: &[SignedCheckpoint],
    ) -> Result<Diagnostic, BindingError> {
        reconcile_candidate_advance(device, journal, pin, trust, trust, receipts, 150)
    }

    #[test]
    fn signed_advance_binds_both_policy_roots_and_stays_diagnostic_only() {
        let (device, journal, pin, trust, receipts) = fixture();
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Ok(Diagnostic::MatchingCounterOnly)
        );
        assert_eq!(*device.value.lock().unwrap(), 18);
        let StoredBinding::Committed(committed) = journal.load().unwrap() else {
            panic!("not committed")
        };
        assert_eq!(committed.counter, 18);
        assert_eq!(committed.policy.policy_head, [77; 32]);
        assert_eq!(committed.policy.revocation_root, [88; 32]);
        assert_eq!(
            reconcile(&device, &journal, pin, &trust, &receipts),
            Ok(Diagnostic::MatchingCounterOnly)
        );
    }

    #[test]
    fn failing_intent_stage_does_not_increment_counter() {
        let (device, journal, pin, trust, receipts) = fixture();
        *journal.fault.lock().unwrap() = Fault::StageFails;
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::PersistenceUncertain)
        );
        assert_eq!(*device.value.lock().unwrap(), 17);
        assert!(matches!(
            journal.load().unwrap(),
            StoredBinding::Committed(_)
        ));
    }

    #[test]
    fn error_before_nv_increment_keeps_prepared_state_not_ready() {
        let (device, journal, pin, trust, receipts) = fixture();
        *device.fault.lock().unwrap() = Fault::CounterErrorBefore;
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::PersistenceUncertain)
        );
        assert_eq!(
            reconcile(&device, &journal, pin, &trust, &receipts),
            Ok(Diagnostic::IntentBeforeIncrement)
        );
        assert_eq!(*device.value.lock().unwrap(), 17);
    }

    #[test]
    fn lost_ack_after_nv_increment_recovers_only_with_original_witnesses() {
        let (device, journal, pin, trust, receipts) = fixture();
        *device.fault.lock().unwrap() = Fault::CounterErrorAfter;
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::PersistenceUncertain)
        );
        assert_eq!(*device.value.lock().unwrap(), 18);
        assert_eq!(
            reconcile(&device, &journal, pin, &trust, &receipts),
            Ok(Diagnostic::MatchingCounterOnly)
        );
        let StoredBinding::Committed(bound) = journal.load().unwrap() else {
            panic!("recovery did not commit")
        };
        assert_eq!(bound.counter, 18);
    }

    #[test]
    fn finalize_failure_requires_rechecking_valid_root_witness_signatures() {
        let (device, journal, pin, trust, mut receipts) = fixture();
        *journal.fault.lock().unwrap() = Fault::FinalizeFails;
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::PersistenceUncertain)
        );
        *journal.fault.lock().unwrap() = Fault::None;
        receipts[0].signature[3] ^= 1;
        assert_eq!(
            reconcile(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::InvalidWitnesses)
        );
        assert!(matches!(
            journal.load().unwrap(),
            StoredBinding::Prepared(_)
        ));
        receipts[0].signature[3] ^= 1;
        assert_eq!(
            reconcile(&device, &journal, pin, &trust, &receipts),
            Ok(Diagnostic::MatchingCounterOnly)
        );
    }

    #[test]
    fn old_app_backup_cannot_overwrite_newer_tpm_counter() {
        let (device, journal, pin, trust, receipts) = fixture();
        let older_backup = journal.load().unwrap();
        begin(&device, &journal, pin, &trust, &receipts).unwrap();
        *journal.state.lock().unwrap() = older_backup;
        assert_eq!(
            reconcile(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::CounterMismatch)
        );
    }

    #[test]
    fn cleared_tpm_and_external_increment_race_fail_closed() {
        let (device, journal, pin, trust, receipts) = fixture();
        *device.fault.lock().unwrap() = Fault::CounterErrorAfter;
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::PersistenceUncertain)
        );
        *device.value.lock().unwrap() = 19;
        assert_eq!(
            reconcile(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::CounterMismatch)
        );
        *device.value.lock().unwrap() = 0;
        assert_eq!(
            reconcile(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::CounterMismatch)
        );
    }

    #[test]
    fn forged_witnesses_wrong_tpm_pin_missing_binding_and_stale_seq_reject() {
        let (device, journal, mut pin, trust, mut receipts) = fixture();
        pin.device_binding = [0; 32];
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::WrongCounterIdentity)
        );
        pin.device_binding = [3; 32];
        receipts[0].signature[0] ^= 1;
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::InvalidWitnesses)
        );
        receipts[0].signature[0] ^= 1;
        *journal.state.lock().unwrap() = StoredBinding::Missing;
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::MissingBinding)
        );
        let (device, journal, pin, trust, receipts) = fixture();
        begin(&device, &journal, pin, &trust, &receipts).unwrap();
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::InvalidPolicyTransition)
        );
    }

    #[test]
    fn counter_overflow_rejects_without_staged_intent() {
        let (device, journal, pin, trust, receipts) = fixture();
        *device.value.lock().unwrap() = u64::MAX;
        {
            let mut guard = journal.state.lock().unwrap();
            let StoredBinding::Committed(ref mut old) = *guard else {
                panic!("not an initial binding")
            };
            old.counter = u64::MAX;
        }
        assert_eq!(
            begin(&device, &journal, pin, &trust, &receipts),
            Err(BindingError::CounterOverflow)
        );
        assert!(matches!(
            journal.load().unwrap(),
            StoredBinding::Committed(_)
        ));
    }
}
