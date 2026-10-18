//! L-001O candidate: TPM counter / signed unified policy binding.
//! ONLY in-memory tests implement these I/O traits. This is NOT TPM NV code.
//! TPM counters cannot atomically store Root, Owner, witness or policy hashes.
//! Every mismatch, omitted intent or ambiguous write fails closed. No permit.

use loom_crypto::space_trust::{VerifiedResourceTrust, verify_root_bound_witnesses};
use loom_crypto::witness_checkpoint::SignedCheckpoint;
use crate::unified_policy_anchor::{
    UnifiedAnchorError, UnifiedPolicyHighWater, checked_unified_promotion,
};

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
    pub after: UnifiedPolicyHighWater,
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
            if binding.identity != pin { return Err(BindingError::WrongCounterIdentity); }
            if binding.counter != observed { return Err(BindingError::CounterMismatch); }
            Ok(Diagnostic::MatchingCounterOnly)
        }
        StoredBinding::Prepared(intent) => {
            if intent.before.identity != pin {
                return Err(BindingError::WrongCounterIdentity);
            }
            let old = intent.before.policy;
            let new = intent.after;
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
            let incremented = intent.before.counter.checked_add(1)
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
    let next = checked_unified_promotion(
        genesis, current, checked.checkpoint(), old, time_ms,
    ).map_err(|_: UnifiedAnchorError| BindingError::InvalidPolicyTransition)?;
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
    prior.counter.checked_add(1).ok_or(BindingError::CounterOverflow)?;
    let after = witnessed_next(genesis, current, receipts, now_ms, prior.policy)?;
    let intent = Prepared { before: prior, after };
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
    if expected != intent.after {
        return Err(BindingError::InvalidWitnesses);
    }
    store.finalize(intent)?;
    Ok(Diagnostic::MatchingCounterOnly)
}
