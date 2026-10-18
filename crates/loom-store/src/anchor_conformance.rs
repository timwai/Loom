//! L-001M: behavioral conformance for a future independent policy anchor.
//! This cannot certify actual OS/hardware rollback resistance or attestation.
//! Run ONLY with a disposable provisioned resource. Never opens ServiceOpen.

use crate::unified_policy_anchor::{
    IndependentUnifiedPolicyAnchor, UnifiedAnchorError, UnifiedPolicyHighWater,
};
use loom_types::{ResourceId, SpaceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    BeforeCommit,
    CommitButUnknownAck,
    ReadUnavailable,
    None,
}

/// A test rig must only restore the APPLICATION/SQLite domain, not its
/// purported independent monotonic anchor. The physical backup/restore,
/// process crash, power cycle and trusted key enrollment must be proven
/// separately on real hardware; this synthetic hook is NOT such proof.
pub trait AnchorProbeRig {
    fn open(&self) -> Result<Box<dyn IndependentUnifiedPolicyAnchor>, UnifiedAnchorError>;
    fn restore_application_snapshot(&self) -> Result<(), UnifiedAnchorError>;
    fn inject_fault(&self, fault: Fault) -> Result<(), UnifiedAnchorError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Initial,
    ScopeIsolation,
    Advance,
    StaleCas,
    SnapshotRollback,
    EqualSequenceDivergence,
    FailedBeforeCommit,
    CommittedWithoutAck,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    Adapter(UnifiedAnchorError),
    Failed(Check),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    pub checks_passed: u8,
    /// A passing in-process probe can NEVER provide physical evidence.
    pub physically_certified: bool,
}

fn exact(
    rig: &dyn AnchorProbeRig,
    expected: UnifiedPolicyHighWater,
    at: Check,
) -> Result<(), ProbeError> {
    let current = rig.open().map_err(ProbeError::Adapter)?
        .read(expected.space, expected.resource)
        .map_err(ProbeError::Adapter)?;
    if current != expected {
        return Err(ProbeError::Failed(at));
    }
    Ok(())
}

fn next(
    previous: UnifiedPolicyHighWater,
    seq: u64,
    byte: u8,
) -> UnifiedPolicyHighWater {
    UnifiedPolicyHighWater {
        policy_sequence: seq,
        policy_head: [byte; 32],
        revocation_root: [byte.wrapping_add(1); 32],
        ..previous
    }
}

/// Requires a newly provisioned, disposable anchor equal to initial.
/// Performs destructive updates to that TEST anchor. No implicit reset,
/// production-usage permit, or claim of physical monotonicity is returned.
pub fn run_behavioral_probe(
    rig: &dyn AnchorProbeRig,
    initial: UnifiedPolicyHighWater,
) -> Result<ProbeReport, ProbeError> {
    exact(rig, initial, Check::Initial)?;
    let provider = rig.open().map_err(ProbeError::Adapter)?;
    let other = ResourceId::from_bytes([0xff; 16]);
    if other == initial.resource {
        return Err(ProbeError::Failed(Check::ScopeIsolation));
    }
    if let Ok(record) = provider.read(initial.space, other) {
        if record == initial {
            return Err(ProbeError::Failed(Check::ScopeIsolation));
        }
    }

    let one = next(initial, 1, 11);
    provider.compare_and_advance(initial, one).map_err(ProbeError::Adapter)?;
    exact(rig, one, Check::Advance)?;

    if provider.compare_and_advance(initial, next(initial, 2, 99)).is_ok() {
        return Err(ProbeError::Failed(Check::StaleCas));
    }
    exact(rig, one, Check::StaleCas)?;

    rig.restore_application_snapshot().map_err(ProbeError::Adapter)?;
    exact(rig, one, Check::SnapshotRollback)?;

    if provider.compare_and_advance(one, next(one, 1, 77)).is_ok() {
        return Err(ProbeError::Failed(Check::EqualSequenceDivergence));
    }
    exact(rig, one, Check::EqualSequenceDivergence)?;

    let two = next(one, 2, 22);
    rig.inject_fault(Fault::BeforeCommit).map_err(ProbeError::Adapter)?;
    if provider.compare_and_advance(one, two).is_ok() {
        return Err(ProbeError::Failed(Check::FailedBeforeCommit));
    }
    rig.inject_fault(Fault::None).map_err(ProbeError::Adapter)?;
    exact(rig, one, Check::FailedBeforeCommit)?;

    rig.inject_fault(Fault::CommitButUnknownAck).map_err(ProbeError::Adapter)?;
    if provider.compare_and_advance(one, two).is_ok() {
        return Err(ProbeError::Failed(Check::CommittedWithoutAck));
    }
    rig.inject_fault(Fault::None).map_err(ProbeError::Adapter)?;
    // Reopen: an ambiguous ACK must NOT erase the already committed value.
    exact(rig, two, Check::CommittedWithoutAck)?;

    rig.inject_fault(Fault::ReadUnavailable).map_err(ProbeError::Adapter)?;
    if rig.open().map_err(ProbeError::Adapter)?
        .read(initial.space, initial.resource).is_ok()
    {
        return Err(ProbeError::Failed(Check::Unavailable));
    }
    rig.inject_fault(Fault::None).map_err(ProbeError::Adapter)?;
    exact(rig, two, Check::Unavailable)?;

    Ok(ProbeReport { checks_passed: 9, physically_certified: false })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// In-memory fault simulation is deliberately NOT durable or secure.
    struct Rig {
        state: Arc<Mutex<UnifiedPolicyHighWater>>,
        snapshot: UnifiedPolicyHighWater,
        fault: Arc<Mutex<Fault>>,
        rolls_back_anchor: bool,
        allows_divergence: bool,
    }
    struct Adapter {
        state: Arc<Mutex<UnifiedPolicyHighWater>>,
        fault: Arc<Mutex<Fault>>,
        allows_divergence: bool,
    }
    impl IndependentUnifiedPolicyAnchor for Adapter {
        fn read(&self, space: SpaceId, resource: ResourceId)
            -> Result<UnifiedPolicyHighWater, UnifiedAnchorError>
        {
            if *self.fault.lock().unwrap() == Fault::ReadUnavailable {
                return Err(UnifiedAnchorError::MissingOrUntrusted);
            }
            let value = *self.state.lock().unwrap();
            if value.space != space || value.resource != resource {
                return Err(UnifiedAnchorError::IdentityOrManifestMismatch);
            }
            Ok(value)
        }
        fn compare_and_advance(
            &self,
            expected: UnifiedPolicyHighWater,
            proposal: UnifiedPolicyHighWater,
        ) -> Result<(), UnifiedAnchorError> {
            let mut value = self.state.lock().unwrap();
            if *value != expected { return Err(UnifiedAnchorError::ConcurrentUpdate); }
            if proposal.space != value.space
                || proposal.resource != value.resource
                || proposal.root_public_key != value.root_public_key
                || proposal.root_key_epoch != value.root_key_epoch
                || proposal.genesis_manifest != value.genesis_manifest
                || proposal.writer_epoch != value.writer_epoch
                || proposal.policy_sequence < value.policy_sequence
            {
                return Err(UnifiedAnchorError::StaleState);
            }
            if !self.allows_divergence && proposal.policy_sequence == value.policy_sequence
                && proposal != *value
            {
                return Err(UnifiedAnchorError::ConflictingHistory);
            }
            match *self.fault.lock().unwrap() {
                Fault::BeforeCommit => Err(UnifiedAnchorError::PersistenceUncertain),
                Fault::CommitButUnknownAck => {
                    *value = proposal;
                    Err(UnifiedAnchorError::PersistenceUncertain)
                }
                Fault::ReadUnavailable => Err(UnifiedAnchorError::MissingOrUntrusted),
                Fault::None => { *value = proposal; Ok(()) }
            }
        }
    }
    impl AnchorProbeRig for Rig {
        fn open(&self) -> Result<Box<dyn IndependentUnifiedPolicyAnchor>, UnifiedAnchorError> {
            Ok(Box::new(Adapter {
                state: Arc::clone(&self.state),
                fault: Arc::clone(&self.fault),
                allows_divergence: self.allows_divergence,
            }))
        }
        fn restore_application_snapshot(&self) -> Result<(), UnifiedAnchorError> {
            if self.rolls_back_anchor {
                *self.state.lock().unwrap() = self.snapshot;
            }
            Ok(())
        }
        fn inject_fault(&self, fault: Fault) -> Result<(), UnifiedAnchorError> {
            *self.fault.lock().unwrap() = fault;
            Ok(())
        }
    }
    fn fixture(rolls_back_anchor: bool, allows_divergence: bool)
        -> (Rig, UnifiedPolicyHighWater)
    {
        let initial = UnifiedPolicyHighWater {
            space: SpaceId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            root_public_key: [31; 32],
            root_key_epoch: 7,
            genesis_manifest: [41; 32],
            current_manifest: [41; 32],
            writer_epoch: 3,
            policy_sequence: 0,
            policy_head: [0; 32],
            revocation_root: [0; 32],
        };
        (Rig {
            state: Arc::new(Mutex::new(initial)),
            snapshot: initial,
            fault: Arc::new(Mutex::new(Fault::None)),
            rolls_back_anchor,
            allows_divergence,
        }, initial)
    }
    #[test]
    fn behavioral_model_passes_but_physical_certification_stays_false() {
        let (rig, initial) = fixture(false, false);
        assert_eq!(
            run_behavioral_probe(&rig, initial),
            Ok(ProbeReport { checks_passed: 9, physically_certified: false })
        );
        assert_eq!(rig.state.lock().unwrap().policy_sequence, 2);
    }
    #[test]
    fn restoring_backup_that_includes_anchor_is_detected() {
        let (rig, initial) = fixture(true, false);
        assert_eq!(
            run_behavioral_probe(&rig, initial),
            Err(ProbeError::Failed(Check::SnapshotRollback))
        );
    }
    #[test]
    fn same_sequence_competing_signed_head_is_detected() {
        let (rig, initial) = fixture(false, true);
        assert_eq!(
            run_behavioral_probe(&rig, initial),
            Err(ProbeError::Failed(Check::EqualSequenceDivergence))
        );
    }
    #[test]
    fn old_genesis_is_not_silently_reprovisioned() {
        let (rig, initial) = fixture(false, false);
        *rig.state.lock().unwrap() = UnifiedPolicyHighWater {
            policy_sequence: 9,
            ..initial
        };
        assert_eq!(
            run_behavioral_probe(&rig, initial),
            Err(ProbeError::Failed(Check::Initial))
        );
    }
}
