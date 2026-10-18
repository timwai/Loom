//! L-001U authenticated, *read-only* candidate intent boundary.
//!
//! This gate does not authenticate or durably persist its external trust
//! provider; those are strictly out-of-band requirements. It never stages,
//! finalizes, increments a counter, or issues a ServiceOpen permit.
//! Caller must still verify replayed signed journal and witness receipts.

use crate::authenticated_intent_record::{
    ExternalReplayFence, ExternalSignerPin, RecordError, VerifiedIntentRecord, verify_signed_record,
};
use crate::tpm_counter_binding::{
    BindingError, CandidateIntentStore, CandidateMonotonicCounter, Committed,
    PinnedCounterIdentity, Prepared, StoredBinding,
};
use std::sync::Arc;

/// Untrusted raw media reader. These bytes may be corrupt, replayed, missing
/// or torn. Their content MUST NOT supply the verifier's signer pin or fence.
pub trait CandidateSignedIntentReader: Send + Sync {
    fn read_frame(&self) -> Result<Vec<u8>, BindingError>;
}

/// The implementing platform must independently authenticate its signer pin,
/// epoch and replay fence and bind the pair into a coherent observation.
/// In-memory/static/file-only implementations are NOT rollback resistant.
pub trait CandidateTrustedIntentReader: Send + Sync {
    fn read_trust(&self) -> Result<(ExternalSignerPin, ExternalReplayFence), BindingError>;
}

/// An I/O boundary that returns a `StoredBinding` ONLY after validating its
/// signature, independently supplied trust and the observed monotonic count.
/// Deliberately implements only `load`; *all* writes fail closed.
pub struct AuthenticatedReadOnlyIntent {
    expected_device: PinnedCounterIdentity,
    counter: Arc<dyn CandidateMonotonicCounter>,
    signed_media: Arc<dyn CandidateSignedIntentReader>,
    trusted: Arc<dyn CandidateTrustedIntentReader>,
}

impl AuthenticatedReadOnlyIntent {
    pub fn new(
        expected_device: PinnedCounterIdentity,
        counter: Arc<dyn CandidateMonotonicCounter>,
        signed_media: Arc<dyn CandidateSignedIntentReader>,
        trusted: Arc<dyn CandidateTrustedIntentReader>,
    ) -> Self {
        Self {
            expected_device,
            counter,
            signed_media,
            trusted,
        }
    }

    /// Two snapshots guard the straightforward mid-read torn input cases.
    /// A malicious source can still perform ABA replays; full atomicity,
    /// snapshot locks and physical anti-rollback are NOT claimed here.
    pub fn inspect_read(&self) -> Result<VerifiedIntentRecord, BindingError> {
        if self.counter.identity() != self.expected_device {
            return Err(BindingError::WrongCounterIdentity);
        }
        let trust1 = self.trusted.read_trust()?;
        if trust1.0.device != self.expected_device {
            return Err(BindingError::WrongCounterIdentity);
        }
        let frame1 = self.signed_media.read_frame()?;
        let count1 = self.counter.read()?;
        let verified =
            verify_signed_record(&frame1, &trust1.0, trust1.1, count1).map_err(record_error)?;

        // Re-observe *all* dependencies. A change is uncertain, not a new
        // enrollment, and must not be silently adopted for this read.
        let trust2 = self.trusted.read_trust()?;
        let frame2 = self.signed_media.read_frame()?;
        let count2 = self.counter.read()?;
        if trust1.0 != trust2.0
            || trust1.1 != trust2.1
            || frame1 != frame2
            || count1 != count2
            || self.counter.identity() != self.expected_device
        {
            return Err(BindingError::PersistenceUncertain);
        }
        Ok(verified)
    }
}

fn record_error(error: RecordError) -> BindingError {
    match error {
        RecordError::CounterMismatch => BindingError::CounterMismatch,
        RecordError::WrongDeviceOrScope | RecordError::UntrustedSigner => {
            BindingError::WrongCounterIdentity
        }
        RecordError::BadEncoding
        | RecordError::UnsupportedVersion
        | RecordError::InvalidState
        | RecordError::InvalidSignature
        | RecordError::ReplayOrFork => BindingError::BrokenIntent,
    }
}

impl CandidateIntentStore for AuthenticatedReadOnlyIntent {
    fn load(&self) -> Result<StoredBinding, BindingError> {
        Ok(self.inspect_read()?.record().binding)
    }

    fn prepare(&self, _expected: Committed, _next: Prepared) -> Result<(), BindingError> {
        Err(BindingError::PersistenceUncertain)
    }

    fn finalize(&self, _expected: Prepared) -> Result<(), BindingError> {
        Err(BindingError::PersistenceUncertain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated_intent_record::{
        IntentRecord, signed_record_digest, signing_preimage,
    };
    use crate::tpm_counter_binding::Diagnostic;
    use crate::unified_policy_anchor::UnifiedPolicyHighWater;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_types::{ResourceId, SpaceId};
    use std::sync::Mutex;

    struct SimCounter {
        device: PinnedCounterIdentity,
        value: Mutex<u64>,
    }

    impl CandidateMonotonicCounter for SimCounter {
        fn identity(&self) -> PinnedCounterIdentity {
            self.device
        }

        fn read(&self) -> Result<u64, BindingError> {
            Ok(*self.value.lock().unwrap())
        }

        fn increment(&self) -> Result<(), BindingError> {
            Err(BindingError::PersistenceUncertain)
        }
    }

    struct SimFrame {
        bytes: Mutex<Vec<u8>>,
        swap_after_first: Mutex<Option<Vec<u8>>>,
    }

    impl CandidateSignedIntentReader for SimFrame {
        fn read_frame(&self) -> Result<Vec<u8>, BindingError> {
            let mut bytes = self.bytes.lock().unwrap();
            let result = bytes.clone();
            if let Some(next) = self.swap_after_first.lock().unwrap().take() {
                *bytes = next;
            }
            Ok(result)
        }
    }

    struct SimTrust {
        current: Mutex<(ExternalSignerPin, ExternalReplayFence)>,
        swap_after_first: Mutex<Option<(ExternalSignerPin, ExternalReplayFence)>>,
    }

    impl CandidateTrustedIntentReader for SimTrust {
        fn read_trust(&self) -> Result<(ExternalSignerPin, ExternalReplayFence), BindingError> {
            let mut current = self.current.lock().unwrap();
            let result = *current;
            if let Some(next) = self.swap_after_first.lock().unwrap().take() {
                *current = next;
            }
            Ok(result)
        }
    }

    fn frame(key: &SigningKey, seq: u64, binding: StoredBinding) -> Vec<u8> {
        let record = IntentRecord {
            record_sequence: seq,
            signer_epoch: 2,
            signer_public_key: key.verifying_key().to_bytes(),
            binding,
        };
        let mut bytes = signing_preimage(&record).unwrap();
        let signature = key.sign(&bytes).to_bytes();
        bytes.extend_from_slice(&signature);
        bytes
    }

    struct Fixture {
        signer: SigningKey,
        bound: Committed,
        counter: Arc<SimCounter>,
        media: Arc<SimFrame>,
        trust: Arc<SimTrust>,
    }

    impl Fixture {
        fn new() -> Self {
            let signer = SigningKey::from_bytes(&[45; 32]);
            let device = PinnedCounterIdentity {
                device_binding: [41; 32],
                nv_index: 0x0180_0111,
            };
            let policy = UnifiedPolicyHighWater {
                space: SpaceId::from_bytes([1; 16]),
                resource: ResourceId::from_bytes([2; 16]),
                root_public_key: [30; 32],
                root_key_epoch: 7,
                genesis_manifest: [22; 32],
                current_manifest: [22; 32],
                writer_epoch: 1,
                policy_sequence: 0,
                policy_head: [0; 32],
                revocation_root: [0; 32],
            };
            let bound = Committed {
                identity: device,
                counter: 9,
                policy,
            };
            let signed = frame(&signer, 1, StoredBinding::Committed(bound));
            let pin = ExternalSignerPin {
                signer_public_key: signer.verifying_key().to_bytes(),
                signer_epoch: 2,
                device,
                space: policy.space,
                resource: policy.resource,
                root_public_key: policy.root_public_key,
                root_key_epoch: policy.root_key_epoch,
                genesis_manifest: policy.genesis_manifest,
                writer_epoch: policy.writer_epoch,
            };
            Self {
                signer,
                bound,
                counter: Arc::new(SimCounter {
                    device,
                    value: Mutex::new(9),
                }),
                media: Arc::new(SimFrame {
                    bytes: Mutex::new(signed.clone()),
                    swap_after_first: Mutex::new(None),
                }),
                trust: Arc::new(SimTrust {
                    current: Mutex::new((
                        pin,
                        ExternalReplayFence {
                            minimum_record_sequence: 1,
                            minimum_counter: 9,
                            last_record_digest: signed_record_digest(&signed),
                        },
                    )),
                    swap_after_first: Mutex::new(None),
                }),
            }
        }

        fn gate(&self) -> AuthenticatedReadOnlyIntent {
            AuthenticatedReadOnlyIntent::new(
                self.bound.identity,
                self.counter.clone(),
                self.media.clone(),
                self.trust.clone(),
            )
        }
    }

    #[test]
    fn only_verified_committed_is_exposed_and_write_methods_never_run() {
        let f = Fixture::new();
        let gate = f.gate();
        let verified = gate.inspect_read().unwrap();
        assert_eq!(verified.diagnostic(), Diagnostic::MatchingCounterOnly);
        assert_eq!(gate.load(), Ok(StoredBinding::Committed(f.bound)));
        let next = Prepared {
            before: f.bound,
            after_sequence: 1,
            after_head: [77; 32],
            after_revocation_root: [88; 32],
            after_manifest: f.bound.policy.current_manifest,
        };
        assert_eq!(
            gate.prepare(f.bound, next),
            Err(BindingError::PersistenceUncertain)
        );
        assert_eq!(gate.finalize(next), Err(BindingError::PersistenceUncertain));
        assert_eq!(*f.counter.value.lock().unwrap(), 9);
    }

    #[test]
    fn corrupt_or_old_signed_media_never_returns_committed_state() {
        let f = Fixture::new();
        f.media.bytes.lock().unwrap()[75] ^= 0x80;
        assert_eq!(f.gate().load(), Err(BindingError::BrokenIntent));
        // A restored signed predecessor is below the independently held
        // sequence floor, even when its original signature remains valid.
        let older = frame(&f.signer, 1, StoredBinding::Committed(f.bound));
        let new = frame(&f.signer, 2, StoredBinding::Committed(f.bound));
        {
            let mut trusted = f.trust.current.lock().unwrap();
            trusted.1.minimum_record_sequence = 2;
            trusted.1.last_record_digest = signed_record_digest(&new);
        }
        *f.media.bytes.lock().unwrap() = older;
        assert_eq!(f.gate().load(), Err(BindingError::BrokenIntent));
    }

    #[test]
    fn coherent_double_read_rejects_record_and_trust_switches() {
        let f = Fixture::new();
        let different = frame(&f.signer, 2, StoredBinding::Committed(f.bound));
        *f.media.swap_after_first.lock().unwrap() = Some(different);
        assert_eq!(f.gate().load(), Err(BindingError::PersistenceUncertain));

        let g = Fixture::new();
        let mut rotated = *g.trust.current.lock().unwrap();
        rotated.0.signer_epoch = 3;
        *g.trust.swap_after_first.lock().unwrap() = Some(rotated);
        assert_eq!(g.gate().load(), Err(BindingError::PersistenceUncertain));
    }

    #[test]
    fn signed_prepared_pre_and_post_increment_are_read_only() {
        let f = Fixture::new();
        let prepared = Prepared {
            before: f.bound,
            after_sequence: 1,
            after_head: [77; 32],
            after_revocation_root: [88; 32],
            after_manifest: f.bound.policy.current_manifest,
        };
        let signed = frame(&f.signer, 2, StoredBinding::Prepared(prepared));
        *f.media.bytes.lock().unwrap() = signed.clone();
        {
            let mut trusted = f.trust.current.lock().unwrap();
            trusted.1.minimum_record_sequence = 2;
            trusted.1.last_record_digest = signed_record_digest(&signed);
        }
        assert_eq!(
            f.gate().inspect_read().unwrap().diagnostic(),
            Diagnostic::IntentBeforeIncrement
        );
        *f.counter.value.lock().unwrap() = 10;
        assert_eq!(
            f.gate().inspect_read().unwrap().diagnostic(),
            Diagnostic::IncrementNeedsSignedRecheck
        );
        assert_eq!(f.gate().load(), Ok(StoredBinding::Prepared(prepared)));
        assert_eq!(
            f.gate().finalize(prepared),
            Err(BindingError::PersistenceUncertain)
        );
    }

    #[test]
    fn key_rotation_only_after_out_of_band_pin_change() {
        let f = Fixture::new();
        let replacement = SigningKey::from_bytes(&[49; 32]);
        let record = IntentRecord {
            record_sequence: 2,
            signer_epoch: 3,
            signer_public_key: replacement.verifying_key().to_bytes(),
            binding: StoredBinding::Committed(f.bound),
        };
        let mut newer = signing_preimage(&record).unwrap();
        let signature = replacement.sign(&newer).to_bytes();
        newer.extend_from_slice(&signature);
        *f.media.bytes.lock().unwrap() = newer.clone();
        assert_eq!(f.gate().load(), Err(BindingError::WrongCounterIdentity));
        {
            let mut trusted = f.trust.current.lock().unwrap();
            trusted.0.signer_epoch = 3;
            trusted.0.signer_public_key = replacement.verifying_key().to_bytes();
            trusted.1.minimum_record_sequence = 2;
            trusted.1.last_record_digest = signed_record_digest(&newer);
        }
        assert_eq!(f.gate().load(), Ok(StoredBinding::Committed(f.bound)));
    }

    #[test]
    fn wrong_observed_counter_device_or_trusted_floor_rejects() {
        let f = Fixture::new();
        *f.counter.value.lock().unwrap() = 11;
        assert_eq!(f.gate().load(), Err(BindingError::CounterMismatch));
        *f.counter.value.lock().unwrap() = 9;
        {
            let mut trusted = f.trust.current.lock().unwrap();
            trusted.0.device.nv_index ^= 1;
        }
        assert_eq!(f.gate().load(), Err(BindingError::WrongCounterIdentity));

        let g = Fixture::new();
        g.trust.current.lock().unwrap().1.minimum_counter = 10;
        assert_eq!(g.gate().load(), Err(BindingError::BrokenIntent));
    }
}
