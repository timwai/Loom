//! L-001T canonical, signed *candidate* Prepared-intent record framing.
//!
//! This module verifies externally pinned Ed25519 signers and monotonic
//! rollback fences, but cannot supply those external trusted dependencies.
//! NO durable I/O, signing-key enrollment, TPM NV writes or access permits.
//! The signature authenticates the bytes, NOT global freshness or safety.

use crate::tpm_counter_binding::{
    BindingError, Committed, Diagnostic, PinnedCounterIdentity, Prepared, StoredBinding,
    inspect_counter,
};
use crate::unified_policy_anchor::UnifiedPolicyHighWater;
use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::{ResourceId, SpaceId};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"LOOMINT1";
const DIGEST_DOMAIN: &[u8] = b"LOOM:INTENT-RECORD-DIGEST:V1\0";
const VERSION: u16 = 1;
const COMMITTED_TAG: u8 = 1;
const PREPARED_TAG: u8 = 2;
const HEADER_LEN: usize = 8 + 2 + 1 + 1 + 8 + 8 + 32;
const POLICY_LEN: usize = 16 + 16 + 32 + 8 + 32 + 32 + 8 + 8 + 32 + 32;
const COMMITTED_LEN: usize = 32 + 4 + 8 + POLICY_LEN;
const PREPARED_LEN: usize = COMMITTED_LEN + 8 + 32 + 32 + 32;
const SIG_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    BadEncoding,
    UnsupportedVersion,
    InvalidState,
    UntrustedSigner,
    InvalidSignature,
    WrongDeviceOrScope,
    ReplayOrFork,
    CounterMismatch,
}

/// The signer pin MUST be acquired from independent authenticated enrollment,
/// never from this record, backed-up SQLite or an untrusted network peer.
#[derive(Clone, Copy, Debug)]
pub struct ExternalSignerPin {
    pub signer_public_key: [u8; 32],
    pub signer_epoch: u64,
    pub device: PinnedCounterIdentity,
    pub space: SpaceId,
    pub resource: ResourceId,
    pub root_public_key: [u8; 32],
    pub root_key_epoch: u64,
    pub genesis_manifest: [u8; 32],
    pub writer_epoch: u64,
}

/// Trusted independently stored low-water fence. It is NOT safe to recover
/// these fields from the potentially rolled-back intent record itself.
/// The digest locks equal-sequence records to a *specific* signed image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalReplayFence {
    pub minimum_record_sequence: u64,
    pub minimum_counter: u64,
    /// [0;32] is only valid with minimum_record_sequence = 0.
    pub last_record_digest: [u8; 32],
}

/// Unsigned record submitted to an externally authorized signing service.
/// The API deliberately does NOT own or generate a private signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentRecord {
    pub record_sequence: u64,
    pub signer_epoch: u64,
    pub signer_public_key: [u8; 32],
    pub binding: StoredBinding,
}

/// Only this module can create a signed, scoped, replay-checked result.
/// The result is diagnostic and MUST NEVER be treated as ServiceOpen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedIntentRecord {
    record: IntentRecord,
    record_digest: [u8; 32],
    diagnostic: Diagnostic,
}

impl VerifiedIntentRecord {
    pub fn record(&self) -> IntentRecord {
        self.record
    }

    pub fn digest(&self) -> [u8; 32] {
        self.record_digest
    }

    pub fn diagnostic(&self) -> Diagnostic {
        self.diagnostic
    }
}

fn encode_high_water(out: &mut Vec<u8>, p: UnifiedPolicyHighWater) {
    out.extend_from_slice(p.space.as_bytes());
    out.extend_from_slice(p.resource.as_bytes());
    out.extend_from_slice(&p.root_public_key);
    out.extend_from_slice(&p.root_key_epoch.to_be_bytes());
    out.extend_from_slice(&p.genesis_manifest);
    out.extend_from_slice(&p.current_manifest);
    out.extend_from_slice(&p.writer_epoch.to_be_bytes());
    out.extend_from_slice(&p.policy_sequence.to_be_bytes());
    out.extend_from_slice(&p.policy_head);
    out.extend_from_slice(&p.revocation_root);
}

fn encode_committed(out: &mut Vec<u8>, c: Committed) {
    out.extend_from_slice(&c.identity.device_binding);
    out.extend_from_slice(&c.identity.nv_index.to_be_bytes());
    out.extend_from_slice(&c.counter.to_be_bytes());
    encode_high_water(out, c.policy);
}

/// Fixed-size, big-endian, no-padding signing bytes. The 8-byte magic and
/// 16-bit version are inside the signature transcript, so they also provide
/// protocol/domain separation. Signed frames append exactly 64 signature bytes.
pub fn signing_preimage(record: &IntentRecord) -> Result<Vec<u8>, RecordError> {
    let tag = match record.binding {
        StoredBinding::Missing => return Err(RecordError::InvalidState),
        StoredBinding::Committed(_) => COMMITTED_TAG,
        StoredBinding::Prepared(_) => PREPARED_TAG,
    };
    if record.record_sequence == 0 || record.signer_epoch == 0 {
        return Err(RecordError::InvalidState);
    }
    let mut out = Vec::with_capacity(
        HEADER_LEN
            + if tag == COMMITTED_TAG {
                COMMITTED_LEN
            } else {
                PREPARED_LEN
            },
    );
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(tag);
    out.push(0); // Must remain zero; signed reserved byte.
    out.extend_from_slice(&record.record_sequence.to_be_bytes());
    out.extend_from_slice(&record.signer_epoch.to_be_bytes());
    out.extend_from_slice(&record.signer_public_key);
    match record.binding {
        StoredBinding::Committed(c) => encode_committed(&mut out, c),
        StoredBinding::Prepared(p) => {
            // Reject malformed Prepared transitions even before signing.
            inspect_counter(p.before.identity, p.before.counter, record.binding)
                .map_err(|_| RecordError::InvalidState)?;
            encode_committed(&mut out, p.before);
            out.extend_from_slice(&p.after_sequence.to_be_bytes());
            out.extend_from_slice(&p.after_head);
            out.extend_from_slice(&p.after_revocation_root);
            out.extend_from_slice(&p.after_manifest);
        }
        StoredBinding::Missing => return Err(RecordError::InvalidState),
    };
    Ok(out)
}

/// Canonical signed-record identity, to be stored in an *independently trusted*
/// high-water fence. A hash alone in the same rollbackable store proves nothing.
pub fn signed_record_digest(frame: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(frame);
    h.finalize().into()
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        let bytes = self
            .input
            .get(self.offset..self.offset + N)
            .ok_or(RecordError::BadEncoding)?;
        self.offset += N;
        bytes.try_into().map_err(|_| RecordError::BadEncoding)
    }

    fn u64(&mut self) -> Result<u64, RecordError> {
        Ok(u64::from_be_bytes(self.read()?))
    }

    fn u32(&mut self) -> Result<u32, RecordError> {
        Ok(u32::from_be_bytes(self.read()?))
    }

    fn u16(&mut self) -> Result<u16, RecordError> {
        Ok(u16::from_be_bytes(self.read()?))
    }
}

fn read_high_water(cursor: &mut Cursor<'_>) -> Result<UnifiedPolicyHighWater, RecordError> {
    Ok(UnifiedPolicyHighWater {
        space: SpaceId::from_bytes(cursor.read()?),
        resource: ResourceId::from_bytes(cursor.read()?),
        root_public_key: cursor.read()?,
        root_key_epoch: cursor.u64()?,
        genesis_manifest: cursor.read()?,
        current_manifest: cursor.read()?,
        writer_epoch: cursor.u64()?,
        policy_sequence: cursor.u64()?,
        policy_head: cursor.read()?,
        revocation_root: cursor.read()?,
    })
}

fn read_committed(cursor: &mut Cursor<'_>) -> Result<Committed, RecordError> {
    Ok(Committed {
        identity: PinnedCounterIdentity {
            device_binding: cursor.read()?,
            nv_index: cursor.u32()?,
        },
        counter: cursor.u64()?,
        policy: read_high_water(cursor)?,
    })
}

fn match_scope(binding: StoredBinding, pin: &ExternalSignerPin) -> bool {
    let committed = match binding {
        StoredBinding::Committed(c) => c,
        StoredBinding::Prepared(p) => p.before,
        StoredBinding::Missing => return false,
    };
    let p = committed.policy;
    committed.identity == pin.device
        && p.space == pin.space
        && p.resource == pin.resource
        && p.root_public_key == pin.root_public_key
        && p.root_key_epoch == pin.root_key_epoch
        && p.genesis_manifest == pin.genesis_manifest
        && p.writer_epoch == pin.writer_epoch
}

fn candidate_diagnostic(
    pin: PinnedCounterIdentity,
    observed_counter: u64,
    binding: StoredBinding,
) -> Result<Diagnostic, RecordError> {
    inspect_counter(pin, observed_counter, binding).map_err(|e| match e {
        BindingError::CounterMismatch | BindingError::CounterOverflow => {
            RecordError::CounterMismatch
        }
        _ => RecordError::InvalidState,
    })
}

/// Authenticates a *single* fixed-format frame against an OUT-OF-BAND pin,
/// independent monotonic replay fence and the observed independent counter.
///
/// **Not** a trust bootstrap, hardware proof, global anti-eclipse proof, or
/// permission grant. A real implementation must securely provision, rotate,
/// and update pin + fence outside SQLite before relying on this diagnostic.
pub fn verify_signed_record(
    bytes: &[u8],
    pin: &ExternalSignerPin,
    fence: ExternalReplayFence,
    observed_counter: u64,
) -> Result<VerifiedIntentRecord, RecordError> {
    // Reject unknown frame sizes before allocation or signature parsing.
    let tag = *bytes.get(10).ok_or(RecordError::BadEncoding)?;
    let required = match tag {
        COMMITTED_TAG => HEADER_LEN + COMMITTED_LEN + SIG_LEN,
        PREPARED_TAG => HEADER_LEN + PREPARED_LEN + SIG_LEN,
        _ => return Err(RecordError::BadEncoding),
    };
    if bytes.len() != required {
        return Err(RecordError::BadEncoding);
    }
    let data = &bytes[..required - SIG_LEN];
    let signature_bytes: [u8; SIG_LEN] = bytes[required - SIG_LEN..]
        .try_into()
        .map_err(|_| RecordError::BadEncoding)?;
    let mut reader = Cursor::new(data);
    if reader.read::<8>()? != *MAGIC {
        return Err(RecordError::BadEncoding);
    }
    if reader.u16()? != VERSION {
        return Err(RecordError::UnsupportedVersion);
    }
    if reader.read::<1>()?[0] != tag || reader.read::<1>()?[0] != 0 {
        return Err(RecordError::BadEncoding);
    }
    let record_sequence = reader.u64()?;
    let signer_epoch = reader.u64()?;
    let signer_public_key = reader.read::<32>()?;
    if record_sequence == 0 || signer_epoch == 0 {
        return Err(RecordError::InvalidState);
    }
    if signer_epoch != pin.signer_epoch || signer_public_key != pin.signer_public_key {
        return Err(RecordError::UntrustedSigner);
    }
    let key = VerifyingKey::from_bytes(&pin.signer_public_key)
        .map_err(|_| RecordError::UntrustedSigner)?;
    key.verify_strict(data, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| RecordError::InvalidSignature)?;

    let before = read_committed(&mut reader)?;
    let binding = if tag == COMMITTED_TAG {
        StoredBinding::Committed(before)
    } else {
        StoredBinding::Prepared(Prepared {
            before,
            after_sequence: reader.u64()?,
            after_head: reader.read()?,
            after_revocation_root: reader.read()?,
            after_manifest: reader.read()?,
        })
    };
    if reader.offset != data.len() || !match_scope(binding, pin) {
        return Err(RecordError::WrongDeviceOrScope);
    }
    if fence.minimum_record_sequence == 0 && fence.last_record_digest != [0; 32] {
        return Err(RecordError::ReplayOrFork);
    }
    if record_sequence < fence.minimum_record_sequence || observed_counter < fence.minimum_counter {
        return Err(RecordError::ReplayOrFork);
    }
    let record_digest = signed_record_digest(bytes);
    if record_sequence == fence.minimum_record_sequence && record_digest != fence.last_record_digest
    {
        return Err(RecordError::ReplayOrFork);
    }
    let diagnostic = candidate_diagnostic(pin.device, observed_counter, binding)?;
    Ok(VerifiedIntentRecord {
        record: IntentRecord {
            record_sequence,
            signer_epoch,
            signer_public_key,
            binding,
        },
        record_digest,
        diagnostic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (SigningKey, ExternalSignerPin, Committed) {
        let key = SigningKey::from_bytes(&[41; 32]);
        let device = PinnedCounterIdentity {
            device_binding: [42; 32],
            nv_index: 0x0180_0111,
        };
        let policy = UnifiedPolicyHighWater {
            space: SpaceId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            root_public_key: [31; 32],
            root_key_epoch: 3,
            genesis_manifest: [32; 32],
            current_manifest: [32; 32],
            writer_epoch: 9,
            policy_sequence: 0,
            policy_head: [0; 32],
            revocation_root: [0; 32],
        };
        let pin = ExternalSignerPin {
            signer_public_key: key.verifying_key().to_bytes(),
            signer_epoch: 2,
            device,
            space: policy.space,
            resource: policy.resource,
            root_public_key: policy.root_public_key,
            root_key_epoch: policy.root_key_epoch,
            genesis_manifest: policy.genesis_manifest,
            writer_epoch: policy.writer_epoch,
        };
        (
            key,
            pin,
            Committed {
                identity: device,
                counter: 17,
                policy,
            },
        )
    }

    fn signed(
        key: &SigningKey,
        counter: Committed,
        record_sequence: u64,
        epoch: u64,
        binding: StoredBinding,
    ) -> Vec<u8> {
        let record = IntentRecord {
            record_sequence,
            signer_epoch: epoch,
            signer_public_key: key.verifying_key().to_bytes(),
            binding,
        };
        let mut bytes = signing_preimage(&record).unwrap();
        let signature = key.sign(&bytes).to_bytes();
        bytes.extend_from_slice(&signature);
        let _ = counter; // ensures helper call sites bind the same fixture identity
        bytes
    }

    fn initial_fence() -> ExternalReplayFence {
        ExternalReplayFence {
            minimum_record_sequence: 0,
            minimum_counter: 17,
            last_record_digest: [0; 32],
        }
    }

    fn future_intent(before: Committed) -> Prepared {
        Prepared {
            before,
            after_sequence: 1,
            after_head: [71; 32],
            after_revocation_root: [72; 32],
            after_manifest: before.policy.current_manifest,
        }
    }

    #[test]
    fn canonical_record_sizes_and_verified_round_trip() {
        let (key, pin, committed) = fixture();
        let frame = signed(&key, committed, 1, 2, StoredBinding::Committed(committed));
        assert_eq!(frame.len(), HEADER_LEN + COMMITTED_LEN + SIG_LEN);
        assert_eq!(&frame[..8], MAGIC);
        let verified = verify_signed_record(&frame, &pin, initial_fence(), 17).unwrap();
        assert_eq!(
            verified.record().binding,
            StoredBinding::Committed(committed)
        );
        assert_eq!(verified.diagnostic(), Diagnostic::MatchingCounterOnly);
        assert_eq!(verified.digest(), signed_record_digest(&frame));

        let intent = future_intent(committed);
        let prepared = signed(&key, committed, 2, 2, StoredBinding::Prepared(intent));
        assert_eq!(prepared.len(), HEADER_LEN + PREPARED_LEN + SIG_LEN);
        assert_eq!(
            verify_signed_record(&prepared, &pin, initial_fence(), 17)
                .unwrap()
                .diagnostic(),
            Diagnostic::IntentBeforeIncrement
        );
        assert_eq!(
            verify_signed_record(&prepared, &pin, initial_fence(), 18)
                .unwrap()
                .diagnostic(),
            Diagnostic::IncrementNeedsSignedRecheck
        );
    }

    #[test]
    fn every_signed_field_tampering_and_signature_substitution_rejected() {
        let (key, pin, committed) = fixture();
        let original = signed(&key, committed, 4, 2, StoredBinding::Committed(committed));
        for index in [
            0,
            8,
            10,
            11,
            12,
            20,
            28,
            59,
            60,
            91,
            92,
            95,
            96,
            103,
            104,
            119,
            120,
            135,
            136,
            143,
            144,
            175,
            176,
            207,
            208,
            215,
            216,
            247,
            248,
            279,
            280,
            311,
            312,
            original.len() - 65,
            original.len() - 1,
        ] {
            let mut tampered = original.clone();
            tampered[index] ^= 1;
            assert!(
                verify_signed_record(&tampered, &pin, initial_fence(), 17).is_err(),
                "tampering byte {index} unexpectedly succeeded"
            );
        }
        let attacker = SigningKey::from_bytes(&[55; 32]);
        let mut bad_sig = original.clone();
        let sig = attacker.sign(&original[..original.len() - SIG_LEN]);
        bad_sig[original.len() - SIG_LEN..].copy_from_slice(&sig.to_bytes());
        assert_eq!(
            verify_signed_record(&bad_sig, &pin, initial_fence(), 17),
            Err(RecordError::InvalidSignature)
        );
    }

    #[test]
    fn version_length_reserved_and_state_canonicalization() {
        let (key, pin, committed) = fixture();
        let frame = signed(&key, committed, 2, 2, StoredBinding::Committed(committed));
        for edited in [
            frame[..frame.len() - 1].to_vec(),
            {
                let mut e = frame.clone();
                e.push(0);
                e
            },
            {
                let mut e = frame.clone();
                e[9] = 2;
                e
            },
            {
                let mut e = frame.clone();
                e[11] = 1;
                e
            },
            {
                let mut e = frame.clone();
                e[10] = 0;
                e
            },
        ] {
            assert!(verify_signed_record(&edited, &pin, initial_fence(), 17).is_err());
        }
        assert_eq!(
            signing_preimage(&IntentRecord {
                record_sequence: 3,
                signer_epoch: 2,
                signer_public_key: key.verifying_key().to_bytes(),
                binding: StoredBinding::Missing,
            }),
            Err(RecordError::InvalidState)
        );
        let mut malformed = future_intent(committed);
        malformed.after_sequence = 0;
        assert_eq!(
            signing_preimage(&IntentRecord {
                record_sequence: 3,
                signer_epoch: 2,
                signer_public_key: key.verifying_key().to_bytes(),
                binding: StoredBinding::Prepared(malformed),
            }),
            Err(RecordError::InvalidState)
        );
    }

    #[test]
    fn cross_device_space_root_writer_and_genesis_substitution_rejected() {
        let (key, pin, committed) = fixture();
        let frame = signed(&key, committed, 5, 2, StoredBinding::Committed(committed));
        let mut wrong = pin;
        wrong.device.nv_index ^= 1;
        assert_eq!(
            verify_signed_record(&frame, &wrong, initial_fence(), 17),
            Err(RecordError::WrongDeviceOrScope)
        );
        for wrong_scope in 0..5 {
            let mut wrong = pin;
            match wrong_scope {
                0 => wrong.space = SpaceId::from_bytes([7; 16]),
                1 => wrong.resource = ResourceId::from_bytes([8; 16]),
                2 => wrong.root_public_key = [1; 32],
                3 => wrong.writer_epoch += 1,
                _ => wrong.genesis_manifest = [8; 32],
            }
            assert_eq!(
                verify_signed_record(&frame, &wrong, initial_fence(), 17),
                Err(RecordError::WrongDeviceOrScope)
            );
        }
    }

    #[test]
    fn replay_fence_blocks_old_records_and_same_sequence_forks() {
        let (key, pin, committed) = fixture();
        let old = signed(&key, committed, 7, 2, StoredBinding::Committed(committed));
        let later = signed(&key, committed, 8, 2, StoredBinding::Committed(committed));
        let fence = ExternalReplayFence {
            minimum_record_sequence: 8,
            minimum_counter: 17,
            last_record_digest: signed_record_digest(&later),
        };
        assert_eq!(
            verify_signed_record(&old, &pin, fence, 17),
            Err(RecordError::ReplayOrFork)
        );
        assert_eq!(
            verify_signed_record(&later, &pin, fence, 17)
                .unwrap()
                .record()
                .record_sequence,
            8
        );
        let altered = signed(
            &key,
            committed,
            8,
            2,
            StoredBinding::Prepared(future_intent(committed)),
        );
        assert_eq!(
            verify_signed_record(&altered, &pin, fence, 17),
            Err(RecordError::ReplayOrFork)
        );
        let no_nv_rollback = ExternalReplayFence {
            minimum_counter: 18,
            ..fence
        };
        assert_eq!(
            verify_signed_record(&later, &pin, no_nv_rollback, 17),
            Err(RecordError::ReplayOrFork)
        );
    }

    #[test]
    fn signer_rotation_needs_out_of_band_epoch_and_public_key_pin() {
        let (old_key, old_pin, committed) = fixture();
        let old = signed(
            &old_key,
            committed,
            12,
            2,
            StoredBinding::Committed(committed),
        );
        let new_key = SigningKey::from_bytes(&[53; 32]);
        let newer = signed(
            &new_key,
            committed,
            13,
            3,
            StoredBinding::Committed(committed),
        );
        let fence = ExternalReplayFence {
            minimum_record_sequence: 12,
            minimum_counter: 17,
            last_record_digest: signed_record_digest(&old),
        };
        assert_eq!(
            verify_signed_record(&newer, &old_pin, fence, 17),
            Err(RecordError::UntrustedSigner)
        );
        let mut rotated_pin = old_pin;
        rotated_pin.signer_epoch = 3;
        rotated_pin.signer_public_key = new_key.verifying_key().to_bytes();
        assert_eq!(
            verify_signed_record(&old, &rotated_pin, fence, 17),
            Err(RecordError::UntrustedSigner)
        );
        assert_eq!(
            verify_signed_record(&newer, &rotated_pin, fence, 17)
                .unwrap()
                .record()
                .record_sequence,
            13
        );
        let old_key_claiming_new_epoch = signed(
            &old_key,
            committed,
            13,
            3,
            StoredBinding::Committed(committed),
        );
        assert_eq!(
            verify_signed_record(&old_key_claiming_new_epoch, &rotated_pin, fence, 17),
            Err(RecordError::UntrustedSigner)
        );
    }

    #[test]
    fn authentic_record_does_not_override_wrong_counter_or_expired_fence() {
        let (key, pin, committed) = fixture();
        let signed = signed(&key, committed, 1, 2, StoredBinding::Committed(committed));
        assert_eq!(
            verify_signed_record(&signed, &pin, initial_fence(), 18),
            Err(RecordError::CounterMismatch)
        );
        let inconsistent = ExternalReplayFence {
            minimum_record_sequence: 0,
            minimum_counter: 17,
            last_record_digest: [1; 32],
        };
        assert_eq!(
            verify_signed_record(&signed, &pin, inconsistent, 17),
            Err(RecordError::ReplayOrFork)
        );
    }

    #[test]
    fn signed_record_recovery_binds_to_simulated_crash_image_and_nv_counter() {
        use crate::durable_intent_simulator::{CrashPoint, CrashRecoverySimulator};

        let (key, pin, committed) = fixture();
        let simulator = CrashRecoverySimulator::enrolled_for_test(committed);
        let (counter, intent) = simulator.handles().unwrap();
        let after = future_intent(committed);
        intent.prepare(committed, after).unwrap();
        simulator
            .fail_once(CrashPoint::IncrementAfterWrite)
            .unwrap();
        assert_eq!(counter.increment(), Err(BindingError::PersistenceUncertain));
        simulator.reboot().unwrap();

        let image = simulator.durable_image().unwrap();
        assert_eq!(image.nv_counter, 18);
        assert_eq!(image.intent, StoredBinding::Prepared(after));
        let record = signed(&key, committed, 10, 2, image.intent);
        let verified =
            verify_signed_record(&record, &pin, initial_fence(), image.nv_counter).unwrap();
        assert_eq!(
            verified.diagnostic(),
            Diagnostic::IncrementNeedsSignedRecheck
        );
        let fence = ExternalReplayFence {
            minimum_record_sequence: 10,
            minimum_counter: 18,
            last_record_digest: verified.digest(),
        };

        // A restored old intent cannot override a later independently pinned
        // record digest. The model's NV counter stays irreversibly advanced.
        simulator
            .restore_untrusted_intent_for_test(StoredBinding::Committed(committed))
            .unwrap();
        let restored = simulator.durable_image().unwrap();
        assert_eq!(restored.nv_counter, 18);
        let stale = signed(&key, committed, 9, 2, restored.intent);
        assert_eq!(
            verify_signed_record(&stale, &pin, fence, restored.nv_counter),
            Err(RecordError::ReplayOrFork)
        );
        let conflicting = signed(&key, committed, 10, 2, restored.intent);
        assert_eq!(
            verify_signed_record(&conflicting, &pin, fence, restored.nv_counter),
            Err(RecordError::ReplayOrFork)
        );
    }
}
