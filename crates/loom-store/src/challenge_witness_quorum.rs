//! L-002C: challenge-bound, two-independent-Witness diagnostic read protocol.
//!
//! Hardware-neutral: a client verifies Ed25519 replies to an independently
//! unpredictable, single-use nonce. This is **not** a remote service, a durable
//! quorum, global anti-eclipse, a proof of actual key independence, or access
//! authorization. The challenge and trusted Witness pins MUST be provisioned
//! outside rollbackable SQLite; there is no production provider here.
//! No TPM, hardware signer, network listener, ServiceOpen or state writes.

use ed25519_dalek::{Signature, VerifyingKey};
use loom_crypto::witness_checkpoint::TrustedWitnessForSpike;
use loom_types::{ResourceId, SpaceId};

const OBSERVATION_DOMAIN: &[u8] = b"LOOM:WITNESS-LATEST:V1\0";

/// Exact signed journal high-water identity. A raw value is NOT authenticated
/// until externally verified against Root/Owner historical signed evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuorumHighWater {
    pub space: SpaceId,
    pub resource: ResourceId,
    pub writer_epoch: u64,
    pub sequence: u64,
    pub policy_head: [u8; 32],
    pub revocation_root: [u8; 32],
}

/// A challenge must be unpredictable and never reused for a signed query.
/// The caller must use a vetted CSPRNG and track outstanding challenges.
/// A deterministic nonce in production would enable replay after local reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuorumChallenge {
    pub nonce: [u8; 32],
    pub expected_space: SpaceId,
    pub expected_resource: ResourceId,
    pub expected_writer_epoch: u64,
}

/// A Witness must sign its latest independently stored monotonic state
/// and this exact request nonce, not a client-provided 'expected' digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuorumObservation {
    pub challenge: QuorumChallenge,
    pub generation: u64,
    pub high_water: QuorumHighWater,
}

#[derive(Clone, Copy, Debug)]
pub struct SignedQuorumObservation {
    pub witness_key_id: [u8; 32],
    pub observation: QuorumObservation,
    pub signature: [u8; 64],
}

/// Externally Root-pinned Witness signing keys. These must be provisioned
/// out-of-band; naming two keys doesn't prove separate operators or custody.
#[derive(Clone, Copy, Debug)]
pub struct PinnedQuorum {
    pub witnesses: [TrustedWitnessForSpike; 2],
    pub space: SpaceId,
    pub resource: ResourceId,
    pub writer_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumError {
    InsecureChallenge,
    MissingOrDuplicateWitness,
    UntrustedWitness,
    InvalidSignature,
    WrongChallenge,
    WrongScope,
    InvalidState,
    SplitWitnesses,
    StaleGeneration,
    LocalRollbackOrFork,
}

/// Merely a checked diagnostic of TWO agreeing freshly signed replies, not
/// a policy, Root or Owner authorization; no ServiceOpen can consume it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedQuorumDiagnostic {
    observation: QuorumObservation,
}

impl VerifiedQuorumDiagnostic {
    pub fn high_water(&self) -> QuorumHighWater {
        self.observation.high_water
    }

    pub fn generation(&self) -> u64 {
        self.observation.generation
    }
}

/// Canonical transcript: domain || nonce || request scope || witnessed
/// generation || witnessed full policy scope/head. All integers u64 BE.
pub fn quorum_observation_transcript(observed: &QuorumObservation) -> Vec<u8> {
    let mut out = Vec::with_capacity(OBSERVATION_DOMAIN.len() + 32 + 32 * 3 + 8 * 4 + 32);
    let request = observed.challenge;
    let state = observed.high_water;
    out.extend_from_slice(OBSERVATION_DOMAIN);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(request.expected_space.as_bytes());
    out.extend_from_slice(request.expected_resource.as_bytes());
    out.extend_from_slice(&request.expected_writer_epoch.to_be_bytes());
    out.extend_from_slice(&observed.generation.to_be_bytes());
    out.extend_from_slice(state.space.as_bytes());
    out.extend_from_slice(state.resource.as_bytes());
    out.extend_from_slice(&state.writer_epoch.to_be_bytes());
    out.extend_from_slice(&state.sequence.to_be_bytes());
    out.extend_from_slice(&state.policy_head);
    out.extend_from_slice(&state.revocation_root);
    out
}

/// Validate TWO independently pinned witnesses against a caller-supplied
/// fresh challenge, known minimum witness generation and the signed local
/// journal state. Exact state agreement is required: a higher remote head
/// also quarantines the stale local DB, never silently imports a new policy.
///
/// The proof is diagnostic-only. It does not establish two Witness machines
/// were deployed, that the keys cannot be stolen, or that the client has an
/// independent globally current challenge source. Physical persistence and
/// remote fork resistance remain separate production security requirements.
pub fn verify_challenge_bound_quorum(
    trusted: &PinnedQuorum,
    request: QuorumChallenge,
    replies: &[SignedQuorumObservation],
    minimum_generation: u64,
    signed_local_state: QuorumHighWater,
) -> Result<VerifiedQuorumDiagnostic, QuorumError> {
    if request.nonce == [0; 32] {
        return Err(QuorumError::InsecureChallenge);
    }
    if request.expected_space != trusted.space
        || request.expected_resource != trusted.resource
        || request.expected_writer_epoch != trusted.writer_epoch
        || signed_local_state.space != trusted.space
        || signed_local_state.resource != trusted.resource
        || signed_local_state.writer_epoch != trusted.writer_epoch
    {
        return Err(QuorumError::WrongScope);
    }
    if trusted.writer_epoch == 0 || signed_local_state.sequence == 0 {
        return Err(QuorumError::InvalidState);
    }
    let [a, b] = trusted.witnesses;
    if replies.len() != 2
        || a.public_key == b.public_key
        || a.key_id == b.key_id
        || a.key_id != TrustedWitnessForSpike::from_public_key(a.public_key).key_id
        || b.key_id != TrustedWitnessForSpike::from_public_key(b.public_key).key_id
    {
        return Err(QuorumError::MissingOrDuplicateWitness);
    }

    let mut checked: [Option<QuorumObservation>; 2] = [None, None];
    for (slot, pin) in trusted.witnesses.iter().enumerate() {
        let candidates: Vec<&SignedQuorumObservation> = replies
            .iter()
            .filter(|r| r.witness_key_id == pin.key_id)
            .collect();
        if candidates.len() != 1 {
            return Err(QuorumError::MissingOrDuplicateWitness);
        }
        let receipt = candidates[0];
        let obs = receipt.observation;
        if obs.challenge != request {
            return Err(QuorumError::WrongChallenge);
        }
        if obs.high_water.space != trusted.space
            || obs.high_water.resource != trusted.resource
            || obs.high_water.writer_epoch != trusted.writer_epoch
        {
            return Err(QuorumError::WrongScope);
        }
        if obs.high_water.sequence == 0 {
            return Err(QuorumError::InvalidState);
        }
        let key = VerifyingKey::from_bytes(&pin.public_key)
            .map_err(|_| QuorumError::UntrustedWitness)?;
        key.verify_strict(
            &quorum_observation_transcript(&obs),
            &Signature::from_bytes(&receipt.signature),
        )
        .map_err(|_| QuorumError::InvalidSignature)?;
        checked[slot] = Some(obs);
    }

    let first = checked[0].ok_or(QuorumError::MissingOrDuplicateWitness)?;
    let second = checked[1].ok_or(QuorumError::MissingOrDuplicateWitness)?;
    if first != second {
        return Err(QuorumError::SplitWitnesses);
    }
    if first.generation < minimum_generation {
        return Err(QuorumError::StaleGeneration);
    }
    if first.high_water != signed_local_state {
        return Err(QuorumError::LocalRollbackOrFork);
    }
    Ok(VerifiedQuorumDiagnostic { observation: first })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Mutex;

    const NEW_NONCE: [u8; 32] = [71; 32];
    const OTHER_NONCE: [u8; 32] = [72; 32];

    fn state(sequence: u64, digest: [u8; 32]) -> QuorumHighWater {
        QuorumHighWater {
            space: SpaceId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            writer_epoch: 3,
            sequence,
            policy_head: digest,
            revocation_root: [81; 32],
        }
    }
    fn challenge(nonce: [u8; 32]) -> QuorumChallenge {
        QuorumChallenge {
            nonce,
            expected_space: state(1, [4; 32]).space,
            expected_resource: state(1, [4; 32]).resource,
            expected_writer_epoch: 3,
        }
    }

    // Different process/storage domains in a real system; only independent
    // in-memory Mutex instances in this test. Signing key is not exported to
    // the production verifier. All advances are test-fixture Owner events.
    struct FakeIndependentWitness {
        signer: SigningKey,
        data: Mutex<(u64, QuorumHighWater)>,
    }
    impl FakeIndependentWitness {
        fn new(secret: u8) -> Self {
            Self {
                signer: SigningKey::from_bytes(&[secret; 32]),
                data: Mutex::new((4, state(8, [9; 32]))),
            }
        }
        fn pinned(&self) -> TrustedWitnessForSpike {
            TrustedWitnessForSpike::from_public_key(self.signer.verifying_key().to_bytes())
        }
        fn read_signed(&self, nonce: [u8; 32]) -> SignedQuorumObservation {
            let (generation, high_water) = *self.data.lock().unwrap();
            let observation = QuorumObservation {
                challenge: challenge(nonce),
                generation,
                high_water,
            };
            SignedQuorumObservation {
                witness_key_id: self.pinned().key_id,
                observation,
                signature: self
                    .signer
                    .sign(&quorum_observation_transcript(&observation))
                    .to_bytes(),
            }
        }
        fn advance_for_test(
            &self,
            expected_generation: u64,
            next: QuorumHighWater,
        ) -> Result<(), QuorumError> {
            let mut data = self.data.lock().unwrap();
            let old = data.1;
            if data.0 != expected_generation
                || old.space != next.space
                || old.resource != next.resource
                || old.writer_epoch != next.writer_epoch
                || old.sequence.checked_add(1) != Some(next.sequence)
                || old.policy_head == next.policy_head
            {
                return Err(QuorumError::LocalRollbackOrFork);
            }
            data.0 = data.0.checked_add(1).ok_or(QuorumError::InvalidState)?;
            data.1 = next;
            Ok(())
        }
    }
    struct Fixture {
        a: FakeIndependentWitness,
        b: FakeIndependentWitness,
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                a: FakeIndependentWitness::new(21),
                b: FakeIndependentWitness::new(22),
            }
        }
        fn pins(&self) -> PinnedQuorum {
            PinnedQuorum {
                witnesses: [self.a.pinned(), self.b.pinned()],
                space: state(8, [9; 32]).space,
                resource: state(8, [9; 32]).resource,
                writer_epoch: 3,
            }
        }
        fn receipts(&self, nonce: [u8; 32]) -> [SignedQuorumObservation; 2] {
            [self.a.read_signed(nonce), self.b.read_signed(nonce)]
        }
        fn verify(&self, nonce: [u8; 32]) -> Result<VerifiedQuorumDiagnostic, QuorumError> {
            verify_challenge_bound_quorum(
                &self.pins(),
                challenge(nonce),
                &self.receipts(nonce),
                4,
                state(8, [9; 32]),
            )
        }
    }

    #[test]
    fn independent_fresh_signatures_agree_but_never_issue_admission() {
        let f = Fixture::new();
        let diagnostic = f.verify(NEW_NONCE).unwrap();
        assert_eq!(diagnostic.generation(), 4);
        assert_eq!(diagnostic.high_water(), state(8, [9; 32]));
    }

    #[test]
    fn old_valid_signed_responses_fail_a_new_challenge() {
        let f = Fixture::new();
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(OTHER_NONCE), &f.receipts(NEW_NONCE),
                4, state(8, [9; 32])
            ),
            Err(QuorumError::WrongChallenge)
        );
    }

    #[test]
    fn empty_nonce_is_refused_not_mistaken_for_crypto_freshness() {
        let f = Fixture::new();
        assert_eq!(f.verify([0; 32]), Err(QuorumError::InsecureChallenge));
    }

    #[test]
    fn one_offline_witness_fails_closed() {
        let f = Fixture::new();
        let responses = f.receipts(NEW_NONCE);
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(NEW_NONCE), &responses[..1],
                4, state(8, [9; 32])
            ),
            Err(QuorumError::MissingOrDuplicateWitness)
        );
    }

    #[test]
    fn duplicate_witness_and_unpinned_identity_are_refused() {
        let f = Fixture::new();
        let [a, _] = f.receipts(NEW_NONCE);
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(NEW_NONCE), &[a, a], 4, state(8, [9; 32])
            ),
            Err(QuorumError::MissingOrDuplicateWitness)
        );
        let mut pins = f.pins();
        pins.witnesses[1] = pins.witnesses[0];
        assert_eq!(
            verify_challenge_bound_quorum(
                &pins, challenge(NEW_NONCE), &f.receipts(NEW_NONCE),
                4, state(8, [9; 32])
            ),
            Err(QuorumError::MissingOrDuplicateWitness)
        );
        pins = f.pins();
        pins.witnesses[1].public_key = [5; 32];
        assert_eq!(
            verify_challenge_bound_quorum(
                &pins, challenge(NEW_NONCE), &f.receipts(NEW_NONCE),
                4, state(8, [9; 32])
            ),
            Err(QuorumError::MissingOrDuplicateWitness)
        );
    }

    #[test]
    fn signatures_and_reply_identity_cannot_be_substituted() {
        let f = Fixture::new();
        let mut replies = f.receipts(NEW_NONCE);
        replies[1].signature[2] ^= 1;
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(NEW_NONCE), &replies, 4, state(8, [9; 32])
            ),
            Err(QuorumError::InvalidSignature)
        );
        let mut replies = f.receipts(NEW_NONCE);
        replies[0].witness_key_id = [4; 32];
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(NEW_NONCE), &replies, 4, state(8, [9; 32])
            ),
            Err(QuorumError::MissingOrDuplicateWitness)
        );
    }

    #[test]
    fn signed_two_witness_split_brain_is_refused() {
        let f = Fixture::new();
        f.a.advance_for_test(4, state(9, [11; 32])).unwrap();
        assert_eq!(f.verify(NEW_NONCE), Err(QuorumError::SplitWitnesses));
    }

    #[test]
    fn locally_restored_database_is_detected_by_fresh_remote_watermark() {
        let f = Fixture::new();
        f.a.advance_for_test(4, state(9, [11; 32])).unwrap();
        f.b.advance_for_test(4, state(9, [11; 32])).unwrap();
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(NEW_NONCE), &f.receipts(NEW_NONCE),
                4, state(8, [9; 32])
            ),
            Err(QuorumError::LocalRollbackOrFork)
        );
        let verified = verify_challenge_bound_quorum(
            &f.pins(), challenge(NEW_NONCE), &f.receipts(NEW_NONCE),
            5, state(9, [11; 32])
        ).unwrap();
        assert_eq!(verified.generation(), 5);
    }

    #[test]
    fn prior_independent_floor_rejects_stale_signed_two_witness_image() {
        let f = Fixture::new();
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(NEW_NONCE), &f.receipts(NEW_NONCE),
                5, state(8, [9; 32])
            ),
            Err(QuorumError::StaleGeneration)
        );
    }

    #[test]
    fn wrong_space_resource_epoch_are_rejected_even_with_two_signatures() {
        let f = Fixture::new();
        let mut query = challenge(NEW_NONCE);
        query.expected_space = SpaceId::from_bytes([8; 16]);
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), query, &f.receipts(NEW_NONCE), 4, state(8, [9; 32])
            ),
            Err(QuorumError::WrongScope)
        );
        query = challenge(NEW_NONCE);
        query.expected_resource = ResourceId::from_bytes([8; 16]);
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), query, &f.receipts(NEW_NONCE), 4, state(8, [9; 32])
            ),
            Err(QuorumError::WrongScope)
        );
        query = challenge(NEW_NONCE);
        query.expected_writer_epoch = 9;
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), query, &f.receipts(NEW_NONCE), 4, state(8, [9; 32])
            ),
            Err(QuorumError::WrongScope)
        );
    }

    #[test]
    fn witness_cas_refuses_duplicate_and_sequence_fork() {
        let f = Fixture::new();
        assert_eq!(
            f.a.advance_for_test(3, state(9, [11; 32])),
            Err(QuorumError::LocalRollbackOrFork)
        );
        f.a.advance_for_test(4, state(9, [11; 32])).unwrap();
        assert_eq!(
            f.a.advance_for_test(4, state(10, [12; 32])),
            Err(QuorumError::LocalRollbackOrFork)
        );
        assert_eq!(
            f.a.advance_for_test(5, state(9, [13; 32])),
            Err(QuorumError::LocalRollbackOrFork)
        );
    }

    #[test]
    fn mismatched_signer_and_signed_local_fork_are_rejected() {
        let f = Fixture::new();
        let mut receipts = f.receipts(NEW_NONCE);
        receipts[0].observation.high_water.policy_head = [3; 32];
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(NEW_NONCE), &receipts, 4, state(8, [9; 32])
            ),
            Err(QuorumError::InvalidSignature)
        );
        assert_eq!(
            verify_challenge_bound_quorum(
                &f.pins(), challenge(NEW_NONCE), &f.receipts(NEW_NONCE),
                4, state(8, [31; 32])
            ),
            Err(QuorumError::LocalRollbackOrFork)
        );
    }
}
