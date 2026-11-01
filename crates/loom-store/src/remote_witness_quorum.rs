//! L-002E transport-neutral client coordinator for two Root-pinned Witnesses.
//!
//! This module defines the client-side write/read protocol, not a network
//! listener or a trusted storage backend. A transport adapter must authenticate
//! the remote endpoint, enforce bounded timeouts, and keep each Witness's key
//! and durable state in a separately administered trust domain.
//!
//! Writes are deliberately confirmed by a fresh challenge-bound read from
//! BOTH Witnesses. An append RPC error is ambiguous: the server may have
//! committed before the connection failed. Never sign a replacement event;
//! retry the exact same SignedAppend after a partial or uncertain result.
//!
//! This coordinator does not prove physical independence, prevent a Witness
//! operator from rolling back its own storage, or authorize ServiceOpen.

use crate::challenge_witness_quorum::{
    PinnedQuorum, QuorumChallenge, QuorumError, QuorumHighWater, SignedQuorumObservation,
    VerifiedQuorumDiagnostic, verify_challenge_bound_quorum,
};
use crate::witness_append::{AppendError, SignedAppend};
use loom_crypto::space_trust::VerifiedResourceTrust;
use sha2::{Digest, Sha256};

/// Errors returned by a transport adapter. Append errors can be ambiguous:
/// the remote side may have committed before the transport failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessEndpointError {
    Unavailable,
    Rejected(AppendError),
}

/// Minimal transport boundary implemented by a future authenticated RPC
/// adapter. Implementations must use bounded timeouts and authenticate the
/// endpoint identity; witness_key_id is checked against the Root-pinned
/// manifest before any request is sent.
pub trait WitnessEndpoint: Send + Sync {
    fn witness_key_id(&self) -> [u8; 32];

    /// Submit the exact Owner-signed append. A successful return is not itself
    /// quorum confirmation; the coordinator performs a fresh signed read.
    fn append(
        &self,
        signed: SignedAppend,
        now_ms: u64,
    ) -> Result<(), WitnessEndpointError>;

    /// Return a signature over the Witness's own current state and this nonce.
    fn observe(
        &self,
        challenge: QuorumChallenge,
        now_ms: u64,
    ) -> Result<SignedQuorumObservation, WitnessEndpointError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessClientError {
    WrongWitnessEndpoints,
    ExpiredTrust,
    InvalidChallenge,
    WrongScope,
    ExpiredAppend,
    InvalidAppend(AppendError),
    StalePredecessor,
    SequenceExhausted,
    WitnessUnavailable,
    /// The two signed responses differ. This includes a partial append and
    /// any other split-brain state; all such cases remain fail-closed.
    PartialCommitOrDivergence,
    /// Both Witnesses agree, but not on the state this client expected.
    /// The caller must re-read and reconcile; it must not mint a new event.
    NotCommittedOrStale,
    Quorum(QuorumError),
}

/// Coordinates exactly two Root-pinned Witness endpoints. Endpoint order must
/// match the Root-signed resource manifest, preventing accidental endpoint
/// substitution during setup.
pub struct WitnessQuorumClient<'a> {
    trust: VerifiedResourceTrust,
    endpoints: [&'a dyn WitnessEndpoint; 2],
}

impl<'a> WitnessQuorumClient<'a> {
    pub fn new(
        trust: VerifiedResourceTrust,
        first: &'a dyn WitnessEndpoint,
        second: &'a dyn WitnessEndpoint,
    ) -> Result<Self, WitnessClientError> {
        let pins = trust.witnesses();
        if pins[0].key_id == pins[1].key_id
            || first.witness_key_id() != pins[0].key_id
            || second.witness_key_id() != pins[1].key_id
        {
            return Err(WitnessClientError::WrongWitnessEndpoints);
        }
        Ok(Self {
            trust,
            endpoints: [first, second],
        })
    }

    fn pinned_quorum(&self) -> PinnedQuorum {
        PinnedQuorum {
            witnesses: self.trust.witnesses(),
            space: self.trust.space(),
            resource: self.trust.resource(),
            writer_epoch: self.trust.writer_epoch(),
        }
    }

    fn check_challenge(
        &self,
        challenge: QuorumChallenge,
    ) -> Result<(), WitnessClientError> {
        if challenge.nonce == [0; 32] {
            return Err(WitnessClientError::InvalidChallenge);
        }
        if challenge.expected_space != self.trust.space()
            || challenge.expected_resource != self.trust.resource()
            || challenge.expected_writer_epoch != self.trust.writer_epoch()
        {
            return Err(WitnessClientError::WrongScope);
        }
        Ok(())
    }

    /// Read and verify a fresh, exactly agreeing two-Witness observation.
    /// minimum_generation must come from a separately trusted floor; it must
    /// never be learned only from the same rollbackable SQLite image.
    pub fn observe_latest(
        &self,
        challenge: QuorumChallenge,
        minimum_generation: u64,
        signed_local_state: QuorumHighWater,
        now_ms: u64,
    ) -> Result<VerifiedQuorumDiagnostic, WitnessClientError> {
        if !self.trust.valid_at(now_ms) {
            return Err(WitnessClientError::ExpiredTrust);
        }
        self.check_challenge(challenge)?;
        let first = self.endpoints[0]
            .observe(challenge, now_ms)
            .map_err(|_| WitnessClientError::WitnessUnavailable)?;
        let second = self.endpoints[1]
            .observe(challenge, now_ms)
            .map_err(|_| WitnessClientError::WitnessUnavailable)?;
        verify_challenge_bound_quorum(
            &self.pinned_quorum(),
            challenge,
            &[first, second],
            minimum_generation,
            signed_local_state,
        )
        .map_err(WitnessClientError::Quorum)
    }

    /// Submit one Owner-signed event to both Witnesses, then confirm the result
    /// with a fresh challenge-bound read. RPC acknowledgements are intentionally
    /// not trusted as proof of durable commit.
    ///
    /// On PartialCommitOrDivergence, NotCommittedOrStale, or
    /// WitnessUnavailable, preserve and retry the SAME signed bytes after
    /// re-reading both Witnesses. Do not create a replacement event for the
    /// same predecessor. current must be the fully replayed local signed
    /// history high-water, not a cached or caller-invented value.
    pub fn append_and_confirm(
        &self,
        signed: SignedAppend,
        current: QuorumHighWater,
        challenge: QuorumChallenge,
        now_ms: u64,
    ) -> Result<QuorumHighWater, WitnessClientError> {
        if !self.trust.valid_at(now_ms) {
            return Err(WitnessClientError::ExpiredTrust);
        }
        self.check_challenge(challenge)?;
        signed
            .verify_history(&self.trust)
            .map_err(WitnessClientError::InvalidAppend)?;
        let request = signed.request;
        if request.manifest != self.trust.manifest_commitment()
            || current.space != self.trust.space()
            || current.resource != self.trust.resource()
            || current.writer_epoch != self.trust.writer_epoch()
        {
            return Err(WitnessClientError::WrongScope);
        }
        if request.issued_at_ms > now_ms || now_ms >= request.expires_at_ms {
            return Err(WitnessClientError::ExpiredAppend);
        }
        if request.expected_generation != current.sequence
            || request.previous_head != current.policy_head
        {
            return Err(WitnessClientError::StalePredecessor);
        }
        let expected = expected_next_high_water(current, signed)?;

        // Always attempt both endpoints. A transport error is ambiguous and
        // must not prevent the other Witness from receiving the same event.
        let _first_append = self.endpoints[0].append(signed, now_ms);
        let _second_append = self.endpoints[1].append(signed, now_ms);

        match self.observe_latest(challenge, 0, expected, now_ms) {
            Ok(observation) if observation.high_water() == expected => Ok(expected),
            Ok(_) => Err(WitnessClientError::NotCommittedOrStale),
            Err(WitnessClientError::Quorum(QuorumError::SplitWitnesses)) => {
                Err(WitnessClientError::PartialCommitOrDivergence)
            }
            Err(WitnessClientError::Quorum(
                QuorumError::InvalidState
                | QuorumError::LocalRollbackOrFork
                | QuorumError::StaleGeneration,
            )) => Err(WitnessClientError::NotCommittedOrStale),
            Err(error) => Err(error),
        }
    }
}

fn expected_next_high_water(
    current: QuorumHighWater,
    signed: SignedAppend,
) -> Result<QuorumHighWater, WitnessClientError> {
    let sequence = current
        .sequence
        .checked_add(1)
        .ok_or(WitnessClientError::SequenceExhausted)?;
    let encoded = signed.encode();
    let policy_head = Sha256::digest(&encoded).into();
    let revocation_root = if signed.request.mutation.allow {
        current.revocation_root
    } else {
        let mut hash = Sha256::new();
        hash.update(b"LOOM:WITNESS-REVOKE:V1\0");
        hash.update(current.revocation_root);
        hash.update(&encoded);
        hash.finalize().into()
    };
    Ok(QuorumHighWater {
        sequence,
        policy_head,
        revocation_root,
        ..current
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge_witness_quorum::{
        QuorumObservation, quorum_observation_transcript,
    };
    use crate::witness_append::{
        AppendRequest, ReadMutation, WitnessHistory, append_transcript,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use loom_crypto::space_trust::{
        ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
        verify_resource_trust_for_spike, trust_manifest_transcript,
    };
    use loom_crypto::witness_checkpoint::TrustedWitnessForSpike;
    use loom_types::{PeerId, ResourceId, SpaceId};
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    struct MemoryWitness {
        key: SigningKey,
        trust: VerifiedResourceTrust,
        records: Mutex<Vec<SignedAppend>>,
        append_available: AtomicBool,
        observe_available: AtomicBool,
    }

    impl MemoryWitness {
        fn new(key: SigningKey, trust: VerifiedResourceTrust) -> Self {
            Self {
                key,
                trust,
                records: Mutex::new(Vec::new()),
                append_available: AtomicBool::new(true),
                observe_available: AtomicBool::new(true),
            }
        }

        fn set_append_available(&self, available: bool) {
            self.append_available.store(available, Ordering::SeqCst);
        }

        fn set_observe_available(&self, available: bool) {
            self.observe_available.store(available, Ordering::SeqCst);
        }

        fn history(&self) -> Result<WitnessHistory, WitnessEndpointError> {
            let records = self
                .records
                .lock()
                .map_err(|_| WitnessEndpointError::Unavailable)?
                .clone();
            WitnessHistory::verify(&self.trust, records)
                .map_err(WitnessEndpointError::Rejected)
        }
    }

    impl WitnessEndpoint for MemoryWitness {
        fn witness_key_id(&self) -> [u8; 32] {
            TrustedWitnessForSpike::from_public_key(self.key.verifying_key().to_bytes()).key_id
        }

        fn append(
            &self,
            signed: SignedAppend,
            now_ms: u64,
        ) -> Result<(), WitnessEndpointError> {
            if !self.append_available.load(Ordering::SeqCst) {
                return Err(WitnessEndpointError::Unavailable);
            }
            if !self.trust.valid_at(now_ms) {
                return Err(WitnessEndpointError::Rejected(AppendError::Expired));
            }
            signed
                .verify_history(&self.trust)
                .map_err(WitnessEndpointError::Rejected)?;
            if signed.request.issued_at_ms > now_ms || now_ms >= signed.request.expires_at_ms {
                return Err(WitnessEndpointError::Rejected(AppendError::Expired));
            }

            let mut records = self
                .records
                .lock()
                .map_err(|_| WitnessEndpointError::Unavailable)?;
            let history = WitnessHistory::verify(&self.trust, records.clone())
                .map_err(WitnessEndpointError::Rejected)?;
            let index = signed.request.expected_generation as usize;
            if let Some(existing) = records.get(index) {
                return if *existing == signed {
                    Ok(())
                } else {
                    Err(WitnessEndpointError::Rejected(AppendError::Conflict))
                };
            }
            if signed.request.expected_generation != history.high_water().sequence
                || signed.request.previous_head != history.high_water().policy_head
            {
                return Err(WitnessEndpointError::Rejected(AppendError::Conflict));
            }
            records.push(signed);
            WitnessHistory::verify(&self.trust, records.clone())
                .map_err(WitnessEndpointError::Rejected)?;
            Ok(())
        }

        fn observe(
            &self,
            challenge: QuorumChallenge,
            now_ms: u64,
        ) -> Result<SignedQuorumObservation, WitnessEndpointError> {
            if !self.observe_available.load(Ordering::SeqCst) || !self.trust.valid_at(now_ms) {
                return Err(WitnessEndpointError::Unavailable);
            }
            if challenge.nonce == [0; 32]
                || challenge.expected_space != self.trust.space()
                || challenge.expected_resource != self.trust.resource()
                || challenge.expected_writer_epoch != self.trust.writer_epoch()
            {
                return Err(WitnessEndpointError::Rejected(AppendError::WrongTrust));
            }
            let high_water = self.history()?.high_water();
            let observation = QuorumObservation {
                challenge,
                generation: high_water.sequence,
                high_water,
            };
            Ok(SignedQuorumObservation {
                witness_key_id: self.witness_key_id(),
                observation,
                signature: self
                    .key
                    .sign(&quorum_observation_transcript(&observation))
                    .to_bytes(),
            })
        }
    }

    fn fixture() -> (
        VerifiedResourceTrust,
        SigningKey,
        MemoryWitness,
        MemoryWitness,
    ) {
        let root = SigningKey::from_bytes(&[30; 32]);
        let owner = SigningKey::from_bytes(&[11; 32]);
        let first_key = SigningKey::from_bytes(&[21; 32]);
        let second_key = SigningKey::from_bytes(&[22; 32]);
        let root_pin = ExternallyPinnedRootForSpike {
            space: SpaceId::from_bytes([1; 16]),
            public_key: root.verifying_key().to_bytes(),
            key_epoch: 7,
        };
        let manifest = ResourceTrustManifest {
            space: root_pin.space,
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner.verifying_key().to_bytes(),
            owner_key_epoch: 3,
            witness_public_keys: [
                first_key.verifying_key().to_bytes(),
                second_key.verifying_key().to_bytes(),
            ],
            writer_epoch: 1,
            root_key_epoch: 7,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let signed_trust = SignedResourceTrust {
            manifest,
            signature: root.sign(&trust_manifest_transcript(&manifest)).to_bytes(),
        };
        let trust = verify_resource_trust_for_spike(&root_pin, &signed_trust, 150).unwrap();
        (
            trust,
            owner,
            MemoryWitness::new(first_key, trust),
            MemoryWitness::new(second_key, trust),
        )
    }

    fn genesis(trust: &VerifiedResourceTrust) -> QuorumHighWater {
        QuorumHighWater {
            space: trust.space(),
            resource: trust.resource(),
            writer_epoch: trust.writer_epoch(),
            sequence: 0,
            policy_head: [0; 32],
            revocation_root: [0; 32],
        }
    }

    fn challenge(trust: &VerifiedResourceTrust, nonce: u8) -> QuorumChallenge {
        QuorumChallenge {
            nonce: [nonce; 32],
            expected_space: trust.space(),
            expected_resource: trust.resource(),
            expected_writer_epoch: trust.writer_epoch(),
        }
    }

    fn signed_append(
        trust: &VerifiedResourceTrust,
        owner: &SigningKey,
        current: QuorumHighWater,
        peer_byte: u8,
        allow: bool,
    ) -> SignedAppend {
        let request = AppendRequest {
            manifest: trust.manifest_commitment(),
            expected_generation: current.sequence,
            previous_head: current.policy_head,
            mutation: ReadMutation {
                peer: PeerId::from_digest([peer_byte; 32]),
                key_epoch: 1,
                member_epoch: 1,
                allow,
            },
            issued_at_ms: 120,
            expires_at_ms: 250,
        };
        SignedAppend {
            request,
            owner_signature: owner.sign(&append_transcript(&request)).to_bytes(),
        }
    }

    #[test]
    fn both_witnesses_commit_and_fresh_read_confirms_exact_state() {
        let (trust, owner, first, second) = fixture();
        let client = WitnessQuorumClient::new(trust, &first, &second).unwrap();
        let current = genesis(&trust);
        let signed = signed_append(&trust, &owner, current, 41, true);
        let next = client
            .append_and_confirm(signed, current, challenge(&trust, 1), 150)
            .unwrap();
        assert_eq!(next.sequence, 1);
        let verified = client
            .observe_latest(challenge(&trust, 2), 1, next, 150)
            .unwrap();
        assert_eq!(verified.high_water(), next);
    }

    #[test]
    fn partial_commit_is_not_acknowledged_and_exact_retry_converges() {
        let (trust, owner, first, second) = fixture();
        let client = WitnessQuorumClient::new(trust, &first, &second).unwrap();
        let genesis = genesis(&trust);
        let first_event = signed_append(&trust, &owner, genesis, 41, true);
        let current = client
            .append_and_confirm(first_event, genesis, challenge(&trust, 3), 150)
            .unwrap();

        let second_event = signed_append(&trust, &owner, current, 42, false);
        second.set_append_available(false);
        assert_eq!(
            client.append_and_confirm(second_event, current, challenge(&trust, 4), 150),
            Err(WitnessClientError::PartialCommitOrDivergence)
        );

        // The first Witness already committed. Retrying the SAME signed bytes
        // is idempotent there and advances the second Witness to the same head.
        second.set_append_available(true);
        let next = client
            .append_and_confirm(second_event, current, challenge(&trust, 5), 150)
            .unwrap();
        assert_eq!(next.sequence, 2);
        assert_ne!(next.revocation_root, current.revocation_root);
    }

    #[test]
    fn divergent_owner_signed_histories_are_never_selected_automatically() {
        let (trust, owner, first, second) = fixture();
        let client = WitnessQuorumClient::new(trust, &first, &second).unwrap();
        let genesis = genesis(&trust);
        let seed = signed_append(&trust, &owner, genesis, 41, true);
        let current = client
            .append_and_confirm(seed, genesis, challenge(&trust, 6), 150)
            .unwrap();

        let branch_a = signed_append(&trust, &owner, current, 42, false);
        let branch_b = signed_append(&trust, &owner, current, 43, false);
        first.append(branch_a, 150).unwrap();
        second.append(branch_b, 150).unwrap();
        assert_eq!(
            client.observe_latest(challenge(&trust, 7), 1, current, 150),
            Err(WitnessClientError::Quorum(QuorumError::SplitWitnesses))
        );
    }

    #[test]
    fn endpoint_order_and_identity_must_match_root_pins() {
        let (trust, _owner, first, second) = fixture();
        assert!(matches!(
            WitnessQuorumClient::new(trust, &first, &first),
            Err(WitnessClientError::WrongWitnessEndpoints)
        ));
        assert!(matches!(
            WitnessQuorumClient::new(trust, &second, &first),
            Err(WitnessClientError::WrongWitnessEndpoints)
        ));
    }

    #[test]
    fn offline_observation_never_degrades_to_single_witness_allow() {
        let (trust, _owner, first, second) = fixture();
        let client = WitnessQuorumClient::new(trust, &first, &second).unwrap();
        second.set_observe_available(false);
        let current = genesis(&trust);
        assert_eq!(
            client.observe_latest(challenge(&trust, 8), 0, current, 150),
            Err(WitnessClientError::WitnessUnavailable)
        );
    }
}
