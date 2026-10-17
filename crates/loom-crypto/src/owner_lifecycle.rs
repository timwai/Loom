//! Ordered, resource-scoped Owner policy transitions (L-001H PoC).
//! This is an in-memory verifier; it does NOT replace persistent SQLite/Root
//! history, external high-water, reliable distribution or production ServiceOpen.
//!
//! A delegate cancellation consumes a resource policy sequence number.
//! Consequently a later revocation signed under that key cannot be made valid
//! by backdating its wall-clock timestamp or replaying an earlier grant.

use std::collections::HashSet;
use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::{ResourceId, SpaceId};
use sha2::{Digest, Sha256};

use crate::owner_authority::{
    OwnerVerifiedRevocation, ProvisionedOwnerForSpike,
    replay_persisted_owner_revocation_for_spike,
};
use crate::space_trust::VerifiedResourceTrust;

const CANCEL_DOMAIN: &[u8] = b"LOOM:DELEGATE-CANCEL:V1\0";
const TRANSFER_DOMAIN: &[u8] = b"LOOM:OWNER-TRANSFER:V1\0";
const POLICY_CHAIN_DOMAIN: &[u8] = b"LOOM:RESOURCE-POLICY-CHAIN:V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegateCancellation {
    pub space: SpaceId,
    pub resource: ResourceId,
    pub owner_public_key: [u8; 32],
    pub owner_epoch: u64,
    pub delegate_key_id: [u8; 32],
    pub delegate_epoch: u64,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SignedDelegateCancellation {
    pub cancellation: DelegateCancellation,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerTransfer {
    pub space: SpaceId,
    pub resource: ResourceId,
    pub prior_manifest: [u8; 32],
    pub successor_manifest: [u8; 32],
    pub previous_owner_public_key: [u8; 32],
    pub successor_owner_public_key: [u8; 32],
    pub previous_owner_epoch: u64,
    pub successor_owner_epoch: u64,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct DualSignedOwnerTransfer {
    pub transfer: OwnerTransfer,
    pub old_owner_signature: [u8; 64],
    pub next_owner_signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    StaleOrOutOfOrder,
    ScopeMismatch,
    OwnerNotCurrent,
    DelegationCanceled,
    InvalidDelegate,
    InvalidTime,
    InvalidOwnerSignature,
    InvalidSuccessorSignature,
    UntrustedSuccessorManifest,
    InvalidEvidence,
    SequenceOverflow,
}

pub fn cancellation_transcript(c: &DelegateCancellation) -> Vec<u8> {
    let mut result = Vec::with_capacity(180);
    result.extend_from_slice(CANCEL_DOMAIN);
    result.extend_from_slice(c.space.as_bytes());
    result.extend_from_slice(c.resource.as_bytes());
    result.extend_from_slice(&c.owner_public_key);
    result.extend_from_slice(&c.owner_epoch.to_be_bytes());
    result.extend_from_slice(&c.delegate_key_id);
    result.extend_from_slice(&c.delegate_epoch.to_be_bytes());
    result.extend_from_slice(&c.sequence.to_be_bytes());
    result.extend_from_slice(&c.issued_at_ms.to_be_bytes());
    result.extend_from_slice(&c.expires_at_ms.to_be_bytes());
    result
}

pub fn owner_transfer_transcript(t: &OwnerTransfer) -> Vec<u8> {
    let mut result = Vec::with_capacity(256);
    result.extend_from_slice(TRANSFER_DOMAIN);
    result.extend_from_slice(t.space.as_bytes());
    result.extend_from_slice(t.resource.as_bytes());
    result.extend_from_slice(&t.prior_manifest);
    result.extend_from_slice(&t.successor_manifest);
    result.extend_from_slice(&t.previous_owner_public_key);
    result.extend_from_slice(&t.successor_owner_public_key);
    result.extend_from_slice(&t.previous_owner_epoch.to_be_bytes());
    result.extend_from_slice(&t.successor_owner_epoch.to_be_bytes());
    result.extend_from_slice(&t.sequence.to_be_bytes());
    result.extend_from_slice(&t.issued_at_ms.to_be_bytes());
    result.extend_from_slice(&t.expires_at_ms.to_be_bytes());
    result
}

fn valid_time(issued: u64, expires: u64, now: u64) -> bool {
    issued <= now && now < expires && issued < expires
}

fn check_signature(
    key: [u8; 32],
    signed: &[u8],
    signature: &[u8; 64],
) -> bool {
    VerifyingKey::from_bytes(&key).is_ok_and(|verifier| {
        verifier.verify_strict(signed, &Signature::from_bytes(signature)).is_ok()
    })
}

/// A deterministic policy chain head across *both* resource revocations and
/// Owner controls. This is intentionally a new candidate chain domain; it is
/// not interchangeable with the earlier revocation-only SQLite root.
fn append_policy_head(
    previous: [u8; 32],
    sequence: u64,
    evidence: &[u8],
) -> Result<[u8; 32], LifecycleError> {
    let len = u32::try_from(evidence.len()).map_err(|_| LifecycleError::InvalidEvidence)?;
    if evidence.is_empty() || evidence.len() > 64 * 1024 || sequence == 0 {
        return Err(LifecycleError::InvalidEvidence);
    }
    let mut hash = Sha256::new();
    hash.update(POLICY_CHAIN_DOMAIN);
    hash.update(previous);
    hash.update(sequence.to_be_bytes());
    hash.update(len.to_be_bytes());
    hash.update(evidence);
    Ok(hash.finalize().into())
}

/// A historical, scoped *verification* state, not a runtime access token.
///
/// Construction starts from sequence zero. Restored state MUST replay every
/// linked event from genesis and check externally trusted high-water; a caller
/// cannot import an arbitrary current cursor or a bitmap of canceled keys.
pub struct ResourceOwnerLifecycle {
    trust: VerifiedResourceTrust,
    sequence: u64,
    policy_head: [u8; 32],
    canceled: HashSet<([u8; 32], u64)>,
}

impl ResourceOwnerLifecycle {
    pub fn from_genesis(trust: VerifiedResourceTrust) -> Self {
        Self {
            trust,
            sequence: 0,
            policy_head: [0; 32],
            canceled: HashSet::new(),
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn policy_head(&self) -> [u8; 32] {
        self.policy_head
    }

    pub fn current_owner(&self) -> ProvisionedOwnerForSpike {
        self.trust.owner()
    }

    fn next_sequence(&self, candidate: u64) -> Result<(), LifecycleError> {
        if self.sequence.checked_add(1) != Some(candidate) {
            return Err(LifecycleError::StaleOrOutOfOrder);
        }
        Ok(())
    }

    fn record(&mut self, sequence: u64, evidence: &[u8]) -> Result<(), LifecycleError> {
        self.next_sequence(sequence)?;
        let head = append_policy_head(self.policy_head, sequence, evidence)?;
        self.sequence = sequence;
        self.policy_head = head;
        Ok(())
    }

    /// Re-verifies both signatures against the **currently** Root-authorized
    /// Owner before applying this resource revocation. A revoked delegate
    /// cannot produce an accepted *later* event even if its original Owner
    /// grant was legitimate and the payload timestamp was backdated.
    pub fn apply_delegated_revocation(
        &mut self,
        proof: &OwnerVerifiedRevocation,
    ) -> Result<(), LifecycleError> {
        self.next_sequence(proof.seq())?;
        let evidence = proof.persistence_bytes();
        replay_persisted_owner_revocation_for_spike(&self.trust.owner(), &evidence)
            .map_err(|_| LifecycleError::InvalidEvidence)?;
        let (delegate_id, epoch) = proof
            .delegated_identity()
            .map_err(|_| LifecycleError::InvalidDelegate)?;
        if self.canceled.contains(&(delegate_id, epoch)) {
            return Err(LifecycleError::DelegationCanceled);
        }
        self.record(proof.seq(), &evidence)
    }

    pub fn cancel_delegate(
        &mut self,
        signed: &SignedDelegateCancellation,
        now_ms: u64,
    ) -> Result<(), LifecycleError> {
        let c = signed.cancellation;
        self.next_sequence(c.sequence)?;
        let current = self.trust.owner();
        if c.space != current.space_id || c.resource != current.resource_id {
            return Err(LifecycleError::ScopeMismatch);
        }
        if c.owner_public_key != current.public_key
            || c.owner_epoch != current.current_key_epoch
        {
            return Err(LifecycleError::OwnerNotCurrent);
        }
        if c.delegate_epoch == 0 || c.delegate_key_id == [0; 32] {
            return Err(LifecycleError::InvalidDelegate);
        }
        if !valid_time(c.issued_at_ms, c.expires_at_ms, now_ms)
            || !self.trust.valid_at(now_ms)
        {
            return Err(LifecycleError::InvalidTime);
        }
        let transcript = cancellation_transcript(&c);
        if !check_signature(current.public_key, &transcript, &signed.signature) {
            return Err(LifecycleError::InvalidOwnerSignature);
        }
        if self.canceled.contains(&(c.delegate_key_id, c.delegate_epoch)) {
            return Err(LifecycleError::DelegationCanceled);
        }
        let mut evidence = transcript;
        evidence.extend_from_slice(&signed.signature);
        // Validate and hash everything first, then mutate both state fields.
        let next_head = append_policy_head(self.policy_head, c.sequence, &evidence)?;
        self.canceled.insert((c.delegate_key_id, c.delegate_epoch));
        self.sequence = c.sequence;
        self.policy_head = next_head;
        Ok(())
    }

    /// A transfer requires: (a) current Owner, (b) successor Owner's consent,
    /// (c) a separately verified Root-signed successor resource manifest.
    /// Any existing delegate is invalidated on transfer, regardless of timing.
    /// This does NOT commit a corresponding external manifest/high-water CAS.
    pub fn transfer_owner(
        &mut self,
        signed: &DualSignedOwnerTransfer,
        successor: VerifiedResourceTrust,
        now_ms: u64,
    ) -> Result<(), LifecycleError> {
        let t = signed.transfer;
        self.next_sequence(t.sequence)?;
        let current = self.trust.owner();
        let next_owner = successor.owner();
        if t.space != current.space_id
            || t.resource != current.resource_id
            || successor.space() != self.trust.space()
            || successor.resource() != self.trust.resource()
        {
            return Err(LifecycleError::ScopeMismatch);
        }
        if successor.root_public_key() != self.trust.root_public_key()
            || successor.root_key_epoch() != self.trust.root_key_epoch()
            || successor.writer_epoch() != self.trust.writer_epoch()
        {
            return Err(LifecycleError::UntrustedSuccessorManifest);
        }
        if t.prior_manifest != self.trust.manifest_commitment()
            || t.successor_manifest != successor.manifest_commitment()
            || t.previous_owner_public_key != current.public_key
            || t.successor_owner_public_key != next_owner.public_key
        {
            return Err(LifecycleError::UntrustedSuccessorManifest);
        }
        if t.previous_owner_epoch != current.current_key_epoch
            || t.successor_owner_epoch != next_owner.current_key_epoch
            || t.previous_owner_epoch.checked_add(1) != Some(t.successor_owner_epoch)
            || t.previous_owner_public_key == t.successor_owner_public_key
        {
            return Err(LifecycleError::OwnerNotCurrent);
        }
        if !valid_time(t.issued_at_ms, t.expires_at_ms, now_ms)
            || !self.trust.valid_at(now_ms)
            || !successor.valid_at(now_ms)
        {
            return Err(LifecycleError::InvalidTime);
        }
        let transcript = owner_transfer_transcript(&t);
        if !check_signature(current.public_key, &transcript, &signed.old_owner_signature) {
            return Err(LifecycleError::InvalidOwnerSignature);
        }
        if !check_signature(next_owner.public_key, &transcript, &signed.next_owner_signature) {
            return Err(LifecycleError::InvalidSuccessorSignature);
        }
        let mut evidence = transcript;
        evidence.extend_from_slice(&signed.old_owner_signature);
        evidence.extend_from_slice(&signed.next_owner_signature);
        let head = append_policy_head(self.policy_head, t.sequence, &evidence)?;
        self.trust = successor;
        self.canceled.clear(); // Old Owner grants fail their signature check.
        self.sequence = t.sequence;
        self.policy_head = head;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_wire::security_event::{
        CanonicalSecurityEvent, EventKind, encode_security_event, signing_input,
    };
    use crate::owner_authority::{issuer_key_id, verify_owner_delegated_revocation_for_spike};
    use crate::space_trust::{
        ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
        trust_manifest_transcript, verify_resource_trust_for_spike,
    };

    fn trust(owner_seed: u8, owner_epoch: u64) -> VerifiedResourceTrust {
        let root = SigningKey::from_bytes(&[30; 32]);
        let owner = SigningKey::from_bytes(&[owner_seed; 32]);
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
            owner_key_epoch: owner_epoch,
            witness_public_keys: [
                witness_a.verifying_key().to_bytes(),
                witness_b.verifying_key().to_bytes(),
            ],
            writer_epoch: 1,
            root_key_epoch: pin.key_epoch,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let signed = SignedResourceTrust {
            manifest,
            signature: root.sign(&trust_manifest_transcript(&manifest)).to_bytes(),
        };
        verify_resource_trust_for_spike(&pin, &signed, 150).unwrap()
    }

    fn delegate_proof(
        owner_seed: u8,
        owner_epoch: u64,
        delegate_seed: u8,
        resource_seq: u64,
    ) -> OwnerVerifiedRevocation {
        let owner = SigningKey::from_bytes(&[owner_seed; 32]);
        let delegate = SigningKey::from_bytes(&[delegate_seed; 32]);
        let delegate_pub = delegate.verifying_key().to_bytes();
        let space = SpaceId::from_bytes([1; 16]);
        let resource = ResourceId::from_bytes([2; 16]);
        let mut grant_payload = resource.as_bytes().to_vec();
        grant_payload.extend_from_slice(&delegate_pub);
        grant_payload.extend_from_slice(&issuer_key_id(&delegate_pub));
        grant_payload.push(1);
        grant_payload.extend_from_slice(&4u64.to_be_bytes());
        let grant = CanonicalSecurityEvent {
            kind: EventKind::OwnerGrant,
            space_id: *space.as_bytes(),
            signer_key_id: issuer_key_id(&owner.verifying_key().to_bytes()),
            issuer_epoch: owner_epoch,
            issued_at_ms: 100,
            expires_at_ms: 300,
            seq: 1,
            payload: grant_payload,
        };
        let mut revoke_payload = resource.as_bytes().to_vec();
        revoke_payload.extend_from_slice(&[5; 32]);
        revoke_payload.push(3);
        let revoke = CanonicalSecurityEvent {
            kind: EventKind::Revocation,
            space_id: *space.as_bytes(),
            signer_key_id: issuer_key_id(&delegate_pub),
            issuer_epoch: 4,
            issued_at_ms: 120,
            expires_at_ms: 250,
            seq: resource_seq,
            payload: revoke_payload,
        };
        let grant_cbor = encode_security_event(&grant).unwrap();
        let revoke_cbor = encode_security_event(&revoke).unwrap();
        let gs = owner.sign(&signing_input(&grant_cbor).unwrap()).to_bytes();
        let rs = delegate.sign(&signing_input(&revoke_cbor).unwrap()).to_bytes();
        verify_owner_delegated_revocation_for_spike(
            &ProvisionedOwnerForSpike {
                space_id: space,
                resource_id: resource,
                public_key: owner.verifying_key().to_bytes(),
                current_key_epoch: owner_epoch,
            },
            &grant_cbor,
            &gs,
            &revoke_cbor,
            &rs,
            150,
        )
        .unwrap()
    }

    fn canceled(seed: u8, sequence: u64) -> SignedDelegateCancellation {
        let owner = SigningKey::from_bytes(&[11; 32]);
        let delegate = SigningKey::from_bytes(&[seed; 32]);
        let c = DelegateCancellation {
            space: SpaceId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner.verifying_key().to_bytes(),
            owner_epoch: 3,
            delegate_key_id: issuer_key_id(&delegate.verifying_key().to_bytes()),
            delegate_epoch: 4,
            sequence,
            issued_at_ms: 120,
            expires_at_ms: 250,
        };
        SignedDelegateCancellation {
            cancellation: c,
            signature: owner.sign(&cancellation_transcript(&c)).to_bytes(),
        }
    }

    fn transfer(
        old: &VerifiedResourceTrust,
        new: &VerifiedResourceTrust,
        sequence: u64,
    ) -> DualSignedOwnerTransfer {
        let old_key = SigningKey::from_bytes(&[11; 32]);
        let new_key = SigningKey::from_bytes(&[33; 32]);
        let t = OwnerTransfer {
            space: old.space(),
            resource: old.resource(),
            prior_manifest: old.manifest_commitment(),
            successor_manifest: new.manifest_commitment(),
            previous_owner_public_key: old.owner().public_key,
            successor_owner_public_key: new.owner().public_key,
            previous_owner_epoch: old.owner().current_key_epoch,
            successor_owner_epoch: new.owner().current_key_epoch,
            sequence,
            issued_at_ms: 120,
            expires_at_ms: 250,
        };
        let bytes = owner_transfer_transcript(&t);
        DualSignedOwnerTransfer {
            transfer: t,
            old_owner_signature: old_key.sign(&bytes).to_bytes(),
            next_owner_signature: new_key.sign(&bytes).to_bytes(),
        }
    }

    #[test]
    fn cancellation_consumes_sequence_and_blocks_backdated_valid_signature() {
        let mut state = ResourceOwnerLifecycle::from_genesis(trust(11, 3));
        state.apply_delegated_revocation(&delegate_proof(11, 3, 12, 1)).unwrap();
        let first_head = state.policy_head();
        state.cancel_delegate(&canceled(12, 2), 150).unwrap();
        assert_eq!(state.sequence(), 2);
        assert_ne!(state.policy_head(), first_head);
        assert_eq!(
            state.apply_delegated_revocation(&delegate_proof(11, 3, 12, 3)),
            Err(LifecycleError::DelegationCanceled)
        );
        assert_eq!(state.sequence(), 2);
        assert_eq!(
            state.apply_delegated_revocation(&delegate_proof(11, 3, 12, 1)),
            Err(LifecycleError::StaleOrOutOfOrder)
        );
    }

    #[test]
    fn other_valid_delegate_can_still_revoke_after_cancel() {
        let mut state = ResourceOwnerLifecycle::from_genesis(trust(11, 3));
        state.apply_delegated_revocation(&delegate_proof(11, 3, 12, 1)).unwrap();
        state.cancel_delegate(&canceled(12, 2), 150).unwrap();
        state.apply_delegated_revocation(&delegate_proof(11, 3, 13, 3)).unwrap();
        assert_eq!(state.sequence(), 3);
    }

    #[test]
    fn forged_cancellation_wrong_scope_epoch_and_duplicate_rejected() {
        let mut state = ResourceOwnerLifecycle::from_genesis(trust(11, 3));
        let mut bad = canceled(12, 1);
        bad.signature[0] ^= 1;
        assert_eq!(state.cancel_delegate(&bad, 150), Err(LifecycleError::InvalidOwnerSignature));
        let mut bad = canceled(12, 1);
        bad.cancellation.resource = ResourceId::from_bytes([8; 16]);
        assert_eq!(state.cancel_delegate(&bad, 150), Err(LifecycleError::ScopeMismatch));
        let mut bad = canceled(12, 1);
        bad.cancellation.owner_epoch = 2;
        assert_eq!(state.cancel_delegate(&bad, 150), Err(LifecycleError::OwnerNotCurrent));
        let mut bad = canceled(12, 2);
        assert_eq!(state.cancel_delegate(&bad, 150), Err(LifecycleError::StaleOrOutOfOrder));
        state.cancel_delegate(&canceled(12, 1), 150).unwrap();
        bad = canceled(12, 2);
        assert_eq!(state.cancel_delegate(&bad, 150), Err(LifecycleError::DelegationCanceled));
        assert_eq!(state.sequence(), 1);
    }

    #[test]
    fn owner_transfer_requires_both_owners_and_root_signed_successor_policy() {
        let prior = trust(11, 3);
        let successor = trust(33, 4);
        let signed = transfer(&prior, &successor, 1);
        let mut state = ResourceOwnerLifecycle::from_genesis(prior);
        state.transfer_owner(&signed, successor, 150).unwrap();
        assert_eq!(state.sequence(), 1);
        assert_eq!(state.current_owner().current_key_epoch, 4);
        assert_eq!(state.current_owner().public_key, SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes());
        assert_eq!(
            state.apply_delegated_revocation(&delegate_proof(11, 3, 12, 2)),
            Err(LifecycleError::InvalidEvidence)
        );
        state.apply_delegated_revocation(&delegate_proof(33, 4, 14, 2)).unwrap();
        assert_eq!(state.sequence(), 2);
    }

    #[test]
    fn forging_either_owner_signature_or_replaying_transfer_fails() {
        let prior = trust(11, 3);
        let successor = trust(33, 4);
        let mut bad = transfer(&prior, &successor, 1);
        bad.old_owner_signature[5] ^= 1;
        let mut state = ResourceOwnerLifecycle::from_genesis(prior);
        assert_eq!(
            state.transfer_owner(&bad, successor, 150),
            Err(LifecycleError::InvalidOwnerSignature)
        );
        let prior = trust(11, 3);
        let successor = trust(33, 4);
        let mut bad = transfer(&prior, &successor, 1);
        bad.next_owner_signature[5] ^= 1;
        let mut state = ResourceOwnerLifecycle::from_genesis(prior);
        assert_eq!(
            state.transfer_owner(&bad, successor, 150),
            Err(LifecycleError::InvalidSuccessorSignature)
        );
        state.transfer_owner(&transfer(&prior, &successor, 1), successor, 150).unwrap();
        assert_eq!(
            state.transfer_owner(&transfer(&prior, &successor, 1), successor, 150),
            Err(LifecycleError::StaleOrOutOfOrder)
        );
    }

    #[test]
    fn wrong_successor_epoch_and_manifest_detected() {
        let prior = trust(11, 3);
        let successor = trust(33, 4);
        let mut bad = transfer(&prior, &successor, 1);
        bad.transfer.successor_manifest = [7; 32];
        let mut state = ResourceOwnerLifecycle::from_genesis(prior);
        assert_eq!(
            state.transfer_owner(&bad, successor, 150),
            Err(LifecycleError::UntrustedSuccessorManifest)
        );
        let wrong_epoch = trust(33, 5);
        let mut state = ResourceOwnerLifecycle::from_genesis(trust(11, 3));
        let signed = transfer(&trust(11, 3), &wrong_epoch, 1);
        assert_eq!(
            state.transfer_owner(&signed, wrong_epoch, 150),
            Err(LifecycleError::OwnerNotCurrent)
        );
    }

    #[test]
    fn resource_policy_head_commits_to_control_and_data_order() {
        let mut first = ResourceOwnerLifecycle::from_genesis(trust(11, 3));
        let mut second = ResourceOwnerLifecycle::from_genesis(trust(11, 3));
        first.apply_delegated_revocation(&delegate_proof(11, 3, 12, 1)).unwrap();
        first.cancel_delegate(&canceled(13, 2), 150).unwrap();
        second.cancel_delegate(&canceled(13, 1), 150).unwrap();
        second.apply_delegated_revocation(&delegate_proof(11, 3, 12, 2)).unwrap();
        assert_ne!(first.policy_head(), second.policy_head());
    }
}
