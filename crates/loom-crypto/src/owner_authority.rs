//! Resource Owner -> signed revoke-only delegate -> signed revocation chain.
//!
//! SECURITY: the Owner anchor here is provisioned by a caller, not derived from
//! an authenticated Space genesis / witness. This is an isolated PoC and
//! NEVER creates a network permission or marks SQLite admission ready.

use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::{PeerId, ResourceId, SpaceId};
use loom_wire::security_event::{EventKind, decode_security_event, signing_input};
use sha2::{Digest, Sha256};

use crate::signed_revocation::{
    PinnedIssuerForSpike, VerifiedRevocation, VerifyEventError, verify_revocation_for_spike,
};

const KEY_ID_DOMAIN: &[u8] = b"LOOM:KEY-ID:V1\0";
const PROOF_DOMAIN: &[u8] = b"LOOM:OWNER-REVOKE-PROOF:V1\0";
const DELEGATION_LEN: usize = 89;
const REVOKE_ONLY: u8 = 1;

/// All values must be supplied from independently authenticated local Owner
/// provisioning. Creating this pin from a received network field is unsafe.
#[derive(Clone, Copy, Debug)]
pub struct ProvisionedOwnerForSpike {
    pub space_id: SpaceId,
    pub resource_id: ResourceId,
    pub public_key: [u8; 32],
    pub current_key_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerChainError {
    BadOwnerSignature,
    BadDelegation,
    ScopeMismatch,
    UnauthorizedOperation,
    DelegationExpired,
    StaleOwnerKey,
    WrongDelegate,
    BadRevocation(VerifyEventError),
    InvalidPersistenceEnvelope,
}

#[derive(Debug, Clone)]
pub struct OwnerVerifiedRevocation {
    revocation: VerifiedRevocation,
    signed_delegation: Vec<u8>,
    delegation_signature: [u8; 64],
}

impl OwnerVerifiedRevocation {
    pub fn resource_id(&self) -> ResourceId {
        self.revocation.resource_id()
    }

    pub fn space_id(&self) -> SpaceId {
        self.revocation.space_id()
    }

    pub fn seq(&self) -> u64 {
        self.revocation.seq()
    }

    pub fn revoked_peer(&self) -> PeerId {
        self.revocation.revoked_peer()
    }

    /// Replay-verifiable evidence: versioned domain, signed grant and signed
    /// revoke event. Replay still requires independently trusted Owner pin.
    pub fn persistence_bytes(&self) -> Vec<u8> {
        let revocation = self.revocation.persistence_bytes();
        let mut out = Vec::with_capacity(
            PROOF_DOMAIN.len() + 4 + self.signed_delegation.len() + 64 + revocation.len(),
        );
        out.extend_from_slice(PROOF_DOMAIN);
        out.extend_from_slice(&(self.signed_delegation.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.signed_delegation);
        out.extend_from_slice(&self.delegation_signature);
        out.extend_from_slice(&revocation);
        out
    }
}

/// Domain-separated key identifier for Ed25519 verification keys.
/// This is a candidate and cannot be silently substituted for PeerId.
pub fn issuer_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(KEY_ID_DOMAIN);
    hash.update(public_key);
    hash.finalize().into()
}

/// L-001D delegated OwnerGrant payload candidate:
/// resource_id[16] | delegated Ed25519 pubkey[32] | derived key-id[32] |
/// revoke_only[1] | delegated_key_epoch(u64BE).
///
/// The grant carries the Owner signer, scope and lifetime in the outer event.
/// The revocation is independently signed by the delegate, and may **only**
/// subtract access to the Owner's single resource.
pub fn verify_owner_delegated_revocation_for_spike(
    owner: &ProvisionedOwnerForSpike,
    delegation_cbor: &[u8],
    delegation_signature: &[u8],
    revoke_cbor: &[u8],
    revoke_signature: &[u8],
    now_ms: u64,
) -> Result<OwnerVerifiedRevocation, OwnerChainError> {
    if owner.current_key_epoch == 0 {
        return Err(OwnerChainError::StaleOwnerKey);
    }
    let event =
        decode_security_event(delegation_cbor).map_err(|_| OwnerChainError::BadDelegation)?;
    if event.kind != EventKind::OwnerGrant || event.seq == 0 {
        return Err(OwnerChainError::BadDelegation);
    }
    if event.space_id != *owner.space_id.as_bytes() {
        return Err(OwnerChainError::ScopeMismatch);
    }
    if event.issuer_epoch != owner.current_key_epoch {
        return Err(OwnerChainError::StaleOwnerKey);
    }
    if event.signer_key_id != issuer_key_id(&owner.public_key) {
        return Err(OwnerChainError::BadOwnerSignature);
    }
    if !(event.issued_at_ms <= now_ms && now_ms < event.expires_at_ms) {
        return Err(OwnerChainError::DelegationExpired);
    }
    let root_key = VerifyingKey::from_bytes(&owner.public_key)
        .map_err(|_| OwnerChainError::BadOwnerSignature)?;
    let root_signature = Signature::from_slice(delegation_signature)
        .map_err(|_| OwnerChainError::BadOwnerSignature)?;
    root_key
        .verify_strict(
            &signing_input(delegation_cbor).map_err(|_| OwnerChainError::BadDelegation)?,
            &root_signature,
        )
        .map_err(|_| OwnerChainError::BadOwnerSignature)?;

    if event.payload.len() != DELEGATION_LEN {
        return Err(OwnerChainError::BadDelegation);
    }
    if event.payload[..16] != owner.resource_id.as_bytes()[..] {
        return Err(OwnerChainError::ScopeMismatch);
    }
    let delegate_key: [u8; 32] = event.payload[16..48]
        .try_into()
        .map_err(|_| OwnerChainError::BadDelegation)?;
    let delegate_id: [u8; 32] = event.payload[48..80]
        .try_into()
        .map_err(|_| OwnerChainError::BadDelegation)?;
    if issuer_key_id(&delegate_key) != delegate_id {
        return Err(OwnerChainError::WrongDelegate);
    }
    if event.payload[80] != REVOKE_ONLY {
        return Err(OwnerChainError::UnauthorizedOperation);
    }
    let delegated_epoch = u64::from_be_bytes(
        event.payload[81..89]
            .try_into()
            .map_err(|_| OwnerChainError::BadDelegation)?,
    );
    if delegated_epoch == 0 {
        return Err(OwnerChainError::BadDelegation);
    }
    // A delegate's own signed proof is only trusted within the Owner-signed
    // scope/time/epoch; a valid signature from another key is never enough.
    let delegate = PinnedIssuerForSpike {
        key_id: delegate_id,
        public_key: delegate_key,
        space_id: owner.space_id,
        minimum_key_epoch: delegated_epoch,
    };
    let revoke_event = decode_security_event(revoke_cbor)
        .map_err(|_| OwnerChainError::BadRevocation(VerifyEventError::NonCanonical))?;
    if revoke_event.issuer_epoch != delegated_epoch {
        return Err(OwnerChainError::WrongDelegate);
    }
    if revoke_event.issued_at_ms < event.issued_at_ms
        || revoke_event.expires_at_ms > event.expires_at_ms
    {
        return Err(OwnerChainError::DelegationExpired);
    }
    let revocation = verify_revocation_for_spike(revoke_cbor, revoke_signature, &delegate, now_ms)
        .map_err(OwnerChainError::BadRevocation)?;
    if revocation.resource_id() != owner.resource_id {
        return Err(OwnerChainError::ScopeMismatch);
    }
    let delegation_signature: [u8; 64] = delegation_signature
        .try_into()
        .map_err(|_| OwnerChainError::BadOwnerSignature)?;
    Ok(OwnerVerifiedRevocation {
        revocation,
        signed_delegation: delegation_cbor.to_vec(),
        delegation_signature,
    })
}

/// Validate a saved two-signature Owner-grant / delegate-revocation envelope.
/// This checks historical issuance, NOT whether a delegated key was later
/// revoked. The owner key MUST come from authenticated *external* root policy.
pub fn replay_persisted_owner_revocation_for_spike(
    owner: &ProvisionedOwnerForSpike,
    saved: &[u8],
) -> Result<OwnerVerifiedRevocation, OwnerChainError> {
    if saved.len() > 64 * 1024 || !saved.starts_with(PROOF_DOMAIN) {
        return Err(OwnerChainError::InvalidPersistenceEnvelope);
    }
    let mut offset = PROOF_DOMAIN.len();
    fn field<'a>(
        bytes: &'a [u8],
        offset: &mut usize,
        length: usize,
    ) -> Result<&'a [u8], OwnerChainError> {
        let end = offset
            .checked_add(length)
            .ok_or(OwnerChainError::InvalidPersistenceEnvelope)?;
        let result = bytes
            .get(*offset..end)
            .ok_or(OwnerChainError::InvalidPersistenceEnvelope)?;
        *offset = end;
        Ok(result)
    }
    fn length(bytes: &[u8], offset: &mut usize) -> Result<usize, OwnerChainError> {
        let size: [u8; 4] = field(bytes, offset, 4)?
            .try_into()
            .map_err(|_| OwnerChainError::InvalidPersistenceEnvelope)?;
        Ok(u32::from_be_bytes(size) as usize)
    }
    let grant_len = length(saved, &mut offset)?;
    if grant_len > 60 * 1024 {
        return Err(OwnerChainError::InvalidPersistenceEnvelope);
    }
    let grant = field(saved, &mut offset, grant_len)?;
    let grant_sig = field(saved, &mut offset, 64)?;
    let revoke_len = length(saved, &mut offset)?;
    if revoke_len > 60 * 1024 {
        return Err(OwnerChainError::InvalidPersistenceEnvelope);
    }
    let revoke = field(saved, &mut offset, revoke_len)?;
    let revoke_sig = field(saved, &mut offset, 64)?;
    if offset != saved.len() {
        return Err(OwnerChainError::InvalidPersistenceEnvelope);
    }
    let event = decode_security_event(revoke)
        .map_err(|_| OwnerChainError::InvalidPersistenceEnvelope)?;
    let checked = verify_owner_delegated_revocation_for_spike(
        owner,
        grant,
        grant_sig,
        revoke,
        revoke_sig,
        event.issued_at_ms,
    )?;
    if checked.persistence_bytes() != saved {
        return Err(OwnerChainError::InvalidPersistenceEnvelope);
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_wire::security_event::{CanonicalSecurityEvent, encode_security_event};

    struct Fixture {
        owner: SigningKey,
        delegate: SigningKey,
        anchor: ProvisionedOwnerForSpike,
        grant: CanonicalSecurityEvent,
        revoke: CanonicalSecurityEvent,
    }

    impl Fixture {
        fn new() -> Self {
            let owner = SigningKey::from_bytes(&[11; 32]);
            let delegate = SigningKey::from_bytes(&[12; 32]);
            let resource_id = ResourceId::from_bytes([2; 16]);
            let space_id = SpaceId::from_bytes([1; 16]);
            let anchor = ProvisionedOwnerForSpike {
                space_id,
                resource_id,
                public_key: owner.verifying_key().to_bytes(),
                current_key_epoch: 3,
            };
            let delegate_pub = delegate.verifying_key().to_bytes();
            let mut delegation = resource_id.as_bytes().to_vec();
            delegation.extend_from_slice(&delegate_pub);
            delegation.extend_from_slice(&issuer_key_id(&delegate_pub));
            delegation.push(REVOKE_ONLY);
            delegation.extend_from_slice(&4u64.to_be_bytes());
            let grant = CanonicalSecurityEvent {
                kind: EventKind::OwnerGrant,
                space_id: *space_id.as_bytes(),
                signer_key_id: issuer_key_id(&anchor.public_key),
                issuer_epoch: 3,
                issued_at_ms: 100,
                expires_at_ms: 300,
                seq: 1,
                payload: delegation,
            };
            let mut payload = resource_id.as_bytes().to_vec();
            payload.extend_from_slice(&[5; 32]);
            payload.push(3);
            let revoke = CanonicalSecurityEvent {
                kind: EventKind::Revocation,
                space_id: *space_id.as_bytes(),
                signer_key_id: issuer_key_id(&delegate_pub),
                issuer_epoch: 4,
                issued_at_ms: 120,
                expires_at_ms: 260,
                seq: 1,
                payload,
            };
            Self {
                owner,
                delegate,
                anchor,
                grant,
                revoke,
            }
        }

        fn signed(&self) -> (Vec<u8>, [u8; 64], Vec<u8>, [u8; 64]) {
            let grant = encode_security_event(&self.grant).unwrap();
            let revoke = encode_security_event(&self.revoke).unwrap();
            let gs = self.owner.sign(&signing_input(&grant).unwrap()).to_bytes();
            let rs = self
                .delegate
                .sign(&signing_input(&revoke).unwrap())
                .to_bytes();
            (grant, gs, revoke, rs)
        }

        fn verify(&self) -> Result<OwnerVerifiedRevocation, OwnerChainError> {
            let (grant, gs, revoke, rs) = self.signed();
            verify_owner_delegated_revocation_for_spike(
                &self.anchor,
                &grant,
                &gs,
                &revoke,
                &rs,
                150,
            )
        }
    }

    #[test]
    fn owner_signed_revoke_only_chain_and_persisted_evidence() {
        let proof = Fixture::new().verify().unwrap();
        assert_eq!(proof.resource_id(), ResourceId::from_bytes([2; 16]));
        assert_eq!(proof.space_id(), SpaceId::from_bytes([1; 16]));
        assert_eq!(proof.revoked_peer(), PeerId::from_digest([5; 32]));
        assert_eq!(proof.seq(), 1);
        assert!(proof.persistence_bytes().starts_with(PROOF_DOMAIN));
        assert!(proof.persistence_bytes().len() > 300);
    }

    #[test]
    fn cannot_forge_owner_or_delegate() {
        let mut fixture = Fixture::new();
        let (grant, mut gs, revoke, rs) = fixture.signed();
        gs[1] ^= 1;
        assert_eq!(
            verify_owner_delegated_revocation_for_spike(
                &fixture.anchor,
                &grant,
                &gs,
                &revoke,
                &rs,
                150,
            )
            .unwrap_err(),
            OwnerChainError::BadOwnerSignature
        );
        fixture.delegate = SigningKey::from_bytes(&[13; 32]);
        assert!(fixture.verify().is_err());
    }

    #[test]
    fn cannot_increase_delegation_rights_or_cross_resource() {
        let mut fixture = Fixture::new();
        fixture.grant.payload[80] = 2;
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::UnauthorizedOperation
        );
        let mut fixture = Fixture::new();
        fixture.revoke.payload[..16].copy_from_slice(&[8; 16]);
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::ScopeMismatch
        );
        let mut fixture = Fixture::new();
        fixture.anchor.resource_id = ResourceId::from_bytes([9; 16]);
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::ScopeMismatch
        );
    }

    #[test]
    fn reject_expiry_owner_epoch_and_delegated_key_epoch() {
        let fixture = Fixture::new();
        let (grant, gs, revoke, rs) = fixture.signed();
        assert_eq!(
            verify_owner_delegated_revocation_for_spike(
                &fixture.anchor,
                &grant,
                &gs,
                &revoke,
                &rs,
                301,
            )
            .unwrap_err(),
            OwnerChainError::DelegationExpired
        );
        let mut old_owner = fixture.anchor;
        old_owner.current_key_epoch = 4;
        assert_eq!(
            verify_owner_delegated_revocation_for_spike(
                &old_owner, &grant, &gs, &revoke, &rs, 150,
            )
            .unwrap_err(),
            OwnerChainError::StaleOwnerKey
        );
        let mut fixture = Fixture::new();
        fixture.revoke.issuer_epoch = 5;
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::WrongDelegate
        );
        let mut fixture = Fixture::new();
        fixture.revoke.expires_at_ms = 400;
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::DelegationExpired
        );
    }

    #[test]
    fn grant_not_signed_for_different_space_or_key_id() {
        let mut fixture = Fixture::new();
        fixture.grant.space_id = [3; 16];
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::ScopeMismatch
        );
        let mut fixture = Fixture::new();
        fixture.grant.signer_key_id = [6; 32];
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::BadOwnerSignature
        );
        let mut fixture = Fixture::new();
        fixture.grant.payload[48] ^= 1;
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::WrongDelegate
        );
    }

    #[test]
    fn no_replay_as_different_event_type() {
        let mut fixture = Fixture::new();
        fixture.grant.kind = EventKind::MembershipGrant;
        assert_eq!(
            fixture.verify().unwrap_err(),
            OwnerChainError::BadDelegation
        );
        let mut fixture = Fixture::new();
        fixture.revoke.kind = EventKind::OwnerGrant;
        assert!(matches!(
            fixture.verify(),
            Err(OwnerChainError::BadRevocation(
                VerifyEventError::WrongEventKind
            ))
        ));
    }

    #[test]
    fn saved_owner_delegation_replays_with_both_signatures() {
        let fixture = Fixture::new();
        let persisted = fixture.verify().unwrap().persistence_bytes();
        let replay = replay_persisted_owner_revocation_for_spike(&fixture.anchor, &persisted)
            .unwrap();
        assert_eq!(replay.resource_id(), fixture.anchor.resource_id);
        assert_eq!(replay.seq(), 1);
        assert_eq!(replay.persistence_bytes(), persisted);
    }

    #[test]
    fn saved_envelope_rejects_truncation_suffix_and_forged_grant() {
        let fixture = Fixture::new();
        let saved = fixture.verify().unwrap().persistence_bytes();
        for cut in 0..saved.len() {
            assert!(replay_persisted_owner_revocation_for_spike(
                &fixture.anchor, &saved[..cut],
            ).is_err());
        }
        let mut trailing = saved.clone();
        trailing.push(0);
        assert_eq!(
            replay_persisted_owner_revocation_for_spike(&fixture.anchor, &trailing)
                .unwrap_err(),
            OwnerChainError::InvalidPersistenceEnvelope
        );
        let mut wrong = saved;
        let start = PROOF_DOMAIN.len() + 4;
        wrong[start + 5] ^= 1;
        assert!(replay_persisted_owner_revocation_for_spike(&fixture.anchor, &wrong).is_err());
        let mut wrong_owner = fixture.anchor;
        wrong_owner.public_key = SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes();
        assert!(replay_persisted_owner_revocation_for_spike(
            &wrong_owner,
            &fixture.verify().unwrap().persistence_bytes(),
        ).is_err());
    }

}
