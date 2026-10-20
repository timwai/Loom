//! Candidate OwnerGrant verifier: Root-bound Owner plus signed membership.
//! Exact current policy sequence is supplied externally. A verified grant is
//! NOT an AdmissionPermit; durable revocation/rollback/session barriers are
//! still required before any production resource operation.
use crate::{
    membership::VerifiedMembership, owner_authority::issuer_key_id,
    space_trust::VerifiedResourceTrust,
};
use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::{Action, PeerId, ResourceId, SpaceId};
use loom_wire::security_event::{EventKind, decode_security_event, signing_input};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantError {
    InvalidTrust,
    InvalidScope,
    InvalidSubject,
    InvalidEpoch,
    InvalidSequence,
    InvalidTime,
    InvalidPayload,
    InvalidSignature,
    WrongKind,
    NonCanonical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedOwnerGrant {
    space: SpaceId,
    resource: ResourceId,
    peer: PeerId,
    key_epoch: u64,
    member_epoch: u64,
    actions: u8,
    sequence: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
}
impl VerifiedOwnerGrant {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn subject_epochs(&self) -> (u64, u64) {
        (self.key_epoch, self.member_epoch)
    }
    /// Field matching only; this does not consult a revocation journal, perform
    /// an atomic ServiceOpen or establish fresh trust after a local rollback.
    pub fn matches(
        &self,
        peer: PeerId,
        space: SpaceId,
        resource: ResourceId,
        action: Action,
        now_ms: u64,
    ) -> bool {
        self.peer == peer
            && self.space == space
            && self.resource == resource
            && self.actions & action_bit(action) != 0
            && self.issued_at_ms <= now_ms
            && now_ms < self.expires_at_ms
    }
}
fn action_bit(action: Action) -> u8 {
    match action {
        Action::Read => 1,
        Action::Write => 2,
        Action::Connect => 4,
        Action::Administer => 8,
    }
}

/// resource[16] || subject peer[32] || key epoch u64 || member epoch u64 || actions u8.
pub fn owner_grant_payload(
    resource: ResourceId,
    member: &VerifiedMembership,
    actions: u8,
) -> Vec<u8> {
    let mut bytes = resource.as_bytes().to_vec();
    bytes.extend_from_slice(member.peer().digest());
    bytes.extend_from_slice(&member.key_epoch().to_be_bytes());
    bytes.extend_from_slice(&member.member_epoch().to_be_bytes());
    bytes.push(actions);
    bytes
}

pub fn verify_owner_grant_for_spike(
    trust: &VerifiedResourceTrust,
    member: &VerifiedMembership,
    current_policy_sequence: u64,
    canonical: &[u8],
    signature: &[u8],
    now_ms: u64,
) -> Result<VerifiedOwnerGrant, GrantError> {
    if !trust.valid_at(now_ms)
        || member.root_identity() != (trust.root_public_key(), trust.root_key_epoch())
    {
        return Err(GrantError::InvalidTrust);
    }
    if member.space() != trust.space() {
        return Err(GrantError::InvalidScope);
    }
    if !member.valid_at(now_ms) {
        return Err(GrantError::InvalidTime);
    }
    let event = decode_security_event(canonical).map_err(|_| GrantError::NonCanonical)?;
    if event.kind != EventKind::OwnerGrant {
        return Err(GrantError::WrongKind);
    }
    let owner = trust.owner();
    if event.space_id != *trust.space().as_bytes()
        || event.signer_key_id != issuer_key_id(&owner.public_key)
    {
        return Err(GrantError::InvalidScope);
    }
    if event.issuer_epoch != owner.current_key_epoch {
        return Err(GrantError::InvalidEpoch);
    }
    if current_policy_sequence == 0 || event.seq != current_policy_sequence {
        return Err(GrantError::InvalidSequence);
    }
    let (trust_start, trust_end) = trust.validity_interval();
    let (member_start, member_end) = member.validity_interval();
    if event.issued_at_ms < trust_start.max(member_start)
        || event.expires_at_ms > trust_end.min(member_end)
        || event.issued_at_ms > now_ms
        || now_ms >= event.expires_at_ms
    {
        return Err(GrantError::InvalidTime);
    }
    if event.payload.len() != 65 {
        return Err(GrantError::InvalidPayload);
    }
    if event.payload[..16] != *trust.resource().as_bytes() {
        return Err(GrantError::InvalidScope);
    }
    if event.payload[16..48] != *member.peer().digest()
        || event.payload[48..56] != member.key_epoch().to_be_bytes()
        || event.payload[56..64] != member.member_epoch().to_be_bytes()
    {
        return Err(GrantError::InvalidSubject);
    }
    let actions = event.payload[64];
    if actions == 0 || actions & !0x0f != 0 {
        return Err(GrantError::InvalidPayload);
    }
    let key = VerifyingKey::from_bytes(&owner.public_key).map_err(|_| GrantError::InvalidTrust)?;
    let signature = Signature::from_slice(signature).map_err(|_| GrantError::InvalidSignature)?;
    key.verify_strict(
        &signing_input(canonical).map_err(|_| GrantError::NonCanonical)?,
        &signature,
    )
    .map_err(|_| GrantError::InvalidSignature)?;
    Ok(VerifiedOwnerGrant {
        space: trust.space(),
        resource: trust.resource(),
        peer: member.peer(),
        key_epoch: member.key_epoch(),
        member_epoch: member.member_epoch(),
        actions,
        sequence: event.seq,
        issued_at_ms: event.issued_at_ms,
        expires_at_ms: event.expires_at_ms,
    })
}
