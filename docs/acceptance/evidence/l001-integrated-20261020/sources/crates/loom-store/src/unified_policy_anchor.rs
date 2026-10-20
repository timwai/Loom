//! L-001J *candidate* unified policy-chain high-water protection.
//! The physical external trust store has NOT been built. This only states
//! the required atomic/rollback-resistant contract and validates transitions.
//! A successful comparison grants NO network, file, VPN or ServiceOpen access.

use loom_crypto::space_trust::VerifiedResourceTrust;
use loom_crypto::witness_checkpoint::Checkpoint;
use loom_types::{ResourceId, SpaceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnifiedPolicyHighWater {
    pub space: SpaceId,
    pub resource: ResourceId,
    pub root_public_key: [u8; 32],
    pub root_key_epoch: u64,
    pub genesis_manifest: [u8; 32],
    pub current_manifest: [u8; 32],
    pub writer_epoch: u64,
    pub policy_sequence: u64,
    pub policy_head: [u8; 32],
    /// Distinct accumulator for *only* resource revocations; unlike the
    /// unified policy head it does not change on delegate cancellation.
    pub revocation_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnifiedAnchorError {
    MissingOrUntrusted,
    PersistenceUncertain,
    ConcurrentUpdate,
    StaleState,
    ConflictingHistory,
    IdentityOrManifestMismatch,
    InvalidEpochOrTime,
}

/// A platform adapter MUST ensure authenticity, non-rollback persistence and
/// an atomic durable compare-and-advance in a storage domain independent from
/// SQLite snapshots. Implementations based on ordinary files are INSUFFICIENT.
pub trait IndependentUnifiedPolicyAnchor: Send + Sync {
    fn read(
        &self,
        space: SpaceId,
        resource: ResourceId,
    ) -> Result<UnifiedPolicyHighWater, UnifiedAnchorError>;

    fn compare_and_advance(
        &self,
        expected: UnifiedPolicyHighWater,
        next: UnifiedPolicyHighWater,
    ) -> Result<(), UnifiedAnchorError>;
}

impl UnifiedPolicyHighWater {
    /// Only for independently authenticated *initial provisioning*.
    /// NEVER use a backed-up SQLite state or inbound network values here.
    pub fn initial(trust: &VerifiedResourceTrust) -> Self {
        let hash = trust.manifest_commitment();
        Self {
            space: trust.space(),
            resource: trust.resource(),
            root_public_key: trust.root_public_key(),
            root_key_epoch: trust.root_key_epoch(),
            genesis_manifest: hash,
            current_manifest: hash,
            writer_epoch: trust.writer_epoch(),
            policy_sequence: 0,
            policy_head: [0; 32],
            revocation_root: [0; 32],
        }
    }
}

/// Validate a Root-authorized *genesis*, the fully replayed current manifest
/// (which may change after a dual-signed Owner transfer), a signed checkpoint,
/// and a previously authenticated external anchor record.
///
/// This cannot establish independent hardware storage, secure time or latest
/// network state. The checkpoint is checked against the journal separately.
pub fn checked_unified_promotion(
    genesis: &VerifiedResourceTrust,
    current: &VerifiedResourceTrust,
    cp: Checkpoint,
    anchor: UnifiedPolicyHighWater,
    now_ms: u64,
) -> Result<UnifiedPolicyHighWater, UnifiedAnchorError> {
    if !genesis.valid_at(now_ms) || !current.valid_at(now_ms) {
        return Err(UnifiedAnchorError::InvalidEpochOrTime);
    }
    if genesis.space() != current.space()
        || genesis.resource() != current.resource()
        || cp.space != genesis.space()
        || cp.resource != genesis.resource()
        || anchor.space != genesis.space()
        || anchor.resource != genesis.resource()
        || anchor.root_public_key != genesis.root_public_key()
        || anchor.root_key_epoch != genesis.root_key_epoch()
        || anchor.genesis_manifest != genesis.manifest_commitment()
    {
        return Err(UnifiedAnchorError::IdentityOrManifestMismatch);
    }
    if current.root_public_key() != genesis.root_public_key()
        || current.root_key_epoch() != genesis.root_key_epoch()
        || current.writer_epoch() != genesis.writer_epoch()
        || anchor.writer_epoch != genesis.writer_epoch()
        || cp.writer_epoch != genesis.writer_epoch()
    {
        return Err(UnifiedAnchorError::InvalidEpochOrTime);
    }
    if cp.seq == 0 && (cp.head_hash != [0; 32] || cp.revocation_root != [0; 32]) {
        return Err(UnifiedAnchorError::ConflictingHistory);
    }
    if cp.seq < anchor.policy_sequence {
        return Err(UnifiedAnchorError::StaleState);
    }
    if cp.seq == anchor.policy_sequence
        && (cp.head_hash != anchor.policy_head
            || cp.revocation_root != anchor.revocation_root
            || current.manifest_commitment() != anchor.current_manifest)
    {
        return Err(UnifiedAnchorError::ConflictingHistory);
    }
    // A manifest replacement without a higher, Root/Owner verified policy
    // sequence is always a conflict. Migration requires its own signed event.
    Ok(UnifiedPolicyHighWater {
        current_manifest: current.manifest_commitment(),
        policy_sequence: cp.seq,
        policy_head: cp.head_hash,
        revocation_root: cp.revocation_root,
        ..anchor
    })
}
