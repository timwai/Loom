//! L-001L read-only *single resource* legacy revocation migration audit.
//! This is an evidence inspection, NEVER a migration approval or authorization.
//! The legacy revocation-only epoch cannot be reused as a unified policy head.

use loom_crypto::owner_authority::replay_persisted_owner_revocation_for_spike;
use loom_crypto::owner_lifecycle::ResourceOwnerLifecycle;
use loom_crypto::space_trust::{ExternallyPinnedRootForSpike, VerifiedResourceTrust};
use loom_crypto::witness_checkpoint::append_revocation_root;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::StoreError;

const MAX_AUDIT_EVENTS: u64 = 10_000;
const LEGACY_REQUIRED: [&str; 4] = [
    "policy_versions",
    "revocations",
    "critical_outbox",
    "security_audit",
];

/// This report is a *candidate* for a later, externally witnessed migration.
/// It cannot prove absence of a newer remote revocation, an independent
/// high-water value, or a revoked Owner delegation in another policy chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyResourceAudit {
    pub legacy_epoch: u64,
    pub legacy_revocation_root: [u8; 32],
    pub candidate_unified_policy_head: [u8; 32],
    pub candidate_unified_revocation_root: [u8; 32],
    pub owner_manifest_commitment: [u8; 32],
    pub requires_external_rewitness: bool,
}

/// Inspect an entire legacy database containing EXACTLY one resource.
/// Fail closed on partial schemas, multiple resources, missing outbox/audit,
/// forged evidence, non-contiguous epochs, or concurrent mutation.
///
/// This performs only SELECT operations inside a consistent read snapshot.
/// It deliberately does NOT write a unified event or create a DB table.
pub fn audit_single_resource_legacy(
    conn: &mut Connection,
    root: &ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
) -> Result<LegacyResourceAudit, StoreError> {
    if root.space != genesis.space()
        || root.public_key != genesis.root_public_key()
        || root.key_epoch != genesis.root_key_epoch()
    {
        return Err(StoreError::Conflict);
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| StoreError::PersistenceFailure)?;
    for table in LEGACY_REQUIRED {
        let found: Option<i64> = tx.query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            params![table],
            |row| row.get(0),
        ).optional().map_err(|_| StoreError::PersistenceFailure)?;
        if found.is_none() {
            return Err(StoreError::Conflict);
        }
    }
    // A half-completed or forged coexistence of the two schema generations
    // is not an acceptable input for this single-resource audit.
    let unified: i64 = tx.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type='table' AND name LIKE 'unified_policy_%'",
        [], |row| row.get(0),
    ).map_err(|_| StoreError::PersistenceFailure)?;
    if unified != 0 {
        return Err(StoreError::Conflict);
    }

    let space_id = genesis.space();
    let resource_id = genesis.resource();
    let scope = [space_id.as_bytes().as_slice(), resource_id.as_bytes().as_slice()];
    let versions: i64 = tx.query_row(
        "SELECT COUNT(*) FROM policy_versions", [], |row| row.get(0),
    ).map_err(|_| StoreError::PersistenceFailure)?;
    if versions != 1 {
        return Err(StoreError::Conflict);
    }
    let current: Option<i64> = tx.query_row(
        "SELECT epoch FROM policy_versions WHERE space=?1 AND resource=?2",
        params![scope[0], scope[1]],
        |row| row.get(0),
    ).optional().map_err(|_| StoreError::PersistenceFailure)?;
    let current = current.ok_or(StoreError::Conflict)?;
    let epoch = u64::try_from(current).map_err(|_| StoreError::Conflict)?;
    if epoch == 0 || epoch > MAX_AUDIT_EVENTS {
        // Even an empty legacy DB is NOT silently bootstrapped. Existing
        // external high-water may reflect revocations missing locally.
        return Err(StoreError::Conflict);
    }

    let counts = [
        ("revocations", "SELECT COUNT(*) FROM revocations"),
        ("critical_outbox", "SELECT COUNT(*) FROM critical_outbox"),
        ("security_audit", "SELECT COUNT(*) FROM security_audit"),
    ];
    for (_, query) in counts {
        let n: i64 = tx.query_row(query, [], |row| row.get(0))
            .map_err(|_| StoreError::PersistenceFailure)?;
        if u64::try_from(n).map_err(|_| StoreError::Conflict)? != epoch {
            return Err(StoreError::Conflict);
        }
    }

    let mut stmt = tx.prepare(
        "SELECT r.epoch,r.signed_event,o.epoch,o.signed_event,a.action
         FROM revocations r
         LEFT JOIN critical_outbox o ON o.revocation_id=r.id
         LEFT JOIN security_audit a ON a.revocation_id=r.id
         WHERE r.space=?1 AND r.resource=?2
         ORDER BY r.epoch",
    ).map_err(|_| StoreError::PersistenceFailure)?;
    let rows = stmt.query_map(params![scope[0], scope[1]], |row| {
        let rev_epoch: i64 = row.get(0)?;
        let evidence: Vec<u8> = row.get(1)?;
        let outbox_epoch: Option<i64> = row.get(2)?;
        let outbox_evidence: Option<Vec<u8>> = row.get(3)?;
        let audit_action: Option<String> = row.get(4)?;
        Ok((rev_epoch,evidence,outbox_epoch,outbox_evidence,audit_action))
    }).map_err(|_| StoreError::PersistenceFailure)?;

    let mut state = ResourceOwnerLifecycle::from_genesis(genesis);
    let mut old_root = [0u8; 32];
    let mut new_revocation_root = [0u8; 32];

    for row in rows {
        let (rev_epoch,evidence,out_epoch,out_event,action) =
            row.map_err(|_| StoreError::PersistenceFailure)?;
        let seq = u64::try_from(rev_epoch).map_err(|_| StoreError::Conflict)?;
        if seq != state.sequence().checked_add(1).ok_or(StoreError::Conflict)?
            || out_epoch != Some(rev_epoch)
            || out_event.as_deref() != Some(evidence.as_slice())
            || action.as_deref() != Some("revoke")
        {
            return Err(StoreError::Conflict);
        }
        let proof = replay_persisted_owner_revocation_for_spike(
            &state.current_owner(), &evidence,
        ).map_err(|_| StoreError::Conflict)?;
        if proof.seq() != seq
            || proof.space_id() != genesis.space()
            || proof.resource_id() != genesis.resource()
        {
            return Err(StoreError::Conflict);
        }
        state.apply_delegated_revocation(&proof).map_err(|_| StoreError::Conflict)?;
        old_root = append_revocation_root(old_root, seq, &evidence)
            .ok_or(StoreError::Conflict)?;
        // A new policy chain has a different hash domain. The legacy epoch
        // is not itself a signed unified policy checkpoint.
        new_revocation_root = append_revocation_root(new_revocation_root, seq, &evidence)
            .ok_or(StoreError::Conflict)?;
    }
    drop(stmt);
    if state.sequence() != epoch {
        return Err(StoreError::Conflict);
    }
    // A read-only transaction never mutates SQLite. A later migration must
    // re-check under an exclusive barrier and obtain fresh signed witnesses.
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(LegacyResourceAudit {
        legacy_epoch: epoch,
        legacy_revocation_root: old_root,
        candidate_unified_policy_head: state.policy_head(),
        candidate_unified_revocation_root: new_revocation_root,
        owner_manifest_commitment: genesis.manifest_commitment(),
        requires_external_rewitness: true,
    })
}
