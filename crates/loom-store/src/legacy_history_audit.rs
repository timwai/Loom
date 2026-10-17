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

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| StoreError::PersistenceFailure)?;
    for table in LEGACY_REQUIRED {
        let found: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::PersistenceFailure)?;
        if found.is_none() {
            return Err(StoreError::Conflict);
        }
    }
    // A half-completed or forged coexistence of the two schema generations
    // is not an acceptable input for this single-resource audit.
    let unified: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
         WHERE type='table' AND name LIKE 'unified_policy_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    if unified != 0 {
        return Err(StoreError::Conflict);
    }

    let space_id = genesis.space();
    let resource_id = genesis.resource();
    let scope = [
        space_id.as_bytes().as_slice(),
        resource_id.as_bytes().as_slice(),
    ];
    let versions: i64 = tx
        .query_row("SELECT COUNT(*) FROM policy_versions", [], |row| row.get(0))
        .map_err(|_| StoreError::PersistenceFailure)?;
    if versions != 1 {
        return Err(StoreError::Conflict);
    }
    let current: Option<i64> = tx
        .query_row(
            "SELECT epoch FROM policy_versions WHERE space=?1 AND resource=?2",
            params![scope[0], scope[1]],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::PersistenceFailure)?;
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
        let n: i64 = tx
            .query_row(query, [], |row| row.get(0))
            .map_err(|_| StoreError::PersistenceFailure)?;
        if u64::try_from(n).map_err(|_| StoreError::Conflict)? != epoch {
            return Err(StoreError::Conflict);
        }
    }

    let mut stmt = tx
        .prepare(
            "SELECT r.epoch,r.signed_event,o.epoch,o.signed_event,a.action
         FROM revocations r
         LEFT JOIN critical_outbox o ON o.revocation_id=r.id
         LEFT JOIN security_audit a ON a.revocation_id=r.id
         WHERE r.space=?1 AND r.resource=?2
         ORDER BY r.epoch",
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    let rows = stmt
        .query_map(params![scope[0], scope[1]], |row| {
            let rev_epoch: i64 = row.get(0)?;
            let evidence: Vec<u8> = row.get(1)?;
            let outbox_epoch: Option<i64> = row.get(2)?;
            let outbox_evidence: Option<Vec<u8>> = row.get(3)?;
            let audit_action: Option<String> = row.get(4)?;
            Ok((
                rev_epoch,
                evidence,
                outbox_epoch,
                outbox_evidence,
                audit_action,
            ))
        })
        .map_err(|_| StoreError::PersistenceFailure)?;

    let mut state = ResourceOwnerLifecycle::from_genesis(genesis);
    let mut old_root = [0u8; 32];
    let mut new_revocation_root = [0u8; 32];

    for row in rows {
        let (rev_epoch, evidence, out_epoch, out_event, action) =
            row.map_err(|_| StoreError::PersistenceFailure)?;
        let seq = u64::try_from(rev_epoch).map_err(|_| StoreError::Conflict)?;
        if seq
            != state
                .sequence()
                .checked_add(1)
                .ok_or(StoreError::Conflict)?
            || out_epoch != Some(rev_epoch)
            || out_event.as_deref() != Some(evidence.as_slice())
            || action.as_deref() != Some("revoke")
        {
            return Err(StoreError::Conflict);
        }
        let proof = replay_persisted_owner_revocation_for_spike(&state.current_owner(), &evidence)
            .map_err(|_| StoreError::Conflict)?;
        if proof.seq() != seq
            || proof.space_id() != genesis.space()
            || proof.resource_id() != genesis.resource()
        {
            return Err(StoreError::Conflict);
        }
        state
            .apply_delegated_revocation(&proof)
            .map_err(|_| StoreError::Conflict)?;
        old_root = append_revocation_root(old_root, seq, &evidence).ok_or(StoreError::Conflict)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_crypto::owner_authority::{
        issuer_key_id, verify_owner_delegated_revocation_for_spike,
    };
    use loom_crypto::space_trust::{
        ResourceTrustManifest, SignedResourceTrust, trust_manifest_transcript,
        verify_resource_trust_for_spike,
    };
    use loom_types::{ResourceId, SpaceId};
    use loom_wire::security_event::{
        CanonicalSecurityEvent, EventKind, encode_security_event, signing_input,
    };

    fn trust() -> (ExternallyPinnedRootForSpike, VerifiedResourceTrust) {
        let root_key = SigningKey::from_bytes(&[30; 32]);
        let owner_key = SigningKey::from_bytes(&[11; 32]);
        let witness_a = SigningKey::from_bytes(&[21; 32]);
        let witness_b = SigningKey::from_bytes(&[22; 32]);
        let root = ExternallyPinnedRootForSpike {
            space: SpaceId::from_bytes([1; 16]),
            public_key: root_key.verifying_key().to_bytes(),
            key_epoch: 7,
        };
        let manifest = ResourceTrustManifest {
            space: root.space,
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner_key.verifying_key().to_bytes(),
            owner_key_epoch: 3,
            witness_public_keys: [
                witness_a.verifying_key().to_bytes(),
                witness_b.verifying_key().to_bytes(),
            ],
            writer_epoch: 1,
            root_key_epoch: 7,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let signed = SignedResourceTrust {
            manifest,
            signature: root_key
                .sign(&trust_manifest_transcript(&manifest))
                .to_bytes(),
        };
        let verified = verify_resource_trust_for_spike(&root, &signed, 150).unwrap();
        (root, verified)
    }

    fn signed_revoke(seq: u64) -> Vec<u8> {
        let owner = SigningKey::from_bytes(&[11; 32]);
        let delegate = SigningKey::from_bytes(&[12; 32]);
        let delegate_pub = delegate.verifying_key().to_bytes();
        let resource = ResourceId::from_bytes([2; 16]);
        let space = SpaceId::from_bytes([1; 16]);
        let mut grant_payload = resource.as_bytes().to_vec();
        grant_payload.extend_from_slice(&delegate_pub);
        grant_payload.extend_from_slice(&issuer_key_id(&delegate_pub));
        grant_payload.push(1);
        grant_payload.extend_from_slice(&4u64.to_be_bytes());
        let grant = CanonicalSecurityEvent {
            kind: EventKind::OwnerGrant,
            space_id: *space.as_bytes(),
            signer_key_id: issuer_key_id(&owner.verifying_key().to_bytes()),
            issuer_epoch: 3,
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
            seq,
            payload: revoke_payload,
        };
        let grant_bytes = encode_security_event(&grant).unwrap();
        let revoke_bytes = encode_security_event(&revoke).unwrap();
        verify_owner_delegated_revocation_for_spike(
            &trust().1.owner(),
            &grant_bytes,
            &owner.sign(&signing_input(&grant_bytes).unwrap()).to_bytes(),
            &revoke_bytes,
            &delegate
                .sign(&signing_input(&revoke_bytes).unwrap())
                .to_bytes(),
            150,
        )
        .unwrap()
        .persistence_bytes()
    }

    fn legacy_db() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE policy_versions(
               space BLOB NOT NULL, resource BLOB NOT NULL, epoch INTEGER NOT NULL
             );
             CREATE TABLE revocations(
               id INTEGER PRIMARY KEY,
               space BLOB NOT NULL, resource BLOB NOT NULL,
               epoch INTEGER NOT NULL, signed_event BLOB NOT NULL
             );
             CREATE TABLE critical_outbox(
               id INTEGER PRIMARY KEY, revocation_id INTEGER NOT NULL,
               epoch INTEGER NOT NULL, signed_event BLOB NOT NULL
             );
             CREATE TABLE security_audit(
               id INTEGER PRIMARY KEY, revocation_id INTEGER NOT NULL, action TEXT NOT NULL
             );",
            )
            .unwrap();
        connection
    }

    fn insert_one(conn: &Connection, seq: i64, evidence: &[u8]) {
        conn.execute(
            "INSERT INTO revocations(space,resource,epoch,signed_event)
             VALUES(?1,?2,?3,?4)",
            params![[1u8; 16].as_slice(), [2u8; 16].as_slice(), seq, evidence],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO critical_outbox(revocation_id,epoch,signed_event)
             VALUES(?1,?2,?3)",
            params![id, seq, evidence],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO security_audit(revocation_id,action) VALUES(?1,'revoke')",
            params![id],
        )
        .unwrap();
    }

    fn full_legacy() -> Connection {
        let conn = legacy_db();
        conn.execute(
            "INSERT INTO policy_versions(space,resource,epoch)
             VALUES(?1,?2,2)",
            params![[1u8; 16].as_slice(), [2u8; 16].as_slice()],
        )
        .unwrap();
        insert_one(&conn, 1, &signed_revoke(1));
        insert_one(&conn, 2, &signed_revoke(2));
        conn
    }

    #[test]
    fn two_signed_events_can_be_audited_but_cannot_authorize_migration() {
        let mut conn = full_legacy();
        let (root, genesis) = trust();
        let before: i64 = conn
            .query_row("SELECT COUNT(*) FROM revocations", [], |row| row.get(0))
            .unwrap();
        let report = audit_single_resource_legacy(&mut conn, &root, genesis).unwrap();
        assert_eq!(report.legacy_epoch, 2);
        assert!(report.requires_external_rewitness);
        assert_eq!(
            report.legacy_revocation_root,
            report.candidate_unified_revocation_root
        );
        assert_ne!(
            report.legacy_revocation_root,
            report.candidate_unified_policy_head
        );
        let after: i64 = conn
            .query_row("SELECT COUNT(*) FROM revocations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before, after);
        let new_schema: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
             WHERE type='table' AND name LIKE 'unified_policy_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_schema, 0);
    }

    #[test]
    fn wrong_root_or_owner_signed_evidence_blocks_audit() {
        let mut conn = full_legacy();
        let (mut root, genesis) = trust();
        root.public_key = SigningKey::from_bytes(&[44; 32]).verifying_key().to_bytes();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
        let (root, genesis) = trust();
        conn.execute(
            "UPDATE revocations SET signed_event=?1 WHERE epoch=2",
            params![b"garbage".as_slice()],
        )
        .unwrap();
        conn.execute(
            "UPDATE critical_outbox SET signed_event=?1 WHERE epoch=2",
            params![b"garbage".as_slice()],
        )
        .unwrap();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn audit_rejects_stale_outbox_and_missing_audit() {
        let mut conn = full_legacy();
        let (root, genesis) = trust();
        conn.execute(
            "UPDATE critical_outbox SET signed_event=?1 WHERE epoch=1",
            params![b"wrong".as_slice()],
        )
        .unwrap();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
        let mut conn = full_legacy();
        conn.execute("DELETE FROM security_audit WHERE id=1", [])
            .unwrap();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn sequence_gaps_rogue_resources_and_partial_schemas_refuse_audit() {
        let (root, genesis) = trust();
        let mut conn = full_legacy();
        conn.execute("UPDATE revocations SET epoch=3 WHERE epoch=2", [])
            .unwrap();
        conn.execute("UPDATE critical_outbox SET epoch=3 WHERE epoch=2", [])
            .unwrap();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
        let mut conn = full_legacy();
        conn.execute(
            "INSERT INTO policy_versions VALUES(?1,?2,1)",
            params![[1u8; 16].as_slice(), [99u8; 16].as_slice()],
        )
        .unwrap();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
        let mut conn = legacy_db();
        conn.execute_batch("DROP TABLE security_audit").unwrap();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn nonempty_old_history_is_not_convertible_after_mixed_schema_creation() {
        let (root, genesis) = trust();
        let mut conn = full_legacy();
        conn.execute_batch("CREATE TABLE unified_policy_events(dummy INTEGER);")
            .unwrap();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn legacy_zero_epoch_is_not_permission_to_reset_highwater() {
        let (root, genesis) = trust();
        let mut conn = legacy_db();
        conn.execute(
            "INSERT INTO policy_versions VALUES(?1,?2,0)",
            params![[1u8; 16].as_slice(), [2u8; 16].as_slice()],
        )
        .unwrap();
        assert_eq!(
            audit_single_resource_legacy(&mut conn, &root, genesis),
            Err(StoreError::Conflict)
        );
    }
}
