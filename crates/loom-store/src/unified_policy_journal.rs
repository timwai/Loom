//! L-001I experimental unified SQLite resource-policy ledger.
//!
//! Every append replays the signed, ordered lifecycle history from genesis
//! under a pinned Root before starting a fresh atomic commit. This does not
//! establish witness freshness and NEVER transitions network admission to
//! Ready. No production permit or ServiceOpen is exported.
//!
//! Synchronous APIs: call from a blocking pool, never on a Tokio runtime core.

use crate::StoreError;
use crate::legacy_migration::require_no_legacy_schema;
use crate::policy_journal_codec::KIND_REVOKE;
pub use crate::policy_journal_codec::NewPolicyEvent;
use crate::policy_journal_codec::{MAX_EVIDENCE, encode_event, replay_event};
use crate::tpm_counter_binding::{
    BindingError, CandidateIntentStore, CandidateMonotonicCounter, Diagnostic,
    PinnedCounterIdentity, StoredBinding, begin_candidate_advance, inspect_counter,
    reconcile_candidate_advance,
};
use crate::unified_policy_anchor::{
    IndependentUnifiedPolicyAnchor, UnifiedAnchorError, UnifiedPolicyHighWater, checked_unified_promotion,
};
use loom_crypto::owner_lifecycle::ResourceOwnerLifecycle;
use loom_crypto::space_trust::verify_root_bound_witnesses;
use loom_crypto::space_trust::{ExternallyPinnedRootForSpike, VerifiedResourceTrust};
use loom_crypto::witness_checkpoint::{Checkpoint, SignedCheckpoint, append_revocation_root};
use loom_types::ResourceId;
#[cfg(test)]
use loom_types::SpaceId;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalSnapshot {
    pub sequence: u64,
    pub policy_head: [u8; 32],
    pub owner_public_key: [u8; 32],
    /// A diagnostic only. In this PoC no ServiceOpen is ever admitted.
    pub admission_paused: bool,
}

/// Recovery assessment only. None of these outcomes enables ServiceOpen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnifiedRecoveryAssessment {
    CandidateConsistent,
    LocalBehind,
    WitnessBehind,
    HistoryConflict,
}

/// L-001Q: a diagnostic-only transition. Neither variant enables ServiceOpen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateCounterOperation {
    Begin,
    Reconcile,
}

/// Test-only I/O contracts. Neither adapter is backed by production TPM NV or
/// a durable authenticated intent store. Both must be independent of the
/// SQLite connection held by the journal actor to avoid reentrant deadlocks.
pub struct CandidateCounterIo {
    pub pin: PinnedCounterIdentity,
    pub counter: Arc<dyn CandidateMonotonicCounter>,
    pub intent: Arc<dyn CandidateIntentStore>,
}

struct JournalCheckpointState {
    snapshot: JournalSnapshot,
    revocation_root: [u8; 32],
    current_trust: VerifiedResourceTrust,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CriticalPolicyOutbox {
    pub sequence: u64,
    pub kind: u8,
    pub evidence: Vec<u8>,
}

enum Command {
    Append {
        root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
        kind: u8,
        evidence: Vec<u8>,
        done: Sender<Result<JournalSnapshot, StoreError>>,
    },
    Inspect {
        root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
        done: Sender<Result<JournalSnapshot, StoreError>>,
    },
    Pending(Sender<Result<Vec<CriticalPolicyOutbox>, StoreError>>),
    InspectWitness {
        root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
        done: Sender<Result<JournalCheckpointState, StoreError>>,
    },
    BoundCounter {
        root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
        receipts: Vec<SignedCheckpoint>,
        now_ms: u64,
        io: CandidateCounterIo,
        operation: CandidateCounterOperation,
        done: Sender<Result<Diagnostic, StoreError>>,
    },
    MarkWitness {
        root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
        checkpoint: Checkpoint,
        current_manifest: [u8; 32],
        done: Sender<Result<(), StoreError>>,
    },
}

/// Append-only SQLite actor, separate from the old L-001C revocation-only
/// candidate schema. Both formats require an explicit migration before use.
pub struct UnifiedPolicyJournal {
    tx: Option<Sender<Command>>,
    join: Option<JoinHandle<()>>,
    gate: Mutex<()>,
}

impl UnifiedPolicyJournal {
    pub fn open(path: PathBuf) -> Result<Self, StoreError> {
        let (tx, receiver) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let join = thread::Builder::new()
            .name("loom-unified-policy-db".to_owned())
            .spawn(move || worker(path, receiver, ready_tx))
            .map_err(|_| StoreError::PersistenceFailure)?;
        ready_rx
            .recv()
            .map_err(|_| StoreError::PersistenceFailure)??;
        Ok(Self {
            tx: Some(tx),
            join: Some(join),
            gate: Mutex::new(()),
        })
    }

    /// Only a diagnostic snapshot; never a permission to access a resource.
    pub fn inspect(
        &self,
        external_root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
    ) -> Result<JournalSnapshot, StoreError> {
        let _barrier = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::Inspect {
                root: external_root,
                genesis,
                done: send,
            })
            .map_err(|_| StoreError::PersistenceFailure)?;
        recv.recv().map_err(|_| StoreError::PersistenceFailure)?
    }

    /// Writes signed evidence only after a replay of all prior policy events.
    /// No external AnchorProvider exists here. A successful local SQLite
    /// commit MUST NOT be interpreted as global policy convergence.
    pub fn append(
        &self,
        external_root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
        input: NewPolicyEvent<'_>,
    ) -> Result<JournalSnapshot, StoreError> {
        let (kind, evidence) = encode_event(input);
        if evidence.is_empty() || evidence.len() > MAX_EVIDENCE {
            return Err(StoreError::Conflict);
        }
        let _barrier = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::Append {
                root: external_root,
                genesis,
                kind,
                evidence,
                done: send,
            })
            .map_err(|_| StoreError::PersistenceFailure)?;
        recv.recv().map_err(|_| StoreError::PersistenceFailure)?
    }

    /// Verify two Root-selected signed checkpoints against a fully replayed,
    /// mixed control+revocation policy chain, then compare and atomically
    /// advance an independently trusted high-water record.
    ///
    /// The signature and storage interfaces do not prove actual external
    /// witness independence or hardware-backed monotonic persistence.
    /// ALWAYS diagnostic only: this API never returns an admission permit.
    pub fn inspect_witnessed_recovery(
        &self,
        external_root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
        receipts: &[SignedCheckpoint],
        now_ms: u64,
        anchor: &dyn IndependentUnifiedPolicyAnchor,
    ) -> Result<UnifiedRecoveryAssessment, StoreError> {
        // The same gate serializes diagnostic witness inspection against
        // append. It cannot mark any session Ready.
        let _barrier = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        let cp = verify_root_bound_witnesses(&genesis, receipts, now_ms)
            .map_err(|_| StoreError::Conflict)?
            .checkpoint();
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::InspectWitness {
                root: external_root,
                genesis,
                done: send,
            })
            .map_err(|_| StoreError::PersistenceFailure)?;
        let local = recv.recv().map_err(|_| StoreError::PersistenceFailure)??;
        // Witness identity/writer rotation requires a separate signed
        // migration. The Owner may change, but witness pair may not here.
        let old_witnesses = genesis.witnesses();
        let new_witnesses = local.current_trust.witnesses();
        if old_witnesses[0].public_key != new_witnesses[0].public_key
            || old_witnesses[1].public_key != new_witnesses[1].public_key
        {
            return Err(StoreError::Conflict);
        }
        if local.snapshot.sequence < cp.seq {
            return Ok(UnifiedRecoveryAssessment::LocalBehind);
        }
        if local.snapshot.sequence > cp.seq {
            return Ok(UnifiedRecoveryAssessment::WitnessBehind);
        }
        if local.snapshot.policy_head != cp.head_hash || local.revocation_root != cp.revocation_root
        {
            return Ok(UnifiedRecoveryAssessment::HistoryConflict);
        }
        // Comparing a matching local journal with a stale *signed*
        // checkpoint is not enough: consult external high-water even at
        // equal version, and never initialize it from SQLite contents.
        let previous = anchor
            .read(cp.space, cp.resource)
            .map_err(|_| StoreError::PersistenceFailure)?;
        let next = checked_unified_promotion(&genesis, &local.current_trust, cp, previous, now_ms)
            .map_err(|error| match error {
                UnifiedAnchorError::StaleState
                | UnifiedAnchorError::ConflictingHistory
                | UnifiedAnchorError::IdentityOrManifestMismatch
                | UnifiedAnchorError::InvalidEpochOrTime => StoreError::Conflict,
                _ => StoreError::PersistenceFailure,
            })?;
        anchor
            .compare_and_advance(previous, next)
            .map_err(|_| StoreError::PersistenceFailure)?;

        // The external CAS is already durable; now record only a LOCAL
        // diagnostic confirmation, conditioned on a fresh signed-history
        // replay inside SQLite. A crash before this SQL COMMIT leaves the
        // marker absent/stale; repeating the signed checkpoint + CAS can
        // reconcile the ambiguous interval. Never trust the marker alone.
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::MarkWitness {
                root: external_root,
                genesis,
                checkpoint: cp,
                current_manifest: local.current_trust.manifest_commitment(),
                done: send,
            })
            .map_err(|_| StoreError::PersistenceFailure)?;
        recv.recv().map_err(|_| StoreError::PersistenceFailure)??;
        Ok(UnifiedRecoveryAssessment::CandidateConsistent)
    }

    /// Journal-bound *candidate* TPM transition, not a resource permit.
    ///
    /// Holds the journal actor's BEGIN IMMEDIATE SQLite transaction across
    /// full signed-history replay, mirror parity validation, dual-witness
    /// checkpoint comparison and the model counter's stage/increment/finalize.
    /// Any error after staging may leave an ambiguous counter and intent:
    /// callers MUST treat errors as quarantine, never retry an increment.
    ///
    /// This is deliberately NOT an operational TPM or independent anchor
    /// implementation. The I/O traits have only in-memory model providers.
    /// A real intent store using this same SQLite file would deadlock.
    pub fn inspect_journal_bound_counter(
        &self,
        external_root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
        receipts: &[SignedCheckpoint],
        now_ms: u64,
        io: CandidateCounterIo,
        operation: CandidateCounterOperation,
    ) -> Result<Diagnostic, StoreError> {
        let _barrier = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::BoundCounter {
                root: external_root,
                genesis,
                receipts: receipts.to_vec(),
                now_ms,
                io,
                operation,
                done: send,
            })
            .map_err(|_| StoreError::PersistenceFailure)?;
        recv.recv().map_err(|_| StoreError::PersistenceFailure)?
    }

    /// Read-only: no ACK is allowed without authenticated remote durable
    /// receipt and a separate fairness/priority retransmission protocol.
    pub fn pending_outbox(&self) -> Result<Vec<CriticalPolicyOutbox>, StoreError> {
        let _barrier = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::Pending(send))
            .map_err(|_| StoreError::PersistenceFailure)?;
        recv.recv().map_err(|_| StoreError::PersistenceFailure)?
    }
}

impl Drop for UnifiedPolicyJournal {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn worker(path: PathBuf, rx: Receiver<Command>, started: Sender<Result<(), StoreError>>) {
    match initialize(&path) {
        Ok(mut connection) => {
            let _ = started.send(Ok(()));
            for command in rx {
                match command {
                    Command::Append {
                        root,
                        genesis,
                        kind,
                        evidence,
                        done,
                    } => {
                        let _ = done.send(append_transaction(
                            &mut connection,
                            root,
                            genesis,
                            kind,
                            &evidence,
                        ));
                    }
                    Command::Inspect {
                        root,
                        genesis,
                        done,
                    } => {
                        let _ = done.send(inspect_db(&mut connection, root, genesis));
                    }
                    Command::Pending(done) => {
                        let _ = done.send(read_outbox(&mut connection));
                    }
                    Command::InspectWitness {
                        root,
                        genesis,
                        done,
                    } => {
                        let _ = done.send(inspect_checkpoint_db(&mut connection, root, genesis));
                    }
                    Command::BoundCounter {
                        root,
                        genesis,
                        receipts,
                        now_ms,
                        io,
                        operation,
                        done,
                    } => {
                        let _ = done.send(journal_bound_counter_transaction(
                            &mut connection,
                            root,
                            genesis,
                            &receipts,
                            now_ms,
                            &io,
                            operation,
                        ));
                    }
                    Command::MarkWitness {
                        root,
                        genesis,
                        checkpoint,
                        current_manifest,
                        done,
                    } => {
                        let _ = done.send(record_witness_confirmation(
                            &mut connection,
                            root,
                            genesis,
                            checkpoint,
                            current_manifest,
                        ));
                    }
                }
            }
        }
        Err(error) => {
            let _ = started.send(Err(error));
        }
    }
}

fn initialize(path: &PathBuf) -> Result<Connection, StoreError> {
    let conn = Connection::open(path).map_err(|_| StoreError::PersistenceFailure)?;
    conn.busy_timeout(Duration::from_secs(2))
        .map_err(|_| StoreError::PersistenceFailure)?;
    // Never create a parallel, empty unified ledger next to legacy
    // revocation-only tables: that would erase required authorization
    // history by omission. Explicit reviewed migration is still pending.
    require_no_legacy_schema(&conn)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS unified_policy_events (
           space BLOB NOT NULL CHECK(length(space)=16),
           resource BLOB NOT NULL CHECK(length(resource)=16),
           seq INTEGER NOT NULL CHECK(seq>0),
           kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 3),
           evidence BLOB NOT NULL CHECK(length(evidence)>0 AND length(evidence)<=65536),
           policy_head BLOB NOT NULL CHECK(length(policy_head)=32),
           PRIMARY KEY(space,resource,seq)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS unified_policy_cursor (
           space BLOB NOT NULL CHECK(length(space)=16),
           resource BLOB NOT NULL CHECK(length(resource)=16),
           seq INTEGER NOT NULL CHECK(seq>0),
           policy_head BLOB NOT NULL CHECK(length(policy_head)=32),
           owner_manifest BLOB NOT NULL CHECK(length(owner_manifest)=32),
           PRIMARY KEY(space,resource)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS unified_policy_outbox (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           space BLOB NOT NULL CHECK(length(space)=16),
           resource BLOB NOT NULL CHECK(length(resource)=16),
           seq INTEGER NOT NULL CHECK(seq>0),
           kind INTEGER NOT NULL,
           evidence BLOB NOT NULL CHECK(length(evidence)>0),
           UNIQUE(space,resource,seq)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS unified_policy_audit (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           space BLOB NOT NULL CHECK(length(space)=16),
           resource BLOB NOT NULL CHECK(length(resource)=16),
           seq INTEGER NOT NULL,
           kind INTEGER NOT NULL,
           policy_head BLOB NOT NULL CHECK(length(policy_head)=32),
           UNIQUE(space,resource,seq)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS unified_policy_witnessed (
           space BLOB NOT NULL CHECK(length(space)=16),
           resource BLOB NOT NULL CHECK(length(resource)=16),
           seq INTEGER NOT NULL CHECK(seq>=0),
           policy_head BLOB NOT NULL CHECK(length(policy_head)=32),
           revocation_root BLOB NOT NULL CHECK(length(revocation_root)=32),
           owner_manifest BLOB NOT NULL CHECK(length(owner_manifest)=32),
           PRIMARY KEY(space,resource)
         ) STRICT;",
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    Ok(conn)
}

fn verify_genesis(
    root: &ExternallyPinnedRootForSpike,
    genesis: &VerifiedResourceTrust,
) -> Result<(), StoreError> {
    if root.space != genesis.space()
        || root.public_key != genesis.root_public_key()
        || root.key_epoch != genesis.root_key_epoch()
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn snapshot(state: &ResourceOwnerLifecycle) -> JournalSnapshot {
    JournalSnapshot {
        sequence: state.sequence(),
        policy_head: state.policy_head(),
        owner_public_key: state.current_owner().public_key,
        admission_paused: true,
    }
}

/// Replays each signed event from the independently supplied genesis manifest.
/// Every stored policy_head and the cursor must match computed state, not the
/// other way around. A local SQLite snapshot is never the trust anchor.
fn replay(
    tx: &Transaction<'_>,
    root: &ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
) -> Result<ResourceOwnerLifecycle, StoreError> {
    verify_genesis(root, &genesis)?;
    let mut state = ResourceOwnerLifecycle::from_genesis(genesis);
    let mut stmt = tx
        .prepare(
            "SELECT seq,kind,evidence,policy_head
         FROM unified_policy_events
         WHERE space=?1 AND resource=?2 ORDER BY seq ASC",
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    let rows = stmt
        .query_map(
            params![
                root.space.as_bytes().as_slice(),
                genesis.resource().as_bytes().as_slice()
            ],
            |row| {
                let seq: i64 = row.get(0)?;
                let kind: i64 = row.get(1)?;
                let evidence: Vec<u8> = row.get(2)?;
                let head: Vec<u8> = row.get(3)?;
                Ok((seq, kind, evidence, head))
            },
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    for row in rows {
        let (seq, kind, evidence, head) = row.map_err(|_| StoreError::PersistenceFailure)?;
        let seq = u64::try_from(seq).map_err(|_| StoreError::Conflict)?;
        let kind = u8::try_from(kind).map_err(|_| StoreError::Conflict)?;
        if state.sequence().checked_add(1) != Some(seq) {
            return Err(StoreError::Conflict);
        }
        replay_event(&mut state, root, kind, &evidence)?;
        if state.sequence() != seq || state.policy_head().as_slice() != head {
            return Err(StoreError::Conflict);
        }
    }
    let cursor: Option<(i64, Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT seq,policy_head,owner_manifest FROM unified_policy_cursor
         WHERE space=?1 AND resource=?2",
            params![
                root.space.as_bytes().as_slice(),
                genesis.resource().as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| StoreError::PersistenceFailure)?;
    match cursor {
        Some((seq, head, manifest)) => {
            let seq = u64::try_from(seq).map_err(|_| StoreError::Conflict)?;
            if seq != state.sequence()
                || head != state.policy_head()
                || manifest != state.current_trust().manifest_commitment()
            {
                return Err(StoreError::Conflict);
            }
        }
        None if state.sequence() == 0 => {}
        None => return Err(StoreError::Conflict),
    }
    // All durable mirrors must agree with the signed history in this transaction.
    verify_side_tables(tx)?;
    Ok(state)
}

/// Ensure that every event has exactly one matching Outbox and Audit row and
/// that there are no orphaned mirror rows, across every stored resource.
/// This is NOT an external high-water anchor or proof against full rollback.
fn verify_side_tables(conn: &Connection) -> Result<(), StoreError> {
    let diverged: i64 = conn
        .query_row(
            "SELECT
               EXISTS (
                 SELECT 1 FROM unified_policy_events AS e
                 LEFT JOIN unified_policy_outbox AS o
                   ON o.space=e.space AND o.resource=e.resource AND o.seq=e.seq
                 LEFT JOIN unified_policy_audit AS a
                   ON a.space=e.space AND a.resource=e.resource AND a.seq=e.seq
                 WHERE o.seq IS NULL OR o.kind!=e.kind OR o.evidence!=e.evidence
                    OR a.seq IS NULL OR a.kind!=e.kind OR a.policy_head!=e.policy_head
               )
               OR EXISTS (
                 SELECT 1 FROM unified_policy_outbox AS o
                 WHERE NOT EXISTS (
                   SELECT 1 FROM unified_policy_events AS e
                   WHERE e.space=o.space AND e.resource=o.resource AND e.seq=o.seq
                 )
               )
               OR EXISTS (
                 SELECT 1 FROM unified_policy_audit AS a
                 WHERE NOT EXISTS (
                   SELECT 1 FROM unified_policy_events AS e
                   WHERE e.space=a.space AND e.resource=a.resource AND e.seq=a.seq
                 )
               )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    if diverged != 0 {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn inspect_db(
    conn: &mut Connection,
    root: ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
) -> Result<JournalSnapshot, StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::PersistenceFailure)?;
    let state = replay(&tx, &root, genesis)?;
    let snapshot = snapshot(&state);
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(snapshot)
}

/// The revocation-only accumulator is deliberately distinct from the unified
/// policy head. Delegate cancellation and Owner transfer change policy_head
/// but do NOT append into this revocation-only chain.
fn revocation_root_for_journal(
    tx: &Transaction<'_>,
    root: &ExternallyPinnedRootForSpike,
    resource: ResourceId,
) -> Result<[u8; 32], StoreError> {
    let mut stmt = tx
        .prepare(
            "SELECT seq,evidence FROM unified_policy_events
         WHERE space=?1 AND resource=?2 AND kind=?3 ORDER BY seq ASC",
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    let rows = stmt
        .query_map(
            params![
                root.space.as_bytes().as_slice(),
                resource.as_bytes().as_slice(),
                i64::from(KIND_REVOKE),
            ],
            |row| {
                let seq: i64 = row.get(0)?;
                let bytes: Vec<u8> = row.get(1)?;
                Ok((seq, bytes))
            },
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    let mut hash = [0u8; 32];
    for row in rows {
        let (seq, evidence) = row.map_err(|_| StoreError::PersistenceFailure)?;
        let seq = u64::try_from(seq).map_err(|_| StoreError::Conflict)?;
        hash = append_revocation_root(hash, seq, &evidence).ok_or(StoreError::Conflict)?;
    }
    Ok(hash)
}

fn binding_error(error: BindingError) -> StoreError {
    match error {
        BindingError::CounterUnavailable
        | BindingError::JournalUnavailable
        | BindingError::PersistenceUncertain => StoreError::PersistenceFailure,
        BindingError::MissingBinding
        | BindingError::WrongCounterIdentity
        | BindingError::CounterMismatch
        | BindingError::CounterOverflow
        | BindingError::BrokenIntent
        | BindingError::InvalidWitnesses
        | BindingError::InvalidPolicyTransition => StoreError::Conflict,
    }
}

/// A full-policy identity comparison, not just a matching TPM number.
fn binding_matches_replayed(
    saved: StoredBinding,
    pin: PinnedCounterIdentity,
    genesis: &VerifiedResourceTrust,
    current: &VerifiedResourceTrust,
    checkpoint: Checkpoint,
) -> bool {
    let StoredBinding::Committed(binding) = saved else {
        return false;
    };
    let policy = binding.policy;
    binding.identity == pin
        && policy.space == genesis.space()
        && policy.resource == genesis.resource()
        && policy.root_public_key == genesis.root_public_key()
        && policy.root_key_epoch == genesis.root_key_epoch()
        && policy.genesis_manifest == genesis.manifest_commitment()
        && policy.current_manifest == current.manifest_commitment()
        && policy.writer_epoch == genesis.writer_epoch()
        && policy.policy_sequence == checkpoint.seq
        && policy.policy_head == checkpoint.head_hash
        && policy.revocation_root == checkpoint.revocation_root
}

/// Prove that the *independently supplied* prior counter binding is the
/// authenticated prefix of this exact signed SQLite policy history.
///
/// Verifying only the latest two-witness checkpoint cannot establish the
/// earlier policy-head / revocation-root / Owner-manifest committed by a
/// counter. A valid later checkpoint could otherwise be paired with a
/// fabricated earlier high-water state. The encompassing transaction first
/// replays and verifies the ENTIRE history, including all side-table mirrors.
/// This function verifies the prior prefix under the SAME SQLite write lock.
/// Neither SQLite nor the caller is an independent rollback-resistant anchor.
fn verify_signed_policy_prefix(
    tx: &Transaction<'_>,
    root: &ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
    prior: UnifiedPolicyHighWater,
) -> Result<(), StoreError> {
    if prior.space != genesis.space()
        || prior.resource != genesis.resource()
        || prior.root_public_key != genesis.root_public_key()
        || prior.root_key_epoch != genesis.root_key_epoch()
        || prior.genesis_manifest != genesis.manifest_commitment()
        || prior.writer_epoch != genesis.writer_epoch()
    {
        return Err(StoreError::Conflict);
    }
    // The SQLite INTEGER domain cannot hold an arbitrary u64. Do not
    // silently wrap, clamp, or reinterpret independently pinned sequence.
    let limit = i64::try_from(prior.policy_sequence).map_err(|_| StoreError::Conflict)?;
    let mut state = ResourceOwnerLifecycle::from_genesis(genesis);
    let mut revocation_root = [0u8; 32];
    let mut stmt = tx
        .prepare(
            "SELECT seq,kind,evidence,policy_head FROM unified_policy_events
             WHERE space=?1 AND resource=?2 AND seq<=?3 ORDER BY seq ASC",
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    let events = stmt
        .query_map(
            params![
                root.space.as_bytes().as_slice(),
                genesis.resource().as_bytes().as_slice(),
                limit
            ],
            |row| {
                let seq: i64 = row.get(0)?;
                let kind: i64 = row.get(1)?;
                let evidence: Vec<u8> = row.get(2)?;
                let head: Vec<u8> = row.get(3)?;
                Ok((seq, kind, evidence, head))
            },
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    for event in events {
        let (seq, kind, evidence, stored_head) =
            event.map_err(|_| StoreError::PersistenceFailure)?;
        let seq = u64::try_from(seq).map_err(|_| StoreError::Conflict)?;
        let kind = u8::try_from(kind).map_err(|_| StoreError::Conflict)?;
        if state.sequence().checked_add(1) != Some(seq) {
            return Err(StoreError::Conflict);
        }
        replay_event(&mut state, root, kind, &evidence)?;
        if state.sequence() != seq || state.policy_head().as_slice() != stored_head {
            return Err(StoreError::Conflict);
        }
        if kind == KIND_REVOKE {
            revocation_root =
                append_revocation_root(revocation_root, seq, &evidence)
                    .ok_or(StoreError::Conflict)?;
        }
    }
    if state.sequence() != prior.policy_sequence
        || state.policy_head() != prior.policy_head
        || revocation_root != prior.revocation_root
        || state.current_trust().manifest_commitment() != prior.current_manifest
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

/// A single DB write transaction covers the external *candidate* counter
/// operation. A second SQLite writer cannot replace the verified snapshot
/// between policy replay and increment. Counter and SQLite are still NOT
/// a durable distributed transaction across a power failure.
fn journal_bound_counter_transaction(
    conn: &mut Connection,
    root: ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
    receipts: &[SignedCheckpoint],
    now_ms: u64,
    io: &CandidateCounterIo,
    operation: CandidateCounterOperation,
) -> Result<Diagnostic, StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::PersistenceFailure)?;
    let verified = replay(&tx, &root, genesis)?;
    let current = verified.current_trust();
    let checkpoint = verify_root_bound_witnesses(&genesis, receipts, now_ms)
        .map_err(|_| StoreError::Conflict)?
        .checkpoint();
    let old_witnesses = genesis.witnesses();
    let new_witnesses = current.witnesses();
    if old_witnesses[0].public_key != new_witnesses[0].public_key
        || old_witnesses[1].public_key != new_witnesses[1].public_key
        || checkpoint.space != genesis.space()
        || checkpoint.resource != genesis.resource()
        || checkpoint.writer_epoch != genesis.writer_epoch()
        || checkpoint.seq != verified.sequence()
        || checkpoint.head_hash != verified.policy_head()
        || checkpoint.revocation_root
            != revocation_root_for_journal(&tx, &root, genesis.resource())?
    {
        return Err(StoreError::Conflict);
    }

    // Use the saved Committed policy, or the Prepared intent's committed
    // BEFORE state. A valid *next* checkpoint must not launder an invented
    // earlier policy prefix. No stage, finalize or counter increment occurs
    // until this proof succeeds. A missing intent is never auto-provisioned.
    let saved = io.intent.load().map_err(binding_error)?;
    let prior = match saved {
        StoredBinding::Committed(record) => record.policy,
        StoredBinding::Prepared(record) => record.before.policy,
        StoredBinding::Missing => return Err(StoreError::Conflict),
    };
    verify_signed_policy_prefix(&tx, &root, genesis, prior)?;

    let outcome = match operation {
        CandidateCounterOperation::Begin => begin_candidate_advance(
            io.counter.as_ref(),
            io.intent.as_ref(),
            io.pin,
            &genesis,
            &current,
            receipts,
            now_ms,
        ),
        CandidateCounterOperation::Reconcile => reconcile_candidate_advance(
            io.counter.as_ref(),
            io.intent.as_ref(),
            io.pin,
            &genesis,
            &current,
            receipts,
            now_ms,
        ),
    }
    .map_err(binding_error)?;

    // "MatchingCounterOnly" must never be emitted for an old committed
    // policy while SQLite has moved on. The model's raw reconciliation
    // routine may return it after a mere numeric equality.
    if outcome == Diagnostic::MatchingCounterOnly {
        let saved = io.intent.load().map_err(binding_error)?;
        let observed = io.counter.read().map_err(binding_error)?;
        if inspect_counter(io.pin, observed, saved).map_err(binding_error)?
            != Diagnostic::MatchingCounterOnly
            || !binding_matches_replayed(saved, io.pin, &genesis, &current, checkpoint)
        {
            return Err(StoreError::Conflict);
        }
    }
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(outcome)
}

fn inspect_checkpoint_db(
    conn: &mut Connection,
    root: ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
) -> Result<JournalCheckpointState, StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::PersistenceFailure)?;
    let verified = replay(&tx, &root, genesis)?;
    let revocation_root = revocation_root_for_journal(&tx, &root, genesis.resource())?;
    let result = JournalCheckpointState {
        snapshot: snapshot(&verified),
        revocation_root,
        current_trust: verified.current_trust(),
    };
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(result)
}

/// Only runs *after* successful external durable CAS. SQLite and an external
/// platform monotonic counter are NOT a distributed atomic transaction.
/// Confirmation is purely local bookkeeping; missing/forged markers cannot
/// enable admission. Must revalidate the exact journal state under BEGIN
/// IMMEDIATE to prevent mislabeling a newer append.
fn record_witness_confirmation(
    conn: &mut Connection,
    root: ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
    checkpoint: Checkpoint,
    expected_manifest: [u8; 32],
) -> Result<(), StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::PersistenceFailure)?;
    let state = replay(&tx, &root, genesis)?;
    let revocation_root = revocation_root_for_journal(&tx, &root, genesis.resource())?;
    if checkpoint.space != genesis.space()
        || checkpoint.resource != genesis.resource()
        || checkpoint.writer_epoch != genesis.writer_epoch()
        || checkpoint.seq != state.sequence()
        || checkpoint.head_hash != state.policy_head()
        || checkpoint.revocation_root != revocation_root
        || expected_manifest != state.current_trust().manifest_commitment()
    {
        return Err(StoreError::Conflict);
    }
    let seq = i64::try_from(checkpoint.seq).map_err(|_| StoreError::Conflict)?;
    tx.execute(
        "INSERT INTO unified_policy_witnessed
           (space,resource,seq,policy_head,revocation_root,owner_manifest)
         VALUES(?1,?2,?3,?4,?5,?6)
         ON CONFLICT(space,resource) DO UPDATE SET
           seq=excluded.seq, policy_head=excluded.policy_head,
           revocation_root=excluded.revocation_root,
           owner_manifest=excluded.owner_manifest
         WHERE excluded.seq >= unified_policy_witnessed.seq",
        params![
            checkpoint.space.as_bytes().as_slice(),
            checkpoint.resource.as_bytes().as_slice(),
            seq,
            checkpoint.head_hash.as_slice(),
            checkpoint.revocation_root.as_slice(),
            expected_manifest.as_slice(),
        ],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(())
}

fn append_transaction(
    conn: &mut Connection,
    root: ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
    kind: u8,
    evidence: &[u8],
) -> Result<JournalSnapshot, StoreError> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE {
        return Err(StoreError::Conflict);
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::PersistenceFailure)?;
    let mut state = replay(&tx, &root, genesis)?;
    replay_event(&mut state, &root, kind, evidence)?;
    let seq = i64::try_from(state.sequence()).map_err(|_| StoreError::Conflict)?;
    let head = state.policy_head();
    let space = root.space.as_bytes().as_slice();
    let resource_id = genesis.resource();
    let resource = resource_id.as_bytes().as_slice();
    tx.execute(
        "INSERT INTO unified_policy_events(space,resource,seq,kind,evidence,policy_head)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![space, resource, seq, kind, evidence, head.as_slice()],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO unified_policy_cursor(space,resource,seq,policy_head,owner_manifest)
         VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(space,resource) DO UPDATE SET
           seq=excluded.seq,policy_head=excluded.policy_head,
           owner_manifest=excluded.owner_manifest",
        params![
            space,
            resource,
            seq,
            head.as_slice(),
            state.current_trust().manifest_commitment().as_slice(),
        ],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO unified_policy_outbox(space,resource,seq,kind,evidence)
         VALUES(?1,?2,?3,?4,?5)",
        params![space, resource, seq, kind, evidence],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO unified_policy_audit(space,resource,seq,kind,policy_head)
         VALUES(?1,?2,?3,?4,?5)",
        params![space, resource, seq, kind, head.as_slice()],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    // SQLite triggers can mutate a mirror after earlier writes succeeded.
    // Reject the whole transaction before COMMIT on any divergence.
    verify_side_tables(&tx)?;
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(snapshot(&state))
}

fn read_outbox(conn: &mut Connection) -> Result<Vec<CriticalPolicyOutbox>, StoreError> {
    // Verify and read the mirrors under one SQLite transaction to prevent
    // a concurrent external writer from changing them between the two steps.
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::PersistenceFailure)?;
    verify_side_tables(&tx)?;
    let outbox = {
        let mut stmt = tx
            .prepare("SELECT seq,kind,evidence FROM unified_policy_outbox ORDER BY id ASC")
            .map_err(|_| StoreError::PersistenceFailure)?;
        let rows = stmt
            .query_map([], |row| {
                let seq: i64 = row.get(0)?;
                let kind: i64 = row.get(1)?;
                let evidence: Vec<u8> = row.get(2)?;
                Ok((seq, kind, evidence))
            })
            .map_err(|_| StoreError::PersistenceFailure)?;
        let mut outbox = Vec::new();
        for row in rows {
            let (seq, kind, evidence) = row.map_err(|_| StoreError::PersistenceFailure)?;
            outbox.push(CriticalPolicyOutbox {
                sequence: u64::try_from(seq).map_err(|_| StoreError::Conflict)?,
                kind: u8::try_from(kind).map_err(|_| StoreError::Conflict)?,
                evidence,
            });
        }
        outbox
    };
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(outbox)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_journal_codec::{KIND_CANCEL, KIND_REVOKE, KIND_TRANSFER};
    use ed25519_dalek::{Signer, SigningKey};
    use loom_crypto::owner_authority::{
        OwnerVerifiedRevocation, ProvisionedOwnerForSpike, issuer_key_id,
        verify_owner_delegated_revocation_for_spike,
    };
    use loom_crypto::owner_lifecycle::{
        DelegateCancellation, DualSignedOwnerTransfer, OwnerTransfer, SignedDelegateCancellation,
        cancellation_transcript, owner_transfer_transcript,
    };
    use loom_crypto::space_trust::{
        ResourceTrustManifest, SignedResourceTrust, trust_manifest_transcript,
        verify_resource_trust_for_spike,
    };
    use loom_wire::security_event::{
        CanonicalSecurityEvent, EventKind, encode_security_event, signing_input,
    };
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDb(PathBuf);
    impl TempDb {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "loom-unified-{}-{nanos}.sqlite",
                std::process::id(),
            )))
        }
        fn open(&self) -> UnifiedPolicyJournal {
            UnifiedPolicyJournal::open(self.0.clone()).unwrap()
        }
    }
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    fn root_pin() -> ExternallyPinnedRootForSpike {
        ExternallyPinnedRootForSpike {
            space: SpaceId::from_bytes([1; 16]),
            public_key: SigningKey::from_bytes(&[30; 32]).verifying_key().to_bytes(),
            key_epoch: 7,
        }
    }

    fn signed_manifest(owner_seed: u8, epoch: u64) -> SignedResourceTrust {
        let pin = root_pin();
        let signer = SigningKey::from_bytes(&[30; 32]);
        let owner = SigningKey::from_bytes(&[owner_seed; 32]);
        let witness_a = SigningKey::from_bytes(&[21; 32]);
        let witness_b = SigningKey::from_bytes(&[22; 32]);
        let manifest = ResourceTrustManifest {
            space: pin.space,
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner.verifying_key().to_bytes(),
            owner_key_epoch: epoch,
            witness_public_keys: [
                witness_a.verifying_key().to_bytes(),
                witness_b.verifying_key().to_bytes(),
            ],
            writer_epoch: 1,
            root_key_epoch: pin.key_epoch,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        SignedResourceTrust {
            manifest,
            signature: signer
                .sign(&trust_manifest_transcript(&manifest))
                .to_bytes(),
        }
    }

    fn trusted_genesis() -> VerifiedResourceTrust {
        verify_resource_trust_for_spike(&root_pin(), &signed_manifest(11, 3), 150).unwrap()
    }

    fn signed_revocation(seq: u64, owner_seed: u8, owner_epoch: u64) -> OwnerVerifiedRevocation {
        let signer = SigningKey::from_bytes(&[owner_seed; 32]);
        let delegate = SigningKey::from_bytes(&[12; 32]);
        let delegate_key = delegate.verifying_key().to_bytes();
        let pin = root_pin();
        let resource = ResourceId::from_bytes([2; 16]);
        let mut grant_payload = resource.as_bytes().to_vec();
        grant_payload.extend_from_slice(&delegate_key);
        grant_payload.extend_from_slice(&issuer_key_id(&delegate_key));
        grant_payload.push(1);
        grant_payload.extend_from_slice(&4u64.to_be_bytes());
        let grant = CanonicalSecurityEvent {
            kind: EventKind::OwnerGrant,
            space_id: *pin.space.as_bytes(),
            signer_key_id: issuer_key_id(&signer.verifying_key().to_bytes()),
            issuer_epoch: owner_epoch,
            issued_at_ms: 100,
            expires_at_ms: 300,
            seq: 1,
            payload: grant_payload,
        };
        let mut revocation_payload = resource.as_bytes().to_vec();
        revocation_payload.extend_from_slice(&[5; 32]);
        revocation_payload.push(3);
        let revoke = CanonicalSecurityEvent {
            kind: EventKind::Revocation,
            space_id: *pin.space.as_bytes(),
            signer_key_id: issuer_key_id(&delegate_key),
            issuer_epoch: 4,
            issued_at_ms: 120,
            expires_at_ms: 250,
            seq,
            payload: revocation_payload,
        };
        let grant_cbor = encode_security_event(&grant).unwrap();
        let revoke_cbor = encode_security_event(&revoke).unwrap();
        verify_owner_delegated_revocation_for_spike(
            &ProvisionedOwnerForSpike {
                space_id: pin.space,
                resource_id: resource,
                public_key: signer.verifying_key().to_bytes(),
                current_key_epoch: owner_epoch,
            },
            &grant_cbor,
            &signer.sign(&signing_input(&grant_cbor).unwrap()).to_bytes(),
            &revoke_cbor,
            &delegate
                .sign(&signing_input(&revoke_cbor).unwrap())
                .to_bytes(),
            150,
        )
        .unwrap()
    }

    fn signed_cancellation(seq: u64) -> SignedDelegateCancellation {
        let owner = SigningKey::from_bytes(&[11; 32]);
        let delegate = SigningKey::from_bytes(&[12; 32]);
        let event = DelegateCancellation {
            space: SpaceId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner.verifying_key().to_bytes(),
            owner_epoch: 3,
            delegate_key_id: issuer_key_id(&delegate.verifying_key().to_bytes()),
            delegate_epoch: 4,
            sequence: seq,
            issued_at_ms: 120,
            expires_at_ms: 250,
        };
        SignedDelegateCancellation {
            cancellation: event,
            signature: owner.sign(&cancellation_transcript(&event)).to_bytes(),
        }
    }

    fn signed_transfer(
        prior: &VerifiedResourceTrust,
        successor: &SignedResourceTrust,
        seq: u64,
    ) -> DualSignedOwnerTransfer {
        let next = verify_resource_trust_for_spike(&root_pin(), successor, 150).unwrap();
        let event = OwnerTransfer {
            space: prior.space(),
            resource: prior.resource(),
            prior_manifest: prior.manifest_commitment(),
            successor_manifest: next.manifest_commitment(),
            previous_owner_public_key: prior.owner().public_key,
            successor_owner_public_key: next.owner().public_key,
            previous_owner_epoch: prior.owner().current_key_epoch,
            successor_owner_epoch: next.owner().current_key_epoch,
            sequence: seq,
            issued_at_ms: 120,
            expires_at_ms: 250,
        };
        let bytes = owner_transfer_transcript(&event);
        DualSignedOwnerTransfer {
            transfer: event,
            old_owner_signature: SigningKey::from_bytes(&[11; 32]).sign(&bytes).to_bytes(),
            next_owner_signature: SigningKey::from_bytes(&[33; 32]).sign(&bytes).to_bytes(),
        }
    }

    #[test]
    fn unified_lifecycle_replays_from_genesis_after_restart() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        assert!(store.inspect(root_pin(), genesis).unwrap().admission_paused);
        let revocation = signed_revocation(1, 11, 3);
        let first = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&revocation))
            .unwrap();
        assert_eq!(first.sequence, 1);
        let cancellation = signed_cancellation(2);
        let second = store
            .append(root_pin(), genesis, NewPolicyEvent::Cancel(&cancellation))
            .unwrap();
        assert_eq!(second.sequence, 2);
        assert_ne!(first.policy_head, second.policy_head);
        assert_eq!(
            store.append(
                root_pin(),
                genesis,
                NewPolicyEvent::Revoke(&signed_revocation(3, 11, 3))
            ),
            Err(StoreError::Conflict)
        );
        let successor = signed_manifest(33, 4);
        let transfer = signed_transfer(&genesis, &successor, 3);
        let third = store
            .append(
                root_pin(),
                genesis,
                NewPolicyEvent::Transfer {
                    transfer: &transfer,
                    successor_manifest: &successor,
                },
            )
            .unwrap();
        assert_eq!(third.sequence, 3);
        assert_eq!(
            store.append(
                root_pin(),
                genesis,
                NewPolicyEvent::Revoke(&signed_revocation(4, 11, 3))
            ),
            Err(StoreError::Conflict)
        );
        let last = store
            .append(
                root_pin(),
                genesis,
                NewPolicyEvent::Revoke(&signed_revocation(4, 33, 4)),
            )
            .unwrap();
        assert_eq!(last.sequence, 4);
        assert_eq!(
            last.owner_public_key,
            SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes()
        );
        assert!(last.admission_paused);
        let outbox = store.pending_outbox().unwrap();
        assert_eq!(
            outbox.iter().map(|e| e.kind).collect::<Vec<_>>(),
            vec![KIND_REVOKE, KIND_CANCEL, KIND_TRANSFER, KIND_REVOKE]
        );
        assert_eq!(
            outbox.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        drop(store);
        let restored = db.open();
        assert_eq!(restored.inspect(root_pin(), genesis).unwrap(), last);
        assert_eq!(restored.pending_outbox().unwrap(), outbox);
    }

    #[test]
    fn old_signed_delegate_remains_blocked_after_restart() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        store
            .append(
                root_pin(),
                genesis,
                NewPolicyEvent::Revoke(&signed_revocation(1, 11, 3)),
            )
            .unwrap();
        let cancellation = signed_cancellation(2);
        store
            .append(root_pin(), genesis, NewPolicyEvent::Cancel(&cancellation))
            .unwrap();
        drop(store);
        let store = db.open();
        assert_eq!(
            store.append(
                root_pin(),
                genesis,
                NewPolicyEvent::Revoke(&signed_revocation(3, 11, 3),)
            ),
            Err(StoreError::Conflict)
        );
        assert_eq!(store.inspect(root_pin(), genesis).unwrap().sequence, 2);
    }

    #[test]
    fn stored_evidence_tampering_cannot_be_hidden_by_cursor() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        store
            .append(
                root_pin(),
                genesis,
                NewPolicyEvent::Revoke(&signed_revocation(1, 11, 3)),
            )
            .unwrap();
        drop(store);
        let conn = Connection::open(&db.0).unwrap();
        conn.execute(
            "UPDATE unified_policy_events SET evidence=?1 WHERE seq=1",
            [b"valid BLOB type, invalid signatures".as_slice()],
        )
        .unwrap();
        drop(conn);
        let reopened = db.open();
        assert_eq!(
            reopened.inspect(root_pin(), genesis),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn outbox_insert_failure_rolls_back_event_cursor_and_audit() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let conn = Connection::open(&db.0).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_outbox BEFORE INSERT ON unified_policy_outbox
             BEGIN SELECT RAISE(ABORT, 'simulated-full-disk'); END;",
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            store.append(
                root_pin(),
                genesis,
                NewPolicyEvent::Revoke(&signed_revocation(1, 11, 3),)
            ),
            Err(StoreError::PersistenceFailure)
        );
        assert_eq!(store.inspect(root_pin(), genesis).unwrap().sequence, 0);
        assert!(store.pending_outbox().unwrap().is_empty());
        let conn = Connection::open(&db.0).unwrap();
        for name in [
            "unified_policy_events",
            "unified_policy_cursor",
            "unified_policy_audit",
            "unified_policy_outbox",
        ] {
            let sql = format!("SELECT COUNT(*) FROM {name}");
            assert_eq!(
                conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        conn.execute_batch("DROP TRIGGER reject_outbox").unwrap();
        drop(conn);
        assert_eq!(
            store
                .append(
                    root_pin(),
                    genesis,
                    NewPolicyEvent::Revoke(&signed_revocation(1, 11, 3),)
                )
                .unwrap()
                .sequence,
            1,
        );
    }

    #[test]
    fn concurrent_identical_resource_version_has_single_winner() {
        let db = TempDb::new();
        let store = Arc::new(db.open());
        let genesis = trusted_genesis();
        let proof = signed_revocation(1, 11, 3);
        let mut handles = Vec::new();
        for _ in 0..6 {
            let db = Arc::clone(&store);
            let proof = proof.clone();
            handles.push(thread::spawn(move || {
                db.append(root_pin(), genesis, NewPolicyEvent::Revoke(&proof))
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(StoreError::Conflict))
                .count(),
            5
        );
        assert_eq!(store.pending_outbox().unwrap().len(), 1);
        assert_eq!(store.inspect(root_pin(), genesis).unwrap().sequence, 1);
    }

    #[test]
    fn genesis_root_substitution_is_rejected_before_history_access() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let mut impostor = root_pin();
        impostor.public_key = SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes();
        assert_eq!(store.inspect(impostor, genesis), Err(StoreError::Conflict));
        assert!(store.pending_outbox().unwrap().is_empty());
    }

    #[test]
    fn successor_manifest_is_not_trusted_from_sqlite_or_unpinned_root() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let successor = signed_manifest(33, 4);
        let transfer = signed_transfer(&genesis, &successor, 1);
        let mut forged = signed_manifest(33, 4);
        forged.signature[7] ^= 1;
        assert_eq!(
            store.append(
                root_pin(),
                genesis,
                NewPolicyEvent::Transfer {
                    transfer: &transfer,
                    successor_manifest: &forged,
                }
            ),
            Err(StoreError::Conflict)
        );
        assert_eq!(store.inspect(root_pin(), genesis).unwrap().sequence, 0);
    }

    struct FakeExternalAnchor {
        state: Mutex<crate::unified_policy_anchor::UnifiedPolicyHighWater>,
        missing: bool,
        fail_cas: bool,
    }

    impl crate::unified_policy_anchor::IndependentUnifiedPolicyAnchor for FakeExternalAnchor {
        fn read(
            &self,
            space: SpaceId,
            resource: ResourceId,
        ) -> Result<
            crate::unified_policy_anchor::UnifiedPolicyHighWater,
            crate::unified_policy_anchor::UnifiedAnchorError,
        > {
            use crate::unified_policy_anchor::UnifiedAnchorError;
            if self.missing {
                return Err(UnifiedAnchorError::MissingOrUntrusted);
            }
            let state = *self.state.lock().unwrap();
            if state.space != space || state.resource != resource {
                return Err(UnifiedAnchorError::IdentityOrManifestMismatch);
            }
            Ok(state)
        }

        fn compare_and_advance(
            &self,
            expected: crate::unified_policy_anchor::UnifiedPolicyHighWater,
            next: crate::unified_policy_anchor::UnifiedPolicyHighWater,
        ) -> Result<(), crate::unified_policy_anchor::UnifiedAnchorError> {
            use crate::unified_policy_anchor::UnifiedAnchorError;
            if self.fail_cas {
                return Err(UnifiedAnchorError::PersistenceUncertain);
            }
            let mut guard = self.state.lock().unwrap();
            if *guard != expected {
                return Err(UnifiedAnchorError::ConcurrentUpdate);
            }
            if next.policy_sequence < guard.policy_sequence {
                return Err(UnifiedAnchorError::StaleState);
            }
            *guard = next;
            Ok(())
        }
    }

    fn fake_anchor(genesis: &VerifiedResourceTrust) -> FakeExternalAnchor {
        FakeExternalAnchor {
            state: Mutex::new(
                crate::unified_policy_anchor::UnifiedPolicyHighWater::initial(genesis),
            ),
            missing: false,
            fail_cas: false,
        }
    }

    fn witness_receipts(
        seq: u64,
        policy_head: [u8; 32],
        revoke_root: [u8; 32],
    ) -> [SignedCheckpoint; 2] {
        use loom_crypto::witness_checkpoint::{
            Checkpoint, TrustedWitnessForSpike, checkpoint_transcript,
        };
        let first = SigningKey::from_bytes(&[21; 32]);
        let second = SigningKey::from_bytes(&[22; 32]);
        let genesis = trusted_genesis();
        let checkpoint = Checkpoint {
            space: genesis.space(),
            resource: genesis.resource(),
            writer_epoch: genesis.writer_epoch(),
            seq,
            head_hash: policy_head,
            revocation_root: revoke_root,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let transcript = checkpoint_transcript(&checkpoint);
        [first, second].map(|key| SignedCheckpoint {
            witness_key_id: TrustedWitnessForSpike::from_public_key(key.verifying_key().to_bytes())
                .key_id,
            checkpoint,
            signature: key.sign(&transcript).to_bytes(),
        })
    }

    fn witnessed(
        db: &UnifiedPolicyJournal,
        genesis: VerifiedResourceTrust,
        receipts: &[SignedCheckpoint],
        anchor: &FakeExternalAnchor,
    ) -> Result<UnifiedRecoveryAssessment, StoreError> {
        db.inspect_witnessed_recovery(root_pin(), genesis, receipts, 150, anchor)
    }

    #[test]
    fn cancellation_is_witnessed_by_policy_head_not_just_revocation_root() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let proof = signed_revocation(1, 11, 3);
        let first = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&proof))
            .unwrap();
        let revoke_root = append_revocation_root([0; 32], 1, &proof.persistence_bytes()).unwrap();
        let canceled = signed_cancellation(2);
        let second = store
            .append(root_pin(), genesis, NewPolicyEvent::Cancel(&canceled))
            .unwrap();
        assert_ne!(first.policy_head, second.policy_head);
        let receipts = witness_receipts(2, second.policy_head, revoke_root);
        let anchor = fake_anchor(&genesis);
        assert_eq!(
            witnessed(&store, genesis, &receipts, &anchor),
            Ok(UnifiedRecoveryAssessment::CandidateConsistent)
        );
        let committed = *anchor.state.lock().unwrap();
        assert_eq!(committed.policy_sequence, 2);
        assert_eq!(committed.policy_head, second.policy_head);
        assert_eq!(committed.revocation_root, revoke_root);
        assert!(second.admission_paused);
        drop(store);
        let restored = db.open();
        assert_eq!(
            witnessed(&restored, genesis, &receipts, &anchor),
            Ok(UnifiedRecoveryAssessment::CandidateConsistent)
        );
        assert!(
            restored
                .inspect(root_pin(), genesis)
                .unwrap()
                .admission_paused
        );
    }

    #[test]
    fn two_consistent_but_stale_witnesses_cannot_rollback_cancelled_delegate() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let proof = signed_revocation(1, 11, 3);
        let first = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&proof))
            .unwrap();
        let rev_root = append_revocation_root([0; 32], 1, &proof.persistence_bytes()).unwrap();
        let cancel = signed_cancellation(2);
        let second = store
            .append(root_pin(), genesis, NewPolicyEvent::Cancel(&cancel))
            .unwrap();
        let anchor = fake_anchor(&genesis);
        assert_eq!(
            witnessed(
                &store,
                genesis,
                &witness_receipts(2, second.policy_head, rev_root),
                &anchor
            ),
            Ok(UnifiedRecoveryAssessment::CandidateConsistent)
        );
        let old_db = TempDb::new();
        let old_store = old_db.open();
        old_store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&proof))
            .unwrap();
        let old_receipts = witness_receipts(1, first.policy_head, rev_root);
        assert_eq!(
            witnessed(&old_store, genesis, &old_receipts, &anchor),
            Err(StoreError::Conflict)
        );
        assert!(
            old_store
                .inspect(root_pin(), genesis)
                .unwrap()
                .admission_paused
        );
        assert_eq!(anchor.state.lock().unwrap().policy_sequence, 2);
    }

    #[test]
    fn witness_policy_head_cannot_be_substituted_with_matching_revocation_root() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let proof = signed_revocation(1, 11, 3);
        store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&proof))
            .unwrap();
        let cancel = signed_cancellation(2);
        let second = store
            .append(root_pin(), genesis, NewPolicyEvent::Cancel(&cancel))
            .unwrap();
        let revoke_root = append_revocation_root([0; 32], 1, &proof.persistence_bytes()).unwrap();
        let forged = witness_receipts(2, [89; 32], revoke_root);
        assert_eq!(
            witnessed(&store, genesis, &forged, &fake_anchor(&genesis)),
            Ok(UnifiedRecoveryAssessment::HistoryConflict)
        );
        let corrupted_anchor = fake_anchor(&genesis);
        let expected = witness_receipts(2, second.policy_head, revoke_root);
        {
            let mut guard = corrupted_anchor.state.lock().unwrap();
            guard.policy_sequence = 2;
            guard.revocation_root = revoke_root;
            guard.policy_head = [78; 32];
        }
        assert_eq!(
            witnessed(&store, genesis, &expected, &corrupted_anchor),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn absent_or_ambiguous_external_anchor_never_approves_recovery() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let receipts = witness_receipts(0, [0; 32], [0; 32]);
        let mut missing = fake_anchor(&genesis);
        missing.missing = true;
        assert_eq!(
            witnessed(&store, genesis, &receipts, &missing),
            Err(StoreError::PersistenceFailure)
        );
        let mut failed_cas = fake_anchor(&genesis);
        failed_cas.fail_cas = true;
        assert_eq!(
            witnessed(&store, genesis, &receipts, &failed_cas),
            Err(StoreError::PersistenceFailure)
        );
        assert_eq!(failed_cas.state.lock().unwrap().policy_sequence, 0);
    }

    #[test]
    fn changed_witness_signature_or_writer_epoch_is_rejected() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let mut invalid = witness_receipts(0, [0; 32], [0; 32]);
        invalid[0].signature[4] ^= 1;
        assert_eq!(
            witnessed(&store, genesis, &invalid, &fake_anchor(&genesis)),
            Err(StoreError::Conflict)
        );
        let mut wrong_epoch = witness_receipts(0, [0; 32], [0; 32]);
        wrong_epoch[0].checkpoint.writer_epoch = 2;
        assert_eq!(
            witnessed(&store, genesis, &wrong_epoch, &fake_anchor(&genesis)),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn transferred_owner_manifest_advances_only_after_both_signatures() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let successor = signed_manifest(33, 4);
        let transfer = signed_transfer(&genesis, &successor, 1);
        let after = store
            .append(
                root_pin(),
                genesis,
                NewPolicyEvent::Transfer {
                    transfer: &transfer,
                    successor_manifest: &successor,
                },
            )
            .unwrap();
        let anchor = fake_anchor(&genesis);
        let cp = witness_receipts(1, after.policy_head, [0; 32]);
        assert_eq!(
            witnessed(&store, genesis, &cp, &anchor),
            Ok(UnifiedRecoveryAssessment::CandidateConsistent)
        );
        let current = anchor.state.lock().unwrap();
        assert_eq!(current.policy_sequence, 1);
        assert_ne!(current.current_manifest, current.genesis_manifest);
        assert_eq!(current.policy_head, after.policy_head);
        assert_eq!(current.revocation_root, [0; 32]);
    }

    #[test]
    fn receipt_cannot_skip_persisted_policy_sequence_or_mask_history_conflict() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let proof = signed_revocation(1, 11, 3);
        let first = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&proof))
            .unwrap();
        let root = append_revocation_root([0; 32], 1, &proof.persistence_bytes()).unwrap();
        assert_eq!(
            witnessed(
                &store,
                genesis,
                &witness_receipts(2, [9; 32], root),
                &fake_anchor(&genesis)
            ),
            Ok(UnifiedRecoveryAssessment::LocalBehind)
        );
        assert_eq!(
            witnessed(
                &store,
                genesis,
                &witness_receipts(0, [0; 32], [0; 32]),
                &fake_anchor(&genesis)
            ),
            Ok(UnifiedRecoveryAssessment::WitnessBehind)
        );
        assert_eq!(
            witnessed(
                &store,
                genesis,
                &witness_receipts(1, first.policy_head, [99; 32]),
                &fake_anchor(&genesis)
            ),
            Ok(UnifiedRecoveryAssessment::HistoryConflict)
        );
    }

    fn local_confirmed_seq(path: &PathBuf) -> Option<i64> {
        let connection = Connection::open(path).unwrap();
        connection
            .query_row(
                "SELECT seq FROM unified_policy_witnessed WHERE space=?1 AND resource=?2",
                params![[1u8; 16].as_slice(), [2u8; 16].as_slice()],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
    }

    #[test]
    fn legacy_revocation_schema_cannot_be_silently_opened_as_empty_unified_history() {
        let db = TempDb::new();
        let connection = Connection::open(&db.0).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE policy_versions (
               space BLOB, resource BLOB, epoch INTEGER
             );
             CREATE TABLE revocations (
               space BLOB, resource BLOB, epoch INTEGER, signed_event BLOB
             );
             INSERT INTO policy_versions VALUES (
               x'01010101010101010101010101010101',
               x'02020202020202020202020202020202', 1
             );
             INSERT INTO revocations VALUES (
               x'01010101010101010101010101010101',
               x'02020202020202020202020202020202', 1, x'FFFF'
             );",
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            UnifiedPolicyJournal::open(db.0.clone()),
            Err(StoreError::Conflict),
        ));
        let preserved = Connection::open(&db.0).unwrap();
        let count: i64 = preserved
            .query_row("SELECT COUNT(*) FROM revocations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let unified_exists: i64 = preserved
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
             WHERE type='table' AND name='unified_policy_events'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unified_exists, 0);
    }

    #[test]
    fn witness_confirmation_recorded_only_after_successful_external_cas() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let proof = signed_revocation(1, 11, 3);
        let after = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&proof))
            .unwrap();
        assert_eq!(local_confirmed_seq(&db.0), None);
        let revocation = append_revocation_root([0; 32], 1, &proof.persistence_bytes()).unwrap();
        let receipts = witness_receipts(1, after.policy_head, revocation);
        let anchor = fake_anchor(&genesis);
        assert_eq!(
            witnessed(&store, genesis, &receipts, &anchor),
            Ok(UnifiedRecoveryAssessment::CandidateConsistent)
        );
        assert_eq!(local_confirmed_seq(&db.0), Some(1));
        assert_eq!(anchor.state.lock().unwrap().policy_sequence, 1);
        assert!(store.inspect(root_pin(), genesis).unwrap().admission_paused);
        drop(store);
        let restarted = db.open();
        assert_eq!(
            witnessed(&restarted, genesis, &receipts, &anchor),
            Ok(UnifiedRecoveryAssessment::CandidateConsistent)
        );
        assert_eq!(local_confirmed_seq(&db.0), Some(1));
    }

    #[test]
    fn durable_anchor_cas_before_sql_marker_failure_is_recoverable_without_ready() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let proof = signed_revocation(1, 11, 3);
        let after = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&proof))
            .unwrap();
        let revocation = append_revocation_root([0; 32], 1, &proof.persistence_bytes()).unwrap();
        let receipts = witness_receipts(1, after.policy_head, revocation);
        let anchor = fake_anchor(&genesis);

        let conn = Connection::open(&db.0).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER interrupt_after_external_cas
             BEFORE INSERT ON unified_policy_witnessed
             BEGIN SELECT RAISE(ABORT, 'simulated-power-loss-before-marker'); END;",
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            witnessed(&store, genesis, &receipts, &anchor),
            Err(StoreError::PersistenceFailure)
        );
        assert_eq!(anchor.state.lock().unwrap().policy_sequence, 1);
        assert_eq!(local_confirmed_seq(&db.0), None);
        assert!(store.inspect(root_pin(), genesis).unwrap().admission_paused);
        drop(store);

        let conn = Connection::open(&db.0).unwrap();
        conn.execute_batch("DROP TRIGGER interrupt_after_external_cas")
            .unwrap();
        drop(conn);
        let restarted = db.open();
        assert_eq!(local_confirmed_seq(&db.0), None);
        assert_eq!(
            witnessed(&restarted, genesis, &receipts, &anchor),
            Ok(UnifiedRecoveryAssessment::CandidateConsistent)
        );
        assert_eq!(local_confirmed_seq(&db.0), Some(1));
        assert!(
            restarted
                .inspect(root_pin(), genesis)
                .unwrap()
                .admission_paused
        );
    }

    #[test]
    fn ambiguous_external_cas_leaves_no_local_confirmation() {
        let genesis = trusted_genesis();
        let db = TempDb::new();
        let store = db.open();
        let receipts = witness_receipts(0, [0; 32], [0; 32]);
        let mut anchor = fake_anchor(&genesis);
        anchor.fail_cas = true;
        assert_eq!(
            witnessed(&store, genesis, &receipts, &anchor),
            Err(StoreError::PersistenceFailure)
        );
        assert_eq!(local_confirmed_seq(&db.0), None);
        assert_eq!(anchor.state.lock().unwrap().policy_sequence, 0);
    }

    #[test]
    fn mirror_rewrite_trigger_rolls_back_entire_append() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let conn = Connection::open(&db.0).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER tamper_outbox_after_audit
             AFTER INSERT ON unified_policy_audit
             BEGIN
               UPDATE unified_policy_outbox SET evidence=x'01'
               WHERE space=NEW.space AND resource=NEW.resource AND seq=NEW.seq;
             END;",
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            store.append(
                root_pin(),
                genesis,
                NewPolicyEvent::Revoke(&signed_revocation(1, 11, 3)),
            ),
            Err(StoreError::Conflict)
        );
        // The changed Outbox was in the same rolled-back transaction.
        assert_eq!(store.inspect(root_pin(), genesis).unwrap().sequence, 0);
        assert!(store.pending_outbox().unwrap().is_empty());

        let conn = Connection::open(&db.0).unwrap();
        conn.execute_batch("DROP TRIGGER tamper_outbox_after_audit")
            .unwrap();
        drop(conn);
        assert_eq!(
            store
                .append(
                    root_pin(),
                    genesis,
                    NewPolicyEvent::Revoke(&signed_revocation(1, 11, 3)),
                )
                .unwrap()
                .sequence,
            1
        );
    }

    #[test]
    fn mirrored_outbox_and_audit_tampering_fail_closed() {
        // Tamper with one local SQL mirror while leaving signed events intact.
        let attacks = [
            "DELETE FROM unified_policy_outbox WHERE seq=1",
            "UPDATE unified_policy_outbox SET evidence=x'01' WHERE seq=1",
            "UPDATE unified_policy_outbox SET kind=3 WHERE seq=1",
            "INSERT INTO unified_policy_outbox(space,resource,seq,kind,evidence)
             SELECT space,resource,2,kind,evidence FROM unified_policy_events WHERE seq=1",
            "DELETE FROM unified_policy_audit WHERE seq=1",
            "UPDATE unified_policy_audit SET policy_head=zeroblob(32) WHERE seq=1",
            "UPDATE unified_policy_audit SET kind=3 WHERE seq=1",
            "INSERT INTO unified_policy_audit(space,resource,seq,kind,policy_head)
             SELECT space,resource,2,kind,policy_head FROM unified_policy_events WHERE seq=1",
        ];
        for attack in attacks {
            let db = TempDb::new();
            let genesis = trusted_genesis();
            {
                let store = db.open();
                store
                    .append(
                        root_pin(),
                        genesis,
                        NewPolicyEvent::Revoke(&signed_revocation(1, 11, 3)),
                    )
                    .unwrap();
                assert_eq!(store.pending_outbox().unwrap().len(), 1);
            }
            let conn = Connection::open(&db.0).unwrap();
            conn.execute_batch(attack).unwrap();
            drop(conn);

            let store = db.open();
            assert_eq!(
                store.inspect(root_pin(), genesis),
                Err(StoreError::Conflict),
                "{attack}"
            );
            assert_eq!(
                store.pending_outbox(),
                Err(StoreError::Conflict),
                "{attack}"
            );
            assert_eq!(
                store.append(
                    root_pin(),
                    genesis,
                    NewPolicyEvent::Cancel(&signed_cancellation(2)),
                ),
                Err(StoreError::Conflict),
                "{attack}"
            );
        }
    }

    #[test]
    fn empty_journal_with_injected_outbox_or_audit_is_not_trusted() {
        for table in ["unified_policy_outbox", "unified_policy_audit"] {
            let db = TempDb::new();
            let store = db.open();
            let conn = Connection::open(&db.0).unwrap();
            let (kind, evidence) =
                encode_event(NewPolicyEvent::Revoke(&signed_revocation(1, 11, 3)));
            let space = root_pin().space;
            let resource = trusted_genesis().resource();
            if table == "unified_policy_outbox" {
                conn.execute(
                    "INSERT INTO unified_policy_outbox(space,resource,seq,kind,evidence)
                     VALUES(?1,?2,1,?3,?4)",
                    params![
                        space.as_bytes().as_slice(),
                        resource.as_bytes().as_slice(),
                        kind,
                        evidence
                    ],
                )
                .unwrap();
            } else {
                conn.execute(
                    "INSERT INTO unified_policy_audit(space,resource,seq,kind,policy_head)
                     VALUES(?1,?2,1,?3,?4)",
                    params![
                        space.as_bytes().as_slice(),
                        resource.as_bytes().as_slice(),
                        kind,
                        [9_u8; 32].as_slice()
                    ],
                )
                .unwrap();
            }
            drop(conn);
            assert_eq!(
                store.inspect(root_pin(), trusted_genesis()),
                Err(StoreError::Conflict),
                "{table}"
            );
            assert_eq!(store.pending_outbox(), Err(StoreError::Conflict), "{table}");
        }
    }

    // L-001Q uses separately allocated, in-memory fakes. The real Linux TPM
    // adapter is read-only and MUST NOT be used for a counter increment.
    struct ModelCounter {
        pin: PinnedCounterIdentity,
        number: Mutex<u64>,
        fail_after_increment: std::sync::atomic::AtomicBool,
        foreign_sqlite: Mutex<Option<PathBuf>>,
        foreign_write_blocked: std::sync::atomic::AtomicBool,
    }

    impl CandidateMonotonicCounter for ModelCounter {
        fn identity(&self) -> PinnedCounterIdentity {
            self.pin
        }

        fn read(&self) -> Result<u64, BindingError> {
            Ok(*self.number.lock().unwrap())
        }

        fn increment(&self) -> Result<(), BindingError> {
            let mut number = self.number.lock().unwrap();
            *number = number.checked_add(1).ok_or(BindingError::CounterOverflow)?;
            if let Some(path) = self.foreign_sqlite.lock().unwrap().as_ref() {
                let conn = Connection::open(path).unwrap();
                conn.busy_timeout(Duration::ZERO).unwrap();
                let attempt = conn.execute(
                    "UPDATE unified_policy_outbox SET evidence=x'01' WHERE seq=1",
                    [],
                );
                self.foreign_write_blocked
                    .store(attempt.is_err(), std::sync::atomic::Ordering::SeqCst);
            }
            if self
                .fail_after_increment
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(BindingError::PersistenceUncertain);
            }
            Ok(())
        }
    }

    struct ModelIntent {
        saved: Mutex<StoredBinding>,
    }

    impl CandidateIntentStore for ModelIntent {
        fn load(&self) -> Result<StoredBinding, BindingError> {
            Ok(*self.saved.lock().unwrap())
        }

        fn prepare(
            &self,
            expected: crate::tpm_counter_binding::Committed,
            next: crate::tpm_counter_binding::Prepared,
        ) -> Result<(), BindingError> {
            let mut saved = self.saved.lock().unwrap();
            if *saved != StoredBinding::Committed(expected) {
                return Err(BindingError::PersistenceUncertain);
            }
            *saved = StoredBinding::Prepared(next);
            Ok(())
        }

        fn finalize(
            &self,
            expected: crate::tpm_counter_binding::Prepared,
        ) -> Result<(), BindingError> {
            let mut saved = self.saved.lock().unwrap();
            if *saved != StoredBinding::Prepared(expected) {
                return Err(BindingError::PersistenceUncertain);
            }
            *saved = StoredBinding::Committed(crate::tpm_counter_binding::Committed {
                identity: expected.before.identity,
                counter: expected
                    .before
                    .counter
                    .checked_add(1)
                    .ok_or(BindingError::CounterOverflow)?,
                policy: crate::unified_policy_anchor::UnifiedPolicyHighWater {
                    policy_sequence: expected.after_sequence,
                    policy_head: expected.after_head,
                    revocation_root: expected.after_revocation_root,
                    current_manifest: expected.after_manifest,
                    ..expected.before.policy
                },
            });
            Ok(())
        }
    }

    fn model_counter_io(
        genesis: &VerifiedResourceTrust,
    ) -> (Arc<ModelCounter>, Arc<ModelIntent>, PinnedCounterIdentity) {
        let pin = PinnedCounterIdentity {
            device_binding: [55; 32],
            nv_index: 0x0180_0ace,
        };
        (
            Arc::new(ModelCounter {
                pin,
                number: Mutex::new(9),
                fail_after_increment: std::sync::atomic::AtomicBool::new(false),
                foreign_sqlite: Mutex::new(None),
                foreign_write_blocked: std::sync::atomic::AtomicBool::new(false),
            }),
            Arc::new(ModelIntent {
                saved: Mutex::new(StoredBinding::Committed(
                    crate::tpm_counter_binding::Committed {
                        identity: pin,
                        counter: 9,
                        policy: crate::unified_policy_anchor::UnifiedPolicyHighWater::initial(
                            genesis,
                        ),
                    },
                )),
            }),
            pin,
        )
    }

    fn bound_counter(
        store: &UnifiedPolicyJournal,
        genesis: VerifiedResourceTrust,
        receipts: &[SignedCheckpoint],
        counter: &Arc<ModelCounter>,
        intent: &Arc<ModelIntent>,
        pin: PinnedCounterIdentity,
        operation: CandidateCounterOperation,
    ) -> Result<Diagnostic, StoreError> {
        store.inspect_journal_bound_counter(
            root_pin(),
            genesis,
            receipts,
            150,
            CandidateCounterIo {
                pin,
                counter: counter.clone(),
                intent: intent.clone(),
            },
            operation,
        )
    }

    #[test]
    fn journal_bound_counter_accepts_exact_signed_mixed_policy() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let revoke = signed_revocation(1, 11, 3);
        store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&revoke))
            .unwrap();
        let cancel = signed_cancellation(2);
        let state = store
            .append(root_pin(), genesis, NewPolicyEvent::Cancel(&cancel))
            .unwrap();
        let revoke_root = append_revocation_root([0; 32], 1, &revoke.persistence_bytes()).unwrap();
        let receipts = witness_receipts(2, state.policy_head, revoke_root);
        let (counter, intent, pin) = model_counter_io(&genesis);
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &receipts,
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Begin
            ),
            Ok(Diagnostic::MatchingCounterOnly)
        );
        assert_eq!(*counter.number.lock().unwrap(), 10);
        let StoredBinding::Committed(committed) = intent.load().unwrap() else {
            panic!("counter intent was not finalized");
        };
        assert_eq!(committed.policy.policy_sequence, 2);
        assert_eq!(committed.policy.policy_head, state.policy_head);
        assert_eq!(committed.policy.revocation_root, revoke_root);
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &receipts,
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Reconcile
            ),
            Ok(Diagnostic::MatchingCounterOnly)
        );
        assert_eq!(*counter.number.lock().unwrap(), 10);
        assert!(state.admission_paused);
    }

    #[test]
    fn signed_checkpoint_for_wrong_journal_never_touches_counter() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let revoke = signed_revocation(1, 11, 3);
        let state = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&revoke))
            .unwrap();
        let root = append_revocation_root([0; 32], 1, &revoke.persistence_bytes()).unwrap();
        let (counter, intent, pin) = model_counter_io(&genesis);
        for receipts in [
            witness_receipts(1, [0xaa; 32], root),
            witness_receipts(1, state.policy_head, [0xbb; 32]),
            witness_receipts(2, state.policy_head, root),
        ] {
            assert_eq!(
                bound_counter(
                    &store,
                    genesis,
                    &receipts,
                    &counter,
                    &intent,
                    pin,
                    CandidateCounterOperation::Begin
                ),
                Err(StoreError::Conflict)
            );
        }
        assert_eq!(*counter.number.lock().unwrap(), 9);
        assert!(matches!(
            intent.load().unwrap(),
            StoredBinding::Committed(_)
        ));
    }

    #[test]
    fn corrupted_mirror_blocks_counter_stage_before_increment() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let revoke = signed_revocation(1, 11, 3);
        let state = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&revoke))
            .unwrap();
        let root = append_revocation_root([0; 32], 1, &revoke.persistence_bytes()).unwrap();
        let receipts = witness_receipts(1, state.policy_head, root);
        let (counter, intent, pin) = model_counter_io(&genesis);
        let conn = Connection::open(&db.0).unwrap();
        conn.execute("DELETE FROM unified_policy_audit WHERE seq=1", [])
            .unwrap();
        drop(conn);
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &receipts,
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Begin
            ),
            Err(StoreError::Conflict)
        );
        assert_eq!(*counter.number.lock().unwrap(), 9);
        assert!(matches!(
            intent.load().unwrap(),
            StoredBinding::Committed(_)
        ));
    }

    #[test]
    fn ambiguous_increment_requires_same_verified_journal_on_reconcile() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let revoke = signed_revocation(1, 11, 3);
        let state = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&revoke))
            .unwrap();
        let root = append_revocation_root([0; 32], 1, &revoke.persistence_bytes()).unwrap();
        let receipts = witness_receipts(1, state.policy_head, root);
        let (counter, intent, pin) = model_counter_io(&genesis);
        counter
            .fail_after_increment
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &receipts,
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Begin
            ),
            Err(StoreError::PersistenceFailure)
        );
        assert_eq!(*counter.number.lock().unwrap(), 10);
        assert!(matches!(intent.load().unwrap(), StoredBinding::Prepared(_)));
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &witness_receipts(1, [0; 32], root),
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Reconcile
            ),
            Err(StoreError::Conflict)
        );
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &receipts,
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Reconcile
            ),
            Ok(Diagnostic::MatchingCounterOnly)
        );
        assert!(matches!(
            intent.load().unwrap(),
            StoredBinding::Committed(_)
        ));
        assert_eq!(*counter.number.lock().unwrap(), 10);
    }

    #[test]
    fn second_sqlite_writer_cannot_swap_snapshot_during_counter_transition() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let revoke = signed_revocation(1, 11, 3);
        let state = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&revoke))
            .unwrap();
        let root = append_revocation_root([0; 32], 1, &revoke.persistence_bytes()).unwrap();
        let receipts = witness_receipts(1, state.policy_head, root);
        let (counter, intent, pin) = model_counter_io(&genesis);
        *counter.foreign_sqlite.lock().unwrap() = Some(db.0.clone());
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &receipts,
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Begin
            ),
            Ok(Diagnostic::MatchingCounterOnly)
        );
        assert!(
            counter
                .foreign_write_blocked
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        assert_eq!(store.pending_outbox().unwrap().len(), 1);
    }

    #[test]
    fn committed_counter_number_without_replayed_policy_match_is_rejected() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let (counter, intent, pin) = model_counter_io(&genesis);
        let revoke = signed_revocation(1, 11, 3);
        let state = store
            .append(root_pin(), genesis, NewPolicyEvent::Revoke(&revoke))
            .unwrap();
        let root = append_revocation_root([0; 32], 1, &revoke.persistence_bytes()).unwrap();
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &witness_receipts(1, state.policy_head, root),
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Reconcile
            ),
            Err(StoreError::Conflict)
        );
        assert_eq!(*counter.number.lock().unwrap(), 9);
    }

    #[test]
    fn owner_transfer_policy_commits_current_manifest_not_just_old_owner() {
        let db = TempDb::new();
        let store = db.open();
        let genesis = trusted_genesis();
        let successor = signed_manifest(33, 4);
        let transfer = signed_transfer(&genesis, &successor, 1);
        let snapshot = store
            .append(
                root_pin(),
                genesis,
                NewPolicyEvent::Transfer {
                    transfer: &transfer,
                    successor_manifest: &successor,
                },
            )
            .unwrap();
        let receipts = witness_receipts(1, snapshot.policy_head, [0; 32]);
        let (counter, intent, pin) = model_counter_io(&genesis);
        assert_eq!(
            bound_counter(
                &store,
                genesis,
                &receipts,
                &counter,
                &intent,
                pin,
                CandidateCounterOperation::Begin
            ),
            Ok(Diagnostic::MatchingCounterOnly)
        );
        let StoredBinding::Committed(binding) = intent.load().unwrap() else {
            panic!("transfer did not finalize");
        };
        let current = verify_resource_trust_for_spike(&root_pin(), &successor, 150).unwrap();
        assert_eq!(
            binding.policy.current_manifest,
            current.manifest_commitment()
        );
        assert_ne!(
            binding.policy.current_manifest,
            genesis.manifest_commitment()
        );
    }
}
