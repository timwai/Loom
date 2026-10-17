//! L-001I experimental unified SQLite resource-policy ledger.
//!
//! Every append replays the signed, ordered lifecycle history from genesis
//! under a pinned Root before starting a fresh atomic commit. This does not
//! establish witness freshness and NEVER transitions network admission to
//! Ready. No production permit or ServiceOpen is exported.
//!
//! Synchronous APIs: call from a blocking pool, never on a Tokio runtime core.

use crate::StoreError;
use crate::policy_journal_codec::{MAX_EVIDENCE, encode_event, replay_event};
pub use crate::policy_journal_codec::NewPolicyEvent;
use loom_crypto::owner_lifecycle::ResourceOwnerLifecycle;
use loom_crypto::space_trust::{ExternallyPinnedRootForSpike, VerifiedResourceTrust};
use loom_types::{ResourceId, SpaceId};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, Sender};
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
        ready_rx.recv().map_err(|_| StoreError::PersistenceFailure)??;
        Ok(Self { tx: Some(tx), join: Some(join), gate: Mutex::new(()) })
    }

    /// Only a diagnostic snapshot; never a permission to access a resource.
    pub fn inspect(
        &self,
        external_root: ExternallyPinnedRootForSpike,
        genesis: VerifiedResourceTrust,
    ) -> Result<JournalSnapshot, StoreError> {
        let _barrier = self.gate.lock().map_err(|_| StoreError::PersistenceFailure)?;
        let (send, recv) = mpsc::channel();
        self.tx.as_ref().ok_or(StoreError::PersistenceFailure)?
            .send(Command::Inspect { root: external_root, genesis, done: send })
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
        let _barrier = self.gate.lock().map_err(|_| StoreError::PersistenceFailure)?;
        let (send, recv) = mpsc::channel();
        self.tx.as_ref().ok_or(StoreError::PersistenceFailure)?
            .send(Command::Append {
                root: external_root, genesis, kind, evidence, done: send,
            })
            .map_err(|_| StoreError::PersistenceFailure)?;
        recv.recv().map_err(|_| StoreError::PersistenceFailure)?
    }

    /// Read-only: no ACK is allowed without authenticated remote durable
    /// receipt and a separate fairness/priority retransmission protocol.
    pub fn pending_outbox(&self) -> Result<Vec<CriticalPolicyOutbox>, StoreError> {
        let _barrier = self.gate.lock().map_err(|_| StoreError::PersistenceFailure)?;
        let (send, recv) = mpsc::channel();
        self.tx.as_ref().ok_or(StoreError::PersistenceFailure)?
            .send(Command::Pending(send))
            .map_err(|_| StoreError::PersistenceFailure)?;
        recv.recv().map_err(|_| StoreError::PersistenceFailure)?
    }
}

impl Drop for UnifiedPolicyJournal {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(join) = self.join.take() { let _ = join.join(); }
    }
}

fn worker(
    path: PathBuf,
    rx: Receiver<Command>,
    started: Sender<Result<(), StoreError>>,
) {
    match initialize(&path) {
        Ok(mut connection) => {
            let _ = started.send(Ok(()));
            for command in rx {
                match command {
                    Command::Append { root, genesis, kind, evidence, done } => {
                        let _ = done.send(append_transaction(
                            &mut connection, root, genesis, kind, &evidence,
                        ));
                    }
                    Command::Inspect { root, genesis, done } => {
                        let _ = done.send(inspect_db(&mut connection, root, genesis));
                    }
                    Command::Pending(done) => {
                        let _ = done.send(read_outbox(&connection));
                    }
                }
            }
        }
        Err(error) => { let _ = started.send(Err(error)); }
    }
}

fn initialize(path: &PathBuf) -> Result<Connection, StoreError> {
    let conn = Connection::open(path).map_err(|_| StoreError::PersistenceFailure)?;
    conn.busy_timeout(Duration::from_secs(2))
        .map_err(|_| StoreError::PersistenceFailure)?;
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
         ) STRICT;",
    ).map_err(|_| StoreError::PersistenceFailure)?;
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
    let mut stmt = tx.prepare(
        "SELECT seq,kind,evidence,policy_head
         FROM unified_policy_events
         WHERE space=?1 AND resource=?2 ORDER BY seq ASC",
    ).map_err(|_| StoreError::PersistenceFailure)?;
    let rows = stmt.query_map(
        params![root.space.as_bytes().as_slice(), genesis.resource().as_bytes().as_slice()],
        |row| {
            let seq: i64 = row.get(0)?;
            let kind: i64 = row.get(1)?;
            let evidence: Vec<u8> = row.get(2)?;
            let head: Vec<u8> = row.get(3)?;
            Ok((seq,kind,evidence,head))
        },
    ).map_err(|_| StoreError::PersistenceFailure)?;
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
    let cursor: Option<(i64, Vec<u8>, Vec<u8>)> = tx.query_row(
        "SELECT seq,policy_head,owner_manifest FROM unified_policy_cursor
         WHERE space=?1 AND resource=?2",
        params![root.space.as_bytes().as_slice(), genesis.resource().as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|_| StoreError::PersistenceFailure)?;
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
    Ok(state)
}

fn inspect_db(
    conn: &mut Connection,
    root: ExternallyPinnedRootForSpike,
    genesis: VerifiedResourceTrust,
) -> Result<JournalSnapshot, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::PersistenceFailure)?;
    let state = replay(&tx, &root, genesis)?;
    let snapshot = snapshot(&state);
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(snapshot)
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
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
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
        params![space,resource,seq,kind,evidence,head.as_slice()],
    ).map_err(|_| StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO unified_policy_cursor(space,resource,seq,policy_head,owner_manifest)
         VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(space,resource) DO UPDATE SET
           seq=excluded.seq,policy_head=excluded.policy_head,
           owner_manifest=excluded.owner_manifest",
        params![
            space,resource,seq,head.as_slice(),
            state.current_trust().manifest_commitment().as_slice(),
        ],
    ).map_err(|_| StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO unified_policy_outbox(space,resource,seq,kind,evidence)
         VALUES(?1,?2,?3,?4,?5)",
        params![space,resource,seq,kind,evidence],
    ).map_err(|_| StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO unified_policy_audit(space,resource,seq,kind,policy_head)
         VALUES(?1,?2,?3,?4,?5)",
        params![space,resource,seq,kind,head.as_slice()],
    ).map_err(|_| StoreError::PersistenceFailure)?;
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(snapshot(&state))
}

fn read_outbox(conn: &Connection) -> Result<Vec<CriticalPolicyOutbox>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT seq,kind,evidence FROM unified_policy_outbox ORDER BY id ASC",
    ).map_err(|_| StoreError::PersistenceFailure)?;
    let rows = stmt.query_map([], |row| {
        let seq: i64 = row.get(0)?;
        let kind: i64 = row.get(1)?;
        let evidence: Vec<u8> = row.get(2)?;
        Ok((seq,kind,evidence))
    }).map_err(|_| StoreError::PersistenceFailure)?;
    let mut outbox = Vec::new();
    for row in rows {
        let (seq, kind, evidence) = row.map_err(|_| StoreError::PersistenceFailure)?;
        outbox.push(CriticalPolicyOutbox {
            sequence: u64::try_from(seq).map_err(|_| StoreError::Conflict)?,
            kind: u8::try_from(kind).map_err(|_| StoreError::Conflict)?,
            evidence,
        });
    }
    Ok(outbox)
}
