//! L-001C experimental revocation persistence. No production ServiceOpen.
//! The only admission helpers are test-only. ADR-20/21 are not yet accepted.

#[cfg(test)]
use crate::SecurityEventStore;
use crate::{PolicyVersion, StoreError};
use loom_crypto::owner_authority::{
    OwnerVerifiedRevocation, ProvisionedOwnerForSpike, replay_persisted_owner_revocation_for_spike,
};
#[cfg(test)]
use loom_crypto::signed_revocation::VerifiedRevocation;
use loom_crypto::space_trust::{VerifiedResourceTrust, verify_root_bound_witnesses};
use loom_crypto::witness_checkpoint::SignedCheckpoint;
use loom_crypto::witness_checkpoint::{VerifiedWitnessCheckpoint, append_revocation_root};
use loom_types::{ResourceId, SpaceId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_EVENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Key(SpaceId, ResourceId);

impl From<PolicyVersion> for Key {
    fn from(v: PolicyVersion) -> Self {
        Self(v.space_id, v.resource_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionState {
    Paused,
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAssessment {
    CandidateConsistent,
    RollbackDetected,
    WitnessBehind,
    HistoryDiverged,
}

#[derive(Clone, Copy, Debug)]
struct LocalChainSnapshot {
    seq: u64,
    root: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEntry {
    pub id: i64,
    pub epoch: u64,
    pub signed_event: Vec<u8>,
}

struct Gate {
    epochs: HashMap<Key, u64>,
    status: AdmissionState,
    #[cfg(test)]
    permits: Vec<(Key, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
    #[cfg(test)]
    fail_after_commit: bool,
}

impl Gate {
    fn pause(&mut self) {
        self.status = AdmissionState::Paused;
        #[cfg(test)]
        for (_, live) in &self.permits {
            live.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

enum Command {
    Commit(
        PolicyVersion,
        Vec<u8>,
        Sender<Result<PolicyVersion, StoreError>>,
    ),
    Pending(Sender<Result<Vec<OutboxEntry>, StoreError>>),
    Snapshot(
        SpaceId,
        ResourceId,
        Sender<Result<LocalChainSnapshot, StoreError>>,
    ),
    RootReplaySnapshot(
        SpaceId,
        ResourceId,
        ProvisionedOwnerForSpike,
        Sender<Result<LocalChainSnapshot, StoreError>>,
    ),
}

/// Synchronous API using one dedicated SQLite OS thread. Async callers must
/// use a blocking executor. Start-up is always Paused until verified recovery.
pub struct SqliteRevocationStore {
    tx: Option<Sender<Command>>,
    gate: Mutex<Gate>,
    join: Option<JoinHandle<()>>,
}

impl SqliteRevocationStore {
    pub fn open(path: PathBuf) -> Result<Self, StoreError> {
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let join = thread::Builder::new()
            .name("loom-revocation-db".to_owned())
            .spawn(move || db_worker(path, rx, ready_tx))
            .map_err(|_| StoreError::PersistenceFailure)?;
        let epochs = ready_rx
            .recv()
            .map_err(|_| StoreError::PersistenceFailure)??;
        Ok(Self {
            tx: Some(tx),
            join: Some(join),
            gate: Mutex::new(Gate {
                epochs,
                status: AdmissionState::Paused,
                #[cfg(test)]
                permits: Vec::new(),
                #[cfg(test)]
                fail_after_commit: false,
            }),
        })
    }

    pub fn admission_state(&self) -> AdmissionState {
        self.gate
            .lock()
            .map(|g| g.status)
            .unwrap_or(AdmissionState::Paused)
    }

    /// Diagnostic only; version read is never proof of current authorization.
    pub fn persisted_epoch(&self, v: PolicyVersion) -> Result<u64, StoreError> {
        let gate = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        Ok(*gate.epochs.get(&v.into()).unwrap_or(&0))
    }

    /// P0 security events must not be ACKed or dropped before remote durable receipt.
    /// The PoC reads pending events but intentionally has no ACK operation.
    pub fn pending_outbox(&self) -> Result<Vec<OutboxEntry>, StoreError> {
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::Pending(send))
            .map_err(|_| StoreError::PersistenceFailure)?;
        recv.recv().map_err(|_| StoreError::PersistenceFailure)?
    }

    /// Diagnostic only. The admission gate remains Paused even if both
    /// independent signatures and the full local evidence root match.
    pub fn inspect_witnessed_recovery(
        &self,
        verified: &VerifiedWitnessCheckpoint,
    ) -> Result<RecoveryAssessment, StoreError> {
        let cp = verified.checkpoint();
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        gate.pause();
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::Snapshot(cp.space, cp.resource, send))
            .map_err(|_| StoreError::PersistenceFailure)?;
        let local = recv.recv().map_err(|_| StoreError::PersistenceFailure)??;
        let result = if local.seq < cp.seq {
            RecoveryAssessment::RollbackDetected
        } else if local.seq > cp.seq {
            RecoveryAssessment::WitnessBehind
        } else if local.root != cp.revocation_root || local.root != cp.head_hash {
            RecoveryAssessment::HistoryDiverged
        } else {
            RecoveryAssessment::CandidateConsistent
        };
        Ok(result)
    }

    /// New P0 diagnostic path: Root-signed witness policy + every persisted
    /// two-signature Owner/delegate event must verify before comparing roots.
    /// No READY transition is possible, including when all proofs match.
    pub fn inspect_root_bound_recovery(
        &self,
        trust: &VerifiedResourceTrust,
        receipts: &[SignedCheckpoint],
        now_ms: u64,
    ) -> Result<RecoveryAssessment, StoreError> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        gate.pause();
        let witness = verify_root_bound_witnesses(trust, receipts, now_ms)
            .map_err(|_| StoreError::Conflict)?;
        let cp = witness.checkpoint();
        let (send, recv) = mpsc::channel();
        self.tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)?
            .send(Command::RootReplaySnapshot(
                cp.space,
                cp.resource,
                trust.owner(),
                send,
            ))
            .map_err(|_| StoreError::PersistenceFailure)?;
        let local = recv.recv().map_err(|_| StoreError::PersistenceFailure)??;
        let assessment = if local.seq < cp.seq {
            RecoveryAssessment::RollbackDetected
        } else if local.seq > cp.seq {
            RecoveryAssessment::WitnessBehind
        } else if local.root != cp.revocation_root || local.root != cp.head_hash {
            RecoveryAssessment::HistoryDiverged
        } else {
            RecoveryAssessment::CandidateConsistent
        };
        Ok(assessment)
    }

    #[cfg(test)]
    fn recover_fixture(&self, witnessed: &[(PolicyVersion, u64)]) -> Result<(), StoreError> {
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        if witnessed
            .iter()
            .any(|(v, min)| gate.epochs.get(&(*v).into()).copied().unwrap_or(0) < *min)
        {
            gate.pause();
            return Err(StoreError::Conflict);
        }
        // No real signed witness implemented. This function is test-only.
        gate.status = AdmissionState::Ready;
        Ok(())
    }

    #[cfg(test)]
    fn admit_fixture(
        &self,
        v: PolicyVersion,
    ) -> Result<std::sync::Arc<std::sync::atomic::AtomicBool>, StoreError> {
        use std::sync::{Arc, atomic::AtomicBool};
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        if gate.status != AdmissionState::Ready {
            return Err(StoreError::NotInitialized);
        }
        if gate.epochs.get(&v.into()).copied().unwrap_or(0) != v.epoch {
            return Err(StoreError::Conflict);
        }
        let live = Arc::new(AtomicBool::new(true));
        gate.permits.push((v.into(), Arc::clone(&live)));
        Ok(live)
    }

    #[cfg(test)]
    fn simulate_post_commit_crash(&self) {
        self.gate.lock().expect("test gate").fail_after_commit = true;
    }
}

impl SqliteRevocationStore {
    /// Accept only a typed event whose exact CBOR and Ed25519 signature have
    /// already been checked. This does NOT prove Owner authority, and the store
    /// remains production-paused until witness-backed admission is implemented.
    /// This candidate public path only accepts an Owner proof that can be
    /// re-verified against the Resource Owner pinned by the Root-signed
    /// manifest. The store remains production PAUSED regardless of proof.
    pub fn commit_root_bound_revocation(
        &self,
        v: PolicyVersion,
        trust: &VerifiedResourceTrust,
        proof: &OwnerVerifiedRevocation,
    ) -> Result<PolicyVersion, StoreError> {
        if trust.space() != v.space_id || trust.resource() != v.resource_id {
            return Err(StoreError::Conflict);
        }
        let evidence = proof.persistence_bytes();
        replay_persisted_owner_revocation_for_spike(&trust.owner(), &evidence)
            .map_err(|_| StoreError::Conflict)?;
        if proof.space_id() != v.space_id
            || proof.resource_id() != v.resource_id
            || v.epoch.checked_add(1) != Some(proof.seq())
        {
            return Err(StoreError::Conflict);
        }
        self.commit_internal(v, &evidence)
    }

    /// Legacy caller-supplied issuer test path; absent in production builds.
    #[cfg(test)]
    fn commit_spike_revocation_for_test(
        &self,
        v: PolicyVersion,
        proof: &VerifiedRevocation,
    ) -> Result<PolicyVersion, StoreError> {
        if proof.space_id() != v.space_id
            || proof.resource_id() != v.resource_id
            || v.epoch.checked_add(1) != Some(proof.seq())
        {
            return Err(StoreError::Conflict);
        }
        self.commit_internal(v, &proof.persistence_bytes())
    }

    /// Private commit primitive: callers cannot bypass signature verification.
    fn commit_internal(&self, v: PolicyVersion, event: &[u8]) -> Result<PolicyVersion, StoreError> {
        if event.is_empty() || event.len() > MAX_EVENT_BYTES {
            return Err(StoreError::PersistenceFailure);
        }
        // Single admission barrier covers test-only SessionOpen and transaction.
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| StoreError::PersistenceFailure)?;
        if gate.status != AdmissionState::Ready {
            return Err(StoreError::NotInitialized);
        }
        let key: Key = v.into();
        if gate.epochs.get(&key).copied().unwrap_or(0) != v.epoch {
            return Err(StoreError::Conflict);
        }
        let (send, recv) = mpsc::channel();
        let result = match self
            .tx
            .as_ref()
            .ok_or(StoreError::PersistenceFailure)
            .and_then(|tx| {
                tx.send(Command::Commit(v, event.to_vec(), send))
                    .map_err(|_| StoreError::PersistenceFailure)
            }) {
            Ok(()) => recv.recv().unwrap_or(Err(StoreError::PersistenceFailure)),
            Err(error) => Err(error),
        };
        match result {
            Ok(committed) => {
                #[cfg(test)]
                if gate.fail_after_commit {
                    gate.pause();
                    return Err(StoreError::PersistenceFailure);
                }
                gate.epochs.insert(key, committed.epoch);
                #[cfg(test)]
                {
                    for (id, live) in &gate.permits {
                        if *id == key {
                            live.store(false, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                    gate.permits.retain(|(id, _)| *id != key);
                }
                Ok(committed)
            }
            Err(error) => {
                // A successful COMMIT followed by response failure is ambiguous:
                // pause rather than serving from a stale in-memory snapshot.
                gate.pause();
                Err(error)
            }
        }
    }
}

#[cfg(test)]
impl SecurityEventStore for SqliteRevocationStore {
    fn commit_revocation(
        &self,
        v: PolicyVersion,
        event: &[u8],
    ) -> Result<PolicyVersion, StoreError> {
        self.commit_internal(v, event)
    }
}

impl Drop for SqliteRevocationStore {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn db_worker(
    path: PathBuf,
    rx: Receiver<Command>,
    ready: Sender<Result<HashMap<Key, u64>, StoreError>>,
) {
    match initialize(&path) {
        Ok((mut conn, versions)) => {
            let _ = ready.send(Ok(versions));
            for command in rx {
                match command {
                    Command::Commit(v, event, done) => {
                        let _ = done.send(write_revocation(&mut conn, v, &event));
                    }
                    Command::Pending(done) => {
                        let _ = done.send(read_outbox(&conn));
                    }
                    Command::Snapshot(space, resource, done) => {
                        let _ = done.send(read_chain_snapshot(&conn, space, resource, None));
                    }
                    Command::RootReplaySnapshot(space, resource, owner, done) => {
                        let _ =
                            done.send(read_chain_snapshot(&conn, space, resource, Some(&owner)));
                    }
                }
            }
        }
        Err(error) => {
            let _ = ready.send(Err(error));
        }
    }
}

fn initialize(path: &PathBuf) -> Result<(Connection, HashMap<Key, u64>), StoreError> {
    let conn = Connection::open(path).map_err(|_| StoreError::PersistenceFailure)?;
    conn.busy_timeout(Duration::from_secs(2))
        .map_err(|_| StoreError::PersistenceFailure)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS policy_versions(
           space BLOB NOT NULL CHECK(length(space)=16),
           resource BLOB NOT NULL CHECK(length(resource)=16),
           epoch INTEGER NOT NULL CHECK(epoch>=0),
           PRIMARY KEY(space,resource)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS revocations(
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           space BLOB NOT NULL CHECK(length(space)=16),
           resource BLOB NOT NULL CHECK(length(resource)=16),
           epoch INTEGER NOT NULL CHECK(epoch>0),
           signed_event BLOB NOT NULL CHECK(length(signed_event)>0),
           UNIQUE(space,resource,epoch)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS critical_outbox(
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           revocation_id INTEGER NOT NULL UNIQUE REFERENCES revocations(id),
           epoch INTEGER NOT NULL,
           signed_event BLOB NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS security_audit(
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           revocation_id INTEGER NOT NULL REFERENCES revocations(id),
           action TEXT NOT NULL
         ) STRICT;",
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    let mut versions = HashMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT space,resource,epoch FROM policy_versions")
            .map_err(|_| StoreError::PersistenceFailure)?;
        let rows = stmt
            .query_map([], |row| {
                let space: Vec<u8> = row.get(0)?;
                let resource: Vec<u8> = row.get(1)?;
                let epoch: i64 = row.get(2)?;
                Ok((space, resource, epoch))
            })
            .map_err(|_| StoreError::PersistenceFailure)?;
        for row in rows {
            let (space, resource, epoch) = row.map_err(|_| StoreError::PersistenceFailure)?;
            let space: [u8; 16] = space
                .try_into()
                .map_err(|_| StoreError::PersistenceFailure)?;
            let resource: [u8; 16] = resource
                .try_into()
                .map_err(|_| StoreError::PersistenceFailure)?;
            let epoch = u64::try_from(epoch).map_err(|_| StoreError::PersistenceFailure)?;
            versions.insert(
                Key(SpaceId::from_bytes(space), ResourceId::from_bytes(resource)),
                epoch,
            );
        }
    }
    Ok((conn, versions))
}

fn write_revocation(
    conn: &mut Connection,
    v: PolicyVersion,
    event: &[u8],
) -> Result<PolicyVersion, StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::PersistenceFailure)?;
    let space = v.space_id.as_bytes().as_slice();
    let resource = v.resource_id.as_bytes().as_slice();
    let actual: Option<i64> = tx
        .query_row(
            "SELECT epoch FROM policy_versions WHERE space=?1 AND resource=?2",
            params![space, resource],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::PersistenceFailure)?;
    let actual = actual.unwrap_or(0);
    let expected = i64::try_from(v.epoch).map_err(|_| StoreError::PersistenceFailure)?;
    if actual != expected {
        return Err(StoreError::Conflict);
    }
    let next = actual
        .checked_add(1)
        .ok_or(StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO policy_versions(space,resource,epoch) VALUES(?1,?2,?3)
         ON CONFLICT(space,resource) DO UPDATE SET epoch=excluded.epoch",
        params![space, resource, next],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO revocations(space,resource,epoch,signed_event) VALUES(?1,?2,?3,?4)",
        params![space, resource, next, event],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    let event_id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO critical_outbox(revocation_id,epoch,signed_event) VALUES(?1,?2,?3)",
        params![event_id, next, event],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    tx.execute(
        "INSERT INTO security_audit(revocation_id,action) VALUES(?1,'revoke')",
        params![event_id],
    )
    .map_err(|_| StoreError::PersistenceFailure)?;
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(PolicyVersion {
        epoch: u64::try_from(next).map_err(|_| StoreError::PersistenceFailure)?,
        ..v
    })
}

fn read_outbox(db: &Connection) -> Result<Vec<OutboxEntry>, StoreError> {
    let mut stmt = db
        .prepare("SELECT id,epoch,signed_event FROM critical_outbox ORDER BY id")
        .map_err(|_| StoreError::PersistenceFailure)?;
    let rows = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let epoch: i64 = row.get(1)?;
            let event: Vec<u8> = row.get(2)?;
            Ok((id, epoch, event))
        })
        .map_err(|_| StoreError::PersistenceFailure)?;
    let mut entries = Vec::new();
    for row in rows {
        let (id, epoch, event) = row.map_err(|_| StoreError::PersistenceFailure)?;
        entries.push(OutboxEntry {
            id,
            epoch: u64::try_from(epoch).map_err(|_| StoreError::PersistenceFailure)?,
            signed_event: event,
        });
    }
    Ok(entries)
}

/// Build a fresh hash of the signed evidence; SQLite-local digests would
/// roll back along with the backup and cannot serve as independent anchors.
fn read_chain_snapshot(
    db: &Connection,
    space: SpaceId,
    resource: ResourceId,
    owner: Option<&ProvisionedOwnerForSpike>,
) -> Result<LocalChainSnapshot, StoreError> {
    let epoch: Option<i64> = db
        .query_row(
            "SELECT epoch FROM policy_versions WHERE space=?1 AND resource=?2",
            params![space.as_bytes().as_slice(), resource.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::PersistenceFailure)?;
    let epoch = u64::try_from(epoch.unwrap_or(0)).map_err(|_| StoreError::PersistenceFailure)?;
    let mut stmt = db
        .prepare(
            "SELECT epoch,signed_event FROM revocations
         WHERE space=?1 AND resource=?2 ORDER BY epoch",
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    let rows = stmt
        .query_map(
            params![space.as_bytes().as_slice(), resource.as_bytes().as_slice()],
            |row| {
                let seq: i64 = row.get(0)?;
                let event: Vec<u8> = row.get(1)?;
                Ok((seq, event))
            },
        )
        .map_err(|_| StoreError::PersistenceFailure)?;
    let mut root = [0_u8; 32];
    let mut previous = 0_u64;
    for row in rows {
        let (seq, event) = row.map_err(|_| StoreError::PersistenceFailure)?;
        let seq = u64::try_from(seq).map_err(|_| StoreError::Conflict)?;
        if seq != previous + 1 || seq > epoch {
            return Err(StoreError::Conflict);
        }
        if let Some(owner) = owner {
            if owner.space_id != space || owner.resource_id != resource {
                return Err(StoreError::Conflict);
            }
            let proof = replay_persisted_owner_revocation_for_spike(owner, &event)
                .map_err(|_| StoreError::Conflict)?;
            if proof.seq() != seq || proof.space_id() != space || proof.resource_id() != resource {
                return Err(StoreError::Conflict);
            }
        }
        root = append_revocation_root(root, seq, &event).ok_or(StoreError::Conflict)?;
        previous = seq;
    }
    if previous != epoch {
        return Err(StoreError::Conflict);
    }
    Ok(LocalChainSnapshot { seq: epoch, root })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDb(PathBuf);
    impl TempDb {
        fn new() -> Self {
            let ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!("loom-{}-{ns}.sqlite", std::process::id())))
        }
        fn open(&self) -> SqliteRevocationStore {
            SqliteRevocationStore::open(self.0.clone()).unwrap()
        }
    }
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }
    fn v0() -> PolicyVersion {
        PolicyVersion {
            space_id: SpaceId::from_bytes([1; 16]),
            resource_id: ResourceId::from_bytes([2; 16]),
            epoch: 0,
        }
    }
    #[test]
    fn startup_is_paused_no_trust_source() {
        let db = TempDb::new();
        let store = db.open();
        assert_eq!(store.admission_state(), AdmissionState::Paused);
        assert!(matches!(
            store.admit_fixture(v0()),
            Err(StoreError::NotInitialized)
        ));
        assert_eq!(
            store.commit_revocation(v0(), b"fixture"),
            Err(StoreError::NotInitialized)
        );
    }
    #[test]
    fn atomic_commit_cancels_old_session_and_survives_restart() {
        let db = TempDb::new();
        let store = db.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        let permit = store.admit_fixture(v0()).unwrap();
        let updated = store.commit_revocation(v0(), b"signed fixture").unwrap();
        assert_eq!(updated.epoch, 1);
        assert!(!permit.load(Ordering::SeqCst));
        assert!(matches!(
            store.admit_fixture(v0()),
            Err(StoreError::Conflict)
        ));
        assert!(store.admit_fixture(updated).is_ok());
        let events = store.pending_outbox().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].signed_event, b"signed fixture");
        drop(store);
        let recovered = db.open();
        assert_eq!(recovered.admission_state(), AdmissionState::Paused);
        assert_eq!(recovered.persisted_epoch(v0()).unwrap(), 1);
        assert_eq!(recovered.pending_outbox().unwrap(), events);
        recovered.recover_fixture(&[(v0(), 1)]).unwrap();
        assert!(matches!(
            recovered.admit_fixture(v0()),
            Err(StoreError::Conflict)
        ));
    }
    #[test]
    fn crash_after_commit_before_memory_publication_fails_closed() {
        let db = TempDb::new();
        let store = db.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        let permit = store.admit_fixture(v0()).unwrap();
        store.simulate_post_commit_crash();
        assert_eq!(
            store.commit_revocation(v0(), b"crash"),
            Err(StoreError::PersistenceFailure)
        );
        assert_eq!(store.admission_state(), AdmissionState::Paused);
        assert!(!permit.load(Ordering::SeqCst));
        drop(store);
        let recovered = db.open();
        assert_eq!(recovered.persisted_epoch(v0()).unwrap(), 1);
        assert_eq!(recovered.pending_outbox().unwrap().len(), 1);
    }
    #[test]
    fn restored_old_db_rejected_against_independent_test_highwater() {
        let db = TempDb::new();
        let store = db.open();
        assert_eq!(
            store.recover_fixture(&[(v0(), 2)]),
            Err(StoreError::Conflict)
        );
        assert_eq!(store.admission_state(), AdmissionState::Paused);
    }
    #[test]
    fn stale_writer_does_not_duplicate_revocation() {
        let db = TempDb::new();
        let store = db.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        assert_eq!(store.commit_revocation(v0(), b"one").unwrap().epoch, 1);
        assert_eq!(
            store.commit_revocation(v0(), b"stale"),
            Err(StoreError::Conflict)
        );
        assert_eq!(store.pending_outbox().unwrap().len(), 1);
    }
    #[test]
    fn thousand_parallel_admissions_cannot_survive_commit() {
        let db = TempDb::new();
        let store = std::sync::Arc::new(db.open());
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&store);
            let b = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                b.wait();
                for _ in 0..125 {
                    if let Ok(permit) = s.admit_fixture(v0()) {
                        let _ = permit.load(Ordering::SeqCst);
                    }
                }
            }));
        }
        barrier.wait();
        assert_eq!(store.commit_revocation(v0(), b"race").unwrap().epoch, 1);
        for t in threads {
            t.join().unwrap();
        }
        assert!(matches!(
            store.admit_fixture(v0()),
            Err(StoreError::Conflict)
        ));
        assert!(store.gate.lock().unwrap().permits.is_empty());
    }

    fn checkpoint_fixture(seq: u64, root: [u8; 32]) -> VerifiedWitnessCheckpoint {
        use ed25519_dalek::{Signer, SigningKey};
        use loom_crypto::witness_checkpoint::{
            Checkpoint, SignedCheckpoint, TrustedWitnessForSpike, checkpoint_transcript,
            verify_two_witnesses,
        };
        let first = SigningKey::from_bytes(&[21; 32]);
        let second = SigningKey::from_bytes(&[22; 32]);
        let a = TrustedWitnessForSpike::from_public_key(first.verifying_key().to_bytes());
        let b = TrustedWitnessForSpike::from_public_key(second.verifying_key().to_bytes());
        let checkpoint = Checkpoint {
            space: v0().space_id,
            resource: v0().resource_id,
            writer_epoch: 1,
            seq,
            head_hash: root,
            revocation_root: root,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let transcript = checkpoint_transcript(&checkpoint);
        let signed = [
            SignedCheckpoint {
                witness_key_id: a.key_id,
                checkpoint,
                signature: first.sign(&transcript).to_bytes(),
            },
            SignedCheckpoint {
                witness_key_id: b.key_id,
                checkpoint,
                signature: second.sign(&transcript).to_bytes(),
            },
        ];
        verify_two_witnesses(&[a, b], &signed, checkpoint.space, checkpoint.resource, 150).unwrap()
    }

    #[test]
    fn real_signed_witnesses_detect_an_older_restored_database() {
        let expected_root = append_revocation_root([0; 32], 1, b"revoke-1").unwrap();
        let witness = checkpoint_fixture(1, expected_root);
        let old = TempDb::new();
        let old_store = old.open();
        assert_eq!(
            old_store.inspect_witnessed_recovery(&witness).unwrap(),
            RecoveryAssessment::RollbackDetected
        );
        assert_eq!(old_store.admission_state(), AdmissionState::Paused);
        let newer = TempDb::new();
        let store = newer.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        store.commit_revocation(v0(), b"revoke-1").unwrap();
        assert_eq!(
            store.inspect_witnessed_recovery(&witness).unwrap(),
            RecoveryAssessment::CandidateConsistent
        );
        assert_eq!(store.admission_state(), AdmissionState::Paused);
        assert!(matches!(
            store.admit_fixture(v0()),
            Err(StoreError::NotInitialized)
        ));
    }

    #[test]
    fn same_epoch_with_corrupt_evidence_detects_different_root() {
        let db = TempDb::new();
        let store = db.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        store.commit_revocation(v0(), b"original").unwrap();
        let witness =
            checkpoint_fixture(1, append_revocation_root([0; 32], 1, b"original").unwrap());
        drop(store);
        let connection = Connection::open(&db.0).unwrap();
        connection
            .execute(
                "UPDATE revocations SET signed_event=?1 WHERE epoch=1",
                [b"substituted".as_slice()],
            )
            .unwrap();
        drop(connection);
        let restored = db.open();
        assert_eq!(
            restored.inspect_witnessed_recovery(&witness).unwrap(),
            RecoveryAssessment::HistoryDiverged
        );
        assert_eq!(restored.admission_state(), AdmissionState::Paused);
    }

    #[test]
    fn witness_behind_local_epoch_does_not_restore_old_permission() {
        let db = TempDb::new();
        let store = db.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        store.commit_revocation(v0(), b"revoke-1").unwrap();
        let witness = checkpoint_fixture(0, [0; 32]);
        assert_eq!(
            store.inspect_witnessed_recovery(&witness).unwrap(),
            RecoveryAssessment::WitnessBehind
        );
        assert_eq!(store.admission_state(), AdmissionState::Paused);
    }

    #[test]
    fn inconsistent_policy_version_and_event_history_fail_closed() {
        let db = TempDb::new();
        let store = db.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        store.commit_revocation(v0(), b"revoke-1").unwrap();
        drop(store);
        let connection = Connection::open(&db.0).unwrap();
        connection
            .execute("UPDATE policy_versions SET epoch=2", [])
            .unwrap();
        drop(connection);
        let restored = db.open();
        let witness =
            checkpoint_fixture(1, append_revocation_root([0; 32], 1, b"revoke-1").unwrap());
        assert_eq!(
            restored.inspect_witnessed_recovery(&witness),
            Err(StoreError::Conflict)
        );
        assert_eq!(restored.admission_state(), AdmissionState::Paused);
    }

    fn root_trust_fixture() -> loom_crypto::space_trust::VerifiedResourceTrust {
        use ed25519_dalek::{Signer, SigningKey};
        use loom_crypto::space_trust::{
            ExternallyPinnedRootForSpike, ResourceTrustManifest, SignedResourceTrust,
            trust_manifest_transcript, verify_resource_trust_for_spike,
        };
        let root_key = SigningKey::from_bytes(&[30; 32]);
        let owner_key = SigningKey::from_bytes(&[11; 32]);
        let witness_a = SigningKey::from_bytes(&[21; 32]);
        let witness_b = SigningKey::from_bytes(&[22; 32]);
        let root = ExternallyPinnedRootForSpike {
            space: v0().space_id,
            public_key: root_key.verifying_key().to_bytes(),
            key_epoch: 7,
        };
        let manifest = ResourceTrustManifest {
            space: v0().space_id,
            resource: v0().resource_id,
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
        verify_resource_trust_for_spike(&root, &signed, 150).unwrap()
    }

    fn root_signed_receipts(
        root: &loom_crypto::space_trust::VerifiedResourceTrust,
        seq: u64,
        head: [u8; 32],
    ) -> [SignedCheckpoint; 2] {
        use ed25519_dalek::{Signer, SigningKey};
        use loom_crypto::witness_checkpoint::{
            Checkpoint, TrustedWitnessForSpike, checkpoint_transcript,
        };
        let a = SigningKey::from_bytes(&[21; 32]);
        let b = SigningKey::from_bytes(&[22; 32]);
        let cp = Checkpoint {
            space: root.space(),
            resource: root.resource(),
            writer_epoch: root.writer_epoch(),
            seq,
            head_hash: head,
            revocation_root: head,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let transcript = checkpoint_transcript(&cp);
        [a, b].map(|key| SignedCheckpoint {
            witness_key_id: TrustedWitnessForSpike::from_public_key(key.verifying_key().to_bytes())
                .key_id,
            checkpoint: cp,
            signature: key.sign(&transcript).to_bytes(),
        })
    }

    #[test]
    fn existing_unanchored_ingress_is_test_only_and_cannot_override_root() {
        let db = TempDb::new();
        let store = db.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        // Root-bound ingress cannot accept random data, even with a
        // completely matching witness sequence/root.
        assert_eq!(
            store.commit_internal(v0(), b"not a verified Owner signature").unwrap().epoch,
            1
        );
        let trusted = root_trust_fixture();
        let head = append_revocation_root([0; 32], 1, b"not a verified Owner signature")
            .unwrap();
        let receipts = root_signed_receipts(&trusted, 1, head);
        assert_eq!(
            store.inspect_root_bound_recovery(&trusted, &receipts, 150),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn root_bound_witnesses_refuse_unsigned_fixture_history() {
        let root = root_trust_fixture();
        let db = TempDb::new();
        let store = db.open();
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        store
            .commit_revocation(v0(), b"arbitrary unsigned bytes")
            .unwrap();
        let head = append_revocation_root([0; 32], 1, b"arbitrary unsigned bytes").unwrap();
        let receipts = root_signed_receipts(&root, 1, head);
        // Plain hash comparison would be consistent. Owner signature replay fails.
        assert_eq!(
            store
                .inspect_witnessed_recovery(
                    &loom_crypto::space_trust::verify_root_bound_witnesses(&root, &receipts, 150,)
                        .unwrap()
                )
                .unwrap(),
            RecoveryAssessment::CandidateConsistent
        );
        assert_eq!(
            store.inspect_root_bound_recovery(&root, &receipts, 150),
            Err(StoreError::Conflict)
        );
        assert_eq!(store.admission_state(), AdmissionState::Paused);
    }

    #[test]
    fn owner_delegated_revocation_must_match_db_resource_and_remain_paused_on_restart() {
        use ed25519_dalek::{Signer, SigningKey};
        use loom_crypto::owner_authority::{
            ProvisionedOwnerForSpike, issuer_key_id, verify_owner_delegated_revocation_for_spike,
        };
        use loom_wire::security_event::{
            CanonicalSecurityEvent, EventKind, encode_security_event, signing_input,
        };

        let owner = SigningKey::from_bytes(&[11; 32]);
        let delegate = SigningKey::from_bytes(&[12; 32]);
        let provisioned = ProvisionedOwnerForSpike {
            space_id: v0().space_id,
            resource_id: v0().resource_id,
            public_key: owner.verifying_key().to_bytes(),
            current_key_epoch: 3,
        };
        let delegated_key = delegate.verifying_key().to_bytes();
        let mut grant_payload = v0().resource_id.as_bytes().to_vec();
        grant_payload.extend_from_slice(&delegated_key);
        grant_payload.extend_from_slice(&issuer_key_id(&delegated_key));
        grant_payload.push(1);
        grant_payload.extend_from_slice(&4u64.to_be_bytes());
        let grant = CanonicalSecurityEvent {
            kind: EventKind::OwnerGrant,
            space_id: *v0().space_id.as_bytes(),
            signer_key_id: issuer_key_id(&provisioned.public_key),
            issuer_epoch: 3,
            issued_at_ms: 100,
            expires_at_ms: 300,
            seq: 1,
            payload: grant_payload,
        };
        let mut revoke_payload = v0().resource_id.as_bytes().to_vec();
        revoke_payload.extend_from_slice(&[5; 32]);
        revoke_payload.push(3);
        let revoke = CanonicalSecurityEvent {
            kind: EventKind::Revocation,
            space_id: *v0().space_id.as_bytes(),
            signer_key_id: issuer_key_id(&delegated_key),
            issuer_epoch: 4,
            issued_at_ms: 120,
            expires_at_ms: 260,
            seq: 1,
            payload: revoke_payload,
        };
        let grant_bytes = encode_security_event(&grant).unwrap();
        let revoke_bytes = encode_security_event(&revoke).unwrap();
        let grant_sig = owner.sign(&signing_input(&grant_bytes).unwrap()).to_bytes();
        let revoke_sig = delegate
            .sign(&signing_input(&revoke_bytes).unwrap())
            .to_bytes();
        let proof = verify_owner_delegated_revocation_for_spike(
            &provisioned,
            &grant_bytes,
            &grant_sig,
            &revoke_bytes,
            &revoke_sig,
            150,
        )
        .unwrap();

        let db = TempDb::new();
        let store = db.open();
        assert_eq!(store.admission_state(), AdmissionState::Paused);
        assert_eq!(
            store.commit_root_bound_revocation(v0(), &root_trust_fixture(), &proof),
            Err(StoreError::NotInitialized)
        );
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        let wrong = PolicyVersion {
            resource_id: ResourceId::from_bytes([88; 16]),
            ..v0()
        };
        assert_eq!(
            store.commit_root_bound_revocation(wrong, &root_trust_fixture(), &proof),
            Err(StoreError::Conflict)
        );
        let trust = root_trust_fixture();
        let next = store.commit_root_bound_revocation(v0(), &trust, &proof).unwrap();
        assert_eq!(next.epoch, 1);
        let persisted = store.pending_outbox().unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].signed_event, proof.persistence_bytes());
        let root_hash = append_revocation_root([0; 32], 1, &proof.persistence_bytes()).unwrap();
        let receipts = root_signed_receipts(&trust, 1, root_hash);
        assert_eq!(
            store
                .inspect_root_bound_recovery(&trust, &receipts, 150)
                .unwrap(),
            RecoveryAssessment::CandidateConsistent
        );
        assert_eq!(store.admission_state(), AdmissionState::Paused);
        drop(store);
        let store = db.open();
        assert_eq!(store.admission_state(), AdmissionState::Paused);
        assert_eq!(store.persisted_epoch(v0()).unwrap(), 1);
        assert_eq!(
            store.pending_outbox().unwrap()[0].signed_event,
            proof.persistence_bytes()
        );
        // A fresh startup remains Paused even with a matching signed history.
        assert_eq!(
            store
                .inspect_root_bound_recovery(&trust, &receipts, 150)
                .unwrap(),
            RecoveryAssessment::CandidateConsistent
        );
        assert_eq!(store.admission_state(), AdmissionState::Paused);
    }

    #[test]
    fn signed_revocation_must_match_expected_resource_and_sequence() {
        use ed25519_dalek::{Signer, SigningKey};
        use loom_crypto::signed_revocation::{
            PinnedIssuerForSpike, VerifyEventError, verify_revocation_for_spike,
        };
        use loom_wire::security_event::{
            CanonicalSecurityEvent, EventKind, encode_security_event, signing_input,
        };
        let signer = SigningKey::from_bytes(&[3; 32]);
        let issuer = PinnedIssuerForSpike {
            key_id: [9; 32],
            public_key: signer.verifying_key().to_bytes(),
            space_id: v0().space_id,
            minimum_key_epoch: 1,
        };
        let mut payload = v0().resource_id.as_bytes().to_vec();
        payload.extend_from_slice(&[4; 32]);
        payload.push(3);
        let event = CanonicalSecurityEvent {
            kind: EventKind::Revocation,
            space_id: *v0().space_id.as_bytes(),
            signer_key_id: issuer.key_id,
            issuer_epoch: 1,
            issued_at_ms: 100,
            expires_at_ms: 200,
            seq: 1,
            payload,
        };
        let cbor = encode_security_event(&event).unwrap();
        let signature = signer.sign(&signing_input(&cbor).unwrap()).to_bytes();
        let checked = verify_revocation_for_spike(&cbor, &signature, &issuer, 150).unwrap();
        assert_eq!(checked.seq(), 1);
        assert_eq!(
            verify_revocation_for_spike(&cbor, &signature, &issuer, 250).unwrap_err(),
            VerifyEventError::Expired
        );

        let db = TempDb::new();
        let store = db.open();
        // This fixture simulates a trust witness. No production permit exists.
        store.recover_fixture(&[(v0(), 0)]).unwrap();
        let wrong_resource = PolicyVersion {
            resource_id: ResourceId::from_bytes([99; 16]),
            ..v0()
        };
        assert_eq!(
            store.commit_spike_revocation_for_test(wrong_resource, &checked),
            Err(StoreError::Conflict)
        );
        let wrong_seq = PolicyVersion { epoch: 1, ..v0() };
        assert_eq!(
            store.commit_spike_revocation_for_test(wrong_seq, &checked),
            Err(StoreError::Conflict)
        );
        let next = store
            .commit_spike_revocation_for_test(v0(), &checked)
            .unwrap();
        assert_eq!(next.epoch, 1);
        let entries = store.pending_outbox().unwrap();
        assert_eq!(entries.len(), 1);
        let stored = checked.persistence_bytes();
        assert_eq!(entries[0].signed_event, stored);
        drop(store);
        let restarted = db.open();
        assert_eq!(restarted.admission_state(), AdmissionState::Paused);
        assert_eq!(restarted.pending_outbox().unwrap()[0].signed_event, stored);
    }
}
