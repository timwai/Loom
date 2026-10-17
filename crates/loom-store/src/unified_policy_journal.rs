//! L-001I experimental unified SQLite resource-policy ledger.
//!
//! Every append replays the signed, ordered lifecycle history from genesis
//! under a pinned Root before starting a fresh atomic commit. This does not
//! establish witness freshness and NEVER transitions network admission to
//! Ready. No production permit or ServiceOpen is exported.
//!
//! Synchronous APIs: call from a blocking pool, never on a Tokio runtime core.

use crate::StoreError;
pub use crate::policy_journal_codec::NewPolicyEvent;
use crate::policy_journal_codec::{MAX_EVIDENCE, encode_event, replay_event};
use loom_crypto::owner_lifecycle::ResourceOwnerLifecycle;
use loom_crypto::space_trust::{ExternallyPinnedRootForSpike, VerifiedResourceTrust};
#[cfg(test)]
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
                        let _ = done.send(read_outbox(&connection));
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
    Ok(state)
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
    tx.commit().map_err(|_| StoreError::PersistenceFailure)?;
    Ok(snapshot(&state))
}

fn read_outbox(conn: &Connection) -> Result<Vec<CriticalPolicyOutbox>, StoreError> {
    let mut stmt = conn
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
}
