//! L-002D candidate authenticated, crash-durable Witness log.
//!
//! Each SQLite log atomically CASes one Owner-signed transition. Two logs are
//! NOT an atomic distributed transaction: partial writes must quarantine reads
//! until the identical request is retried. Ordinary SQLite is rollbackable;
//! local files and fixture keys are never independent antirollback evidence.

use crate::challenge_witness_quorum::{
    QuorumChallenge, QuorumHighWater, QuorumObservation, SignedQuorumObservation,
    quorum_observation_transcript,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use loom_crypto::space_trust::VerifiedResourceTrust;
use loom_crypto::witness_checkpoint::TrustedWitnessForSpike;
use loom_types::PeerId;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, path::Path, time::Duration};

const DOMAIN: &[u8] = b"LOOM:WITNESS-APPEND:V1\0";
const BODY_LEN: usize = 32 + 8 + 32 + 32 + 8 + 8 + 1 + 8 + 8;
pub const SIGNED_APPEND_BYTES: usize = DOMAIN.len() + BODY_LEN + 64;
const MAX_RECORDS: usize = 16_384;

/// Exact read-only ACL mutation. `allow=false` removes all epochs for this Peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadMutation {
    pub peer: PeerId,
    pub key_epoch: u64,
    pub member_epoch: u64,
    pub allow: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendRequest {
    pub manifest: [u8; 32],
    pub expected_generation: u64,
    pub previous_head: [u8; 32],
    pub mutation: ReadMutation,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedAppend {
    pub request: AppendRequest,
    pub owner_signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppendError {
    Storage,
    InvalidRecord,
    InvalidSignature,
    WrongTrust,
    Expired,
    Conflict,
    /// Both requests are Owner-signed for the same predecessor. Retain this
    /// record with the rejected request as evidence; never choose a winner.
    Fork(Box<SignedAppend>),
}

pub fn append_transcript(r: &AppendRequest) -> Vec<u8> {
    let mut b = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    b.extend_from_slice(DOMAIN);
    b.extend_from_slice(&r.manifest);
    b.extend_from_slice(&r.expected_generation.to_be_bytes());
    b.extend_from_slice(&r.previous_head);
    b.extend_from_slice(r.mutation.peer.digest());
    b.extend_from_slice(&r.mutation.key_epoch.to_be_bytes());
    b.extend_from_slice(&r.mutation.member_epoch.to_be_bytes());
    b.push(u8::from(r.mutation.allow));
    b.extend_from_slice(&r.issued_at_ms.to_be_bytes());
    b.extend_from_slice(&r.expires_at_ms.to_be_bytes());
    b
}

impl SignedAppend {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = append_transcript(&self.request);
        b.extend_from_slice(&self.owner_signature);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AppendError> {
        if bytes.len() != SIGNED_APPEND_BYTES || !bytes.starts_with(DOMAIN) {
            return Err(AppendError::InvalidRecord);
        }
        let mut pos = DOMAIN.len();
        fn take<const N: usize>(b: &[u8], p: &mut usize) -> Result<[u8; N], AppendError> {
            let result = b.get(*p..*p + N).ok_or(AppendError::InvalidRecord)?;
            *p += N;
            result.try_into().map_err(|_| AppendError::InvalidRecord)
        }
        let manifest = take(bytes, &mut pos)?;
        let expected_generation = u64::from_be_bytes(take(bytes, &mut pos)?);
        let previous_head = take(bytes, &mut pos)?;
        let peer = PeerId::from_digest(take(bytes, &mut pos)?);
        let key_epoch = u64::from_be_bytes(take(bytes, &mut pos)?);
        let member_epoch = u64::from_be_bytes(take(bytes, &mut pos)?);
        let allow = match take::<1>(bytes, &mut pos)?[0] {
            0 => false,
            1 => true,
            _ => return Err(AppendError::InvalidRecord),
        };
        let issued_at_ms = u64::from_be_bytes(take(bytes, &mut pos)?);
        let expires_at_ms = u64::from_be_bytes(take(bytes, &mut pos)?);
        let owner_signature = take(bytes, &mut pos)?;
        Ok(Self {
            request: AppendRequest {
                manifest,
                expected_generation,
                previous_head,
                mutation: ReadMutation {
                    peer,
                    key_epoch,
                    member_epoch,
                    allow,
                },
                issued_at_ms,
                expires_at_ms,
            },
            owner_signature,
        })
    }

    /// Historical authentication: expiry forbids new appends and grants, but
    /// MUST NOT erase a previously committed revocation during replay.
    pub fn verify_history(&self, trust: &VerifiedResourceTrust) -> Result<(), AppendError> {
        let r = self.request;
        if r.manifest != trust.manifest_commitment() {
            return Err(AppendError::WrongTrust);
        }
        let (start, end) = trust.validity_interval();
        if r.mutation.key_epoch == 0
            || r.mutation.member_epoch == 0
            || r.expected_generation >= MAX_RECORDS as u64
            || r.issued_at_ms < start
            || r.expires_at_ms > end
            || r.issued_at_ms >= r.expires_at_ms
        {
            return Err(AppendError::InvalidRecord);
        }
        VerifyingKey::from_bytes(&trust.owner().public_key)
            .map_err(|_| AppendError::WrongTrust)?
            .verify_strict(
                &append_transcript(&r),
                &Signature::from_bytes(&self.owner_signature),
            )
            .map_err(|_| AppendError::InvalidSignature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessHistory {
    records: Vec<SignedAppend>,
    high_water: QuorumHighWater,
}

impl WitnessHistory {
    pub fn records(&self) -> &[SignedAppend] {
        &self.records
    }
    pub fn into_records(self) -> Vec<SignedAppend> {
        self.records
    }
    pub fn high_water(&self) -> QuorumHighWater {
        self.high_water
    }
    pub fn verify(
        trust: &VerifiedResourceTrust,
        records: Vec<SignedAppend>,
    ) -> Result<Self, AppendError> {
        if records.len() > MAX_RECORDS {
            return Err(AppendError::InvalidRecord);
        }
        let mut high_water = QuorumHighWater {
            space: trust.space(),
            resource: trust.resource(),
            writer_epoch: trust.writer_epoch(),
            sequence: 0,
            policy_head: [0; 32],
            revocation_root: [0; 32],
        };
        for signed in &records {
            signed.verify_history(trust)?;
            let r = signed.request;
            if r.expected_generation != high_water.sequence
                || r.previous_head != high_water.policy_head
            {
                return Err(AppendError::Conflict);
            }
            high_water.sequence += 1;
            high_water.policy_head = Sha256::digest(signed.encode()).into();
            if !r.mutation.allow {
                let mut h = Sha256::new();
                h.update(b"LOOM:WITNESS-REVOKE:V1\0");
                h.update(high_water.revocation_root);
                h.update(signed.encode());
                high_water.revocation_root = h.finalize().into();
            }
        }
        Ok(Self {
            records,
            high_water,
        })
    }

    pub fn permits(&self, peer: PeerId, key_epoch: u64, member_epoch: u64, now_ms: u64) -> bool {
        self.records
            .iter()
            .rev()
            .find(|s| s.request.mutation.peer == peer)
            .is_some_and(|s| {
                let r = s.request;
                r.mutation.allow
                    && r.mutation.key_epoch == key_epoch
                    && r.mutation.member_epoch == member_epoch
                    && r.issued_at_ms <= now_ms
                    && now_ms < r.expires_at_ms
            })
    }
}

/// Candidate local storage adapter. Always replays signed history in the same
/// transaction as CAS/read. No cache can turn a corrupt/missing DB into Allow.
pub struct WitnessLog {
    connection: Connection,
    trust: VerifiedResourceTrust,
}

impl WitnessLog {
    /// Explicit enrollment only: never replaces an existing log. A failed
    /// enrollment leaves an unusable file, requiring deliberate operator repair.
    pub fn create(path: &Path, trust: VerifiedResourceTrust) -> Result<Self, AppendError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| AppendError::Storage)?;
        file.sync_all().map_err(|_| AppendError::Storage)?;
        let mut log = Self::connect(path, trust)?;
        let tx = log
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AppendError::Storage)?;
        tx.execute_batch("CREATE TABLE enrollment (id INTEGER PRIMARY KEY CHECK(id=1), manifest BLOB NOT NULL); CREATE TABLE entries (generation INTEGER PRIMARY KEY, evidence BLOB NOT NULL); CREATE TABLE forks (rejected BLOB PRIMARY KEY NOT NULL, accepted BLOB NOT NULL);").map_err(|_| AppendError::Storage)?;
        tx.execute(
            "INSERT INTO enrollment VALUES (1, ?1)",
            [trust.manifest_commitment().as_slice()],
        )
        .map_err(|_| AppendError::Storage)?;
        tx.commit().map_err(|_| AppendError::Storage)?;
        #[cfg(unix)]
        std::fs::File::open(path.parent().ok_or(AppendError::Storage)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AppendError::Storage)?;
        Ok(log)
    }

    pub fn open(path: &Path, trust: VerifiedResourceTrust) -> Result<Self, AppendError> {
        let mut log = Self::connect(path, trust)?;
        // Quarantined logs may be opened to export authenticated fork evidence,
        // but history, appends and signed observations all remain refused.
        log.fork_evidence()?;
        Ok(log)
    }

    pub fn manifest_commitment(&self) -> [u8; 32] {
        self.trust.manifest_commitment()
    }

    fn reject_quarantined(c: &Connection) -> Result<(), AppendError> {
        let count: u64 = c
            .query_row("SELECT count(*) FROM forks", [], |r| r.get(0))
            .map_err(|_| AppendError::Storage)?;
        if count != 0 {
            return Err(AppendError::Conflict);
        }
        Ok(())
    }

    fn connect(path: &Path, trust: VerifiedResourceTrust) -> Result<Self, AppendError> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|_| AppendError::Storage)?;
        connection
            .busy_timeout(Duration::from_millis(100))
            .map_err(|_| AppendError::Storage)?;
        // DELETE mode keeps each committed image self-contained. FULL is an OS
        // durability request, not physical power-loss or rollback certification.
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
            )
            .map_err(|_| AppendError::Storage)?;
        Ok(Self { connection, trust })
    }

    fn replay(
        c: &Connection,
        trust: &VerifiedResourceTrust,
    ) -> Result<WitnessHistory, AppendError> {
        let manifest: Vec<u8> = c
            .query_row("SELECT CASE WHEN length(manifest)=32 THEN manifest ELSE NULL END FROM enrollment WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(|_| AppendError::Storage)?;
        if manifest.as_slice() != trust.manifest_commitment() {
            return Err(AppendError::WrongTrust);
        }
        let mut stmt = c
            .prepare(&format!("SELECT generation,CASE WHEN length(evidence)={SIGNED_APPEND_BYTES} THEN evidence ELSE NULL END FROM entries ORDER BY generation LIMIT 16385"))
            .map_err(|_| AppendError::Storage)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(|_| AppendError::Storage)?;
        let mut records = Vec::new();
        for row in rows {
            let (generation, bytes) = row.map_err(|_| AppendError::Storage)?;
            if generation != records.len() as u64 + 1 || records.len() == MAX_RECORDS {
                return Err(AppendError::InvalidRecord);
            }
            records.push(SignedAppend::decode(&bytes)?);
        }
        WitnessHistory::verify(trust, records)
    }

    pub fn history(&mut self) -> Result<WitnessHistory, AppendError> {
        self.inspect(Ok)
    }

    /// A bounded local operation may run under the read transaction. In DELETE
    /// journal mode even another SQLite connection cannot commit a policy
    /// change until this operation completes. Never perform network IO here.
    pub fn inspect<T>(
        &mut self,
        operation: impl FnOnce(WitnessHistory) -> Result<T, AppendError>,
    ) -> Result<T, AppendError> {
        let tx = self
            .connection
            .transaction()
            .map_err(|_| AppendError::Storage)?;
        let history = Self::replay(&tx, &self.trust)?;
        Self::reject_quarantined(&tx)?;
        let result = operation(history)?;
        tx.commit().map_err(|_| AppendError::Storage)?;
        Ok(result)
    }

    /// Acknowledges only after SQLite COMMIT. An error/connection loss is an
    /// ambiguous outcome: retry exact signed bytes, never sign a replacement.
    pub fn append(
        &mut self,
        signed: SignedAppend,
        now_ms: u64,
    ) -> Result<WitnessHistory, AppendError> {
        self.append_inner(signed, now_ms, |_| {})
    }

    /// Fault injection is compiled only by an explicit laboratory feature.
    #[cfg(feature = "witness-lab")]
    pub fn append_lab(
        &mut self,
        signed: SignedAppend,
        now_ms: u64,
        at: impl FnMut(&str),
    ) -> Result<WitnessHistory, AppendError> {
        self.append_inner(signed, now_ms, at)
    }

    fn append_inner(
        &mut self,
        signed: SignedAppend,
        now_ms: u64,
        mut at: impl FnMut(&str),
    ) -> Result<WitnessHistory, AppendError> {
        signed.verify_history(&self.trust)?;
        let r = signed.request;
        if !self.trust.valid_at(now_ms) {
            return Err(AppendError::Expired);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AppendError::Storage)?;
        let history = Self::replay(&tx, &self.trust)?;
        Self::reject_quarantined(&tx)?;
        if let Some(stored) = history.records.get(r.expected_generation as usize) {
            if *stored == signed {
                return Ok(history);
            }
            if stored.request.previous_head == r.previous_head {
                // Persist both authenticated alternatives before returning
                // fork evidence, without changing the selected policy head.
                let count: u64 = tx
                    .query_row("SELECT count(*) FROM forks", [], |r| r.get(0))
                    .map_err(|_| AppendError::Storage)?;
                if count >= MAX_RECORDS as u64 {
                    return Err(AppendError::Storage);
                }
                tx.execute(
                    "INSERT OR IGNORE INTO forks VALUES (?1,?2)",
                    params![signed.encode(), stored.encode()],
                )
                .map_err(|_| AppendError::Storage)?;
                let stored = *stored;
                tx.commit().map_err(|_| AppendError::Storage)?;
                return Err(AppendError::Fork(Box::new(stored)));
            }
            return Err(AppendError::Conflict);
        }
        if r.issued_at_ms > now_ms || now_ms >= r.expires_at_ms {
            return Err(AppendError::Expired);
        }
        if r.expected_generation != history.high_water.sequence
            || r.previous_head != history.high_water.policy_head
        {
            return Err(AppendError::Conflict);
        }
        at("before-insert");
        tx.execute(
            "INSERT INTO entries VALUES (?1,?2)",
            params![r.expected_generation + 1, signed.encode()],
        )
        .map_err(|_| AppendError::Storage)?;
        let next = Self::replay(&tx, &self.trust)?;
        at("after-insert");
        tx.commit().map_err(|_| AppendError::Storage)?;
        at("after-commit");
        Ok(next)
    }

    pub fn fork_evidence(&mut self) -> Result<Vec<(SignedAppend, SignedAppend)>, AppendError> {
        let tx = self
            .connection
            .transaction()
            .map_err(|_| AppendError::Storage)?;
        let history = Self::replay(&tx, &self.trust)?;
        let mut stmt = tx
            .prepare(&format!("SELECT CASE WHEN length(accepted)={SIGNED_APPEND_BYTES} THEN accepted ELSE NULL END,CASE WHEN length(rejected)={SIGNED_APPEND_BYTES} THEN rejected ELSE NULL END FROM forks LIMIT 16385"))
            .map_err(|_| AppendError::Storage)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|_| AppendError::Storage)?;
        let mut evidence = Vec::new();
        for row in rows {
            let (accepted, rejected) = row.map_err(|_| AppendError::Storage)?;
            let (a, b) = (
                SignedAppend::decode(&accepted)?,
                SignedAppend::decode(&rejected)?,
            );
            a.verify_history(&self.trust)?;
            b.verify_history(&self.trust)?;
            if evidence.len() == MAX_RECORDS
                || a == b
                || a.request.expected_generation != b.request.expected_generation
                || a.request.previous_head != b.request.previous_head
                || history.records.get(a.request.expected_generation as usize) != Some(&a)
            {
                return Err(AppendError::InvalidRecord);
            }
            evidence.push((a, b));
        }
        Ok(evidence)
    }

    /// Sign the log's own current state, never a client-supplied expected head.
    pub fn observe(
        &mut self,
        key: &SigningKey,
        challenge: QuorumChallenge,
        now_ms: u64,
    ) -> Result<SignedQuorumObservation, AppendError> {
        let pin = TrustedWitnessForSpike::from_public_key(key.verifying_key().to_bytes());
        if !self.trust.valid_at(now_ms)
            || challenge.nonce == [0; 32]
            || challenge.expected_space != self.trust.space()
            || challenge.expected_resource != self.trust.resource()
            || challenge.expected_writer_epoch != self.trust.writer_epoch()
            || !self
                .trust
                .witnesses()
                .iter()
                .any(|w| w.key_id == pin.key_id)
        {
            return Err(AppendError::WrongTrust);
        }
        let high_water = self.history()?.high_water;
        let observation = QuorumObservation {
            challenge,
            generation: high_water.sequence,
            high_water,
        };
        Ok(SignedQuorumObservation {
            witness_key_id: pin.key_id,
            observation,
            signature: key
                .sign(&quorum_observation_transcript(&observation))
                .to_bytes(),
        })
    }
}
