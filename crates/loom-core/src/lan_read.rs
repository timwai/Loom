//! Opt-in L-002 LAN read laboratory with actual Owner-approved file snapshots.
//!
//! No path crosses the protocol: enrollment consumes an already-open regular
//! file and freezes at most 1 MiB. Later path/symlink changes cannot redirect
//! reads. A new file snapshot requires separate Owner enrollment. This module
//! does NOT provide production ServiceOpen or independently durable enrollment.

use loom_crypto::{membership::VerifiedMembership, space_trust::VerifiedResourceTrust};
use loom_identity::{PeerPrincipal, signed_membership::SignedMembershipVerifier};
use loom_store::{
    challenge_witness_quorum::{
        PinnedQuorum, QuorumChallenge, SignedQuorumObservation, verify_challenge_bound_quorum,
    },
    witness_append::{SignedAppend, WitnessHistory, WitnessLog},
};
use loom_transport::secure_channel::SecurePeerChannel;
use loom_types::ResourceId;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    Denied,
    Stale,
    Storage,
    InvalidInput,
    Quorum,
    Membership,
    Clock,
}

/// A process-local session, invalidated by EVERY policy change, including a
/// revoke followed by re-grant. Never serialized as a durable admission token.
#[derive(Debug)]
pub struct ReadSession {
    principal: PeerPrincipal,
    key_epoch: u64,
    head: [u8; 32],
    snapshot: [u8; 32],
    offset: usize,
}

pub struct LanReadCandidate {
    trust: VerifiedResourceTrust,
    bytes: Vec<u8>,
    digest: [u8; 32],
    journal: Mutex<WitnessLog>,
}

fn now_ms() -> Result<u64, ReadError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReadError::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| ReadError::Clock)
}

impl LanReadCandidate {
    /// Local Owner supplies the capability, NEVER a received path. The handle
    /// must have been safely selected by a trusted enrollment workflow. Snapshot
    /// enrollment while another local writer edits the file is not supported.
    pub fn from_owner_file(
        trust: VerifiedResourceTrust,
        mut file: File,
        journal: WitnessLog,
    ) -> Result<Self, ReadError> {
        if journal.manifest_commitment() != trust.manifest_commitment() {
            return Err(ReadError::Storage);
        }
        let metadata = file.metadata().map_err(|_| ReadError::Storage)?;
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
            return Err(ReadError::InvalidInput);
        }
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ReadError::Storage)?;
        file.by_ref()
            .take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReadError::Storage)?;
        if bytes.len() > MAX_FILE_BYTES || bytes.len() as u64 != metadata.len() {
            return Err(ReadError::InvalidInput);
        }
        let digest = Sha256::digest(&bytes).into();
        Ok(Self {
            trust,
            bytes,
            digest,
            journal: Mutex::new(journal),
        })
    }

    pub fn snapshot_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Local signed policy commits share the read barrier. No network call is
    /// made under this lock. A partial remote quorum never authorizes a read.
    pub fn commit(&self, signed: SignedAppend) -> Result<WitnessHistory, ReadError> {
        signed
            .verify_history(&self.trust)
            .map_err(|_| ReadError::Denied)?;
        self.journal
            .lock()
            .map_err(|_| ReadError::Storage)?
            .append(signed, now_ms()?)
            .map_err(|_| ReadError::Storage)
    }

    fn history(&self) -> Result<WitnessHistory, ReadError> {
        let records = self
            .journal
            .lock()
            .map_err(|_| ReadError::Storage)?
            .history()
            .map_err(|_| ReadError::Storage)?
            .into_records();
        // Re-verify against THIS resource's root, even if the supplied SQLite
        // handle was enrolled for a different manifest.
        WitnessHistory::verify(&self.trust, records).map_err(|_| ReadError::Storage)
    }

    fn check_channel<S>(
        &self,
        channel: &SecurePeerChannel<S>,
        member: &VerifiedMembership,
        verifier: &SignedMembershipVerifier,
    ) -> Result<(), ReadError> {
        channel
            .revalidate_membership(verifier)
            .map_err(|_| ReadError::Membership)?;
        let principal = channel.remote_principal();
        if !member.valid_at(now_ms()?)
            || member.root_identity() != (self.trust.root_public_key(), self.trust.root_key_epoch())
            || member.space() != self.trust.space()
            || principal.peer_id != member.peer()
            || channel.remote_key_epoch() != member.key_epoch()
            || principal.space_id != member.space()
            || principal.membership_epoch != member.member_epoch()
        {
            return Err(ReadError::Membership);
        }
        Ok(())
    }

    /// Fetch runs without a SQLite transaction or resource lock. The nonce is
    /// created here by OS CSPRNG and lives for this one call only. Every open
    /// and chunk requires two fresh responses; timeout/offline is fail-closed.
    fn fresh_history<F>(&self, fetch: F) -> Result<WitnessHistory, ReadError>
    where
        F: FnOnce(QuorumChallenge) -> Result<Vec<SignedQuorumObservation>, ReadError>,
    {
        let history = self.history()?;
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| ReadError::Quorum)?;
        let challenge = QuorumChallenge {
            nonce,
            expected_space: self.trust.space(),
            expected_resource: self.trust.resource(),
            expected_writer_epoch: self.trust.writer_epoch(),
        };
        let replies = fetch(challenge)?;
        verify_challenge_bound_quorum(
            &PinnedQuorum {
                witnesses: self.trust.witnesses(),
                space: self.trust.space(),
                resource: self.trust.resource(),
                writer_epoch: self.trust.writer_epoch(),
            },
            challenge,
            &replies,
            history.high_water().sequence,
            history.high_water(),
        )
        .map_err(|_| ReadError::Quorum)?;
        Ok(history)
    }

    pub fn open_read<S, F>(
        &self,
        channel: &SecurePeerChannel<S>,
        member: &VerifiedMembership,
        verifier: &SignedMembershipVerifier,
        resource: ResourceId,
        fetch: F,
    ) -> Result<ReadSession, ReadError>
    where
        F: FnOnce(QuorumChallenge) -> Result<Vec<SignedQuorumObservation>, ReadError>,
    {
        if resource != self.trust.resource() {
            return Err(ReadError::Denied);
        }
        self.check_channel(channel, member, verifier)?;
        let history = self.fresh_history(fetch)?;
        let mut journal = self.journal.lock().map_err(|_| ReadError::Storage)?;
        self.check_channel(channel, member, verifier)?;
        journal
            .inspect(|current| {
                Ok((|| {
                    if current.high_water() != history.high_water() {
                        return Err(ReadError::Stale);
                    }
                    if !self.trust.valid_at(now_ms()?)
                        || !history.permits(
                            member.peer(),
                            member.key_epoch(),
                            member.member_epoch(),
                            now_ms()?,
                        )
                    {
                        return Err(ReadError::Denied);
                    }
                    Ok(ReadSession {
                        principal: *channel.remote_principal(),
                        key_epoch: member.key_epoch(),
                        head: history.high_water().policy_head,
                        snapshot: self.digest,
                        offset: 0,
                    })
                })())
            })
            .map_err(|_| ReadError::Storage)?
    }

    /// Linearization boundary is copying this bounded chunk under the local
    /// commit barrier. Bytes copied before a revoke can remain in TLS/kernel
    /// buffers; a revocation cannot recall bytes already released.
    pub fn read_chunk<S, F>(
        &self,
        session: &mut ReadSession,
        channel: &SecurePeerChannel<S>,
        member: &VerifiedMembership,
        verifier: &SignedMembershipVerifier,
        size: usize,
        fetch: F,
    ) -> Result<Vec<u8>, ReadError>
    where
        F: FnOnce(QuorumChallenge) -> Result<Vec<SignedQuorumObservation>, ReadError>,
    {
        if size == 0 || size > MAX_CHUNK_BYTES {
            return Err(ReadError::InvalidInput);
        }
        self.check_channel(channel, member, verifier)?;
        if session.principal != *channel.remote_principal()
            || session.key_epoch != member.key_epoch()
            || session.snapshot != self.digest
        {
            return Err(ReadError::Stale);
        }
        let history = self.fresh_history(fetch)?;
        let mut journal = self.journal.lock().map_err(|_| ReadError::Storage)?;
        self.check_channel(channel, member, verifier)?;
        journal
            .inspect(|current| {
                Ok((|| {
                    if current.high_water() != history.high_water()
                        || session.head != current.high_water().policy_head
                    {
                        return Err(ReadError::Stale);
                    }
                    if !self.trust.valid_at(now_ms()?)
                        || !history.permits(
                            member.peer(),
                            member.key_epoch(),
                            member.member_epoch(),
                            now_ms()?,
                        )
                    {
                        return Err(ReadError::Denied);
                    }
                    let end = session.offset.saturating_add(size).min(self.bytes.len());
                    let bytes = self
                        .bytes
                        .get(session.offset..end)
                        .ok_or(ReadError::Stale)?
                        .to_vec();
                    session.offset = end;
                    Ok(bytes)
                })())
            })
            .map_err(|_| ReadError::Storage)?
    }
}
