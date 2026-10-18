//! L-002A: **test-only** two-Peer LAN file-read/revocation model.
//!
//! Never exported in a non-test build. A test harness stands in for an
//! authenticated Owner and Peer session; its grants are NOT signed,
//! remotely enrolled, independently fresh or production authorization.
//! There are no sockets, real file paths, disk operations or ServiceOpen.
//! Every chunk is checked against the same volatile ACL/revision lock.
use loom_identity::PeerPrincipal;
use loom_types::{PeerId, ResourceId, SpaceId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const MAX_FIXTURE_BYTES: usize = 64 * 1024;
const MAX_CHUNK_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelReadError {
    Denied,
    StaleSession,
    InvalidChunk,
    FixtureTooLarge,
    Uncertain,
}

struct ModelReadState {
    bytes: Vec<u8>,
    grants: HashMap<PeerId, u64>,
    sessions: HashMap<u64, SessionCursor>,
    policy_revision: u64,
    next_session: u64,
}

struct SessionCursor {
    peer: PeerId,
    membership_epoch: u64,
    policy_revision: u64,
    offset: usize,
}

/// Test fixture: a single fixed resource owned by a hypothetical local Peer.
struct ModelLanFileServer {
    space: SpaceId,
    resource: ResourceId,
    state: Arc<Mutex<ModelReadState>>,
}

impl ModelLanFileServer {
    fn new_for_test(
        space: SpaceId,
        resource: ResourceId,
        content: &[u8],
    ) -> Result<Self, ModelReadError> {
        if content.len() > MAX_FIXTURE_BYTES {
            return Err(ModelReadError::FixtureTooLarge);
        }
        Ok(Self {
            space,
            resource,
            state: Arc::new(Mutex::new(ModelReadState {
                bytes: content.to_vec(),
                grants: HashMap::new(),
                sessions: HashMap::new(),
                policy_revision: 0,
                next_session: 0,
            })),
        })
    }

    /// A **simulated** Owner action, intentionally not exposed to production.
    /// All existing streams are invalidated on every policy transition.
    fn owner_grant_for_test(&self, peer: PeerId, epoch: u64) -> Result<(), ModelReadError> {
        if epoch == 0 {
            return Err(ModelReadError::Denied);
        }
        let mut state = self.state.lock().map_err(|_| ModelReadError::Uncertain)?;
        let next = state
            .policy_revision
            .checked_add(1)
            .ok_or(ModelReadError::Uncertain)?;
        state.grants.insert(peer, epoch);
        state.policy_revision = next;
        state.sessions.clear();
        Ok(())
    }

    /// Simulated signed-revocation commit callback. This must be invoked
    /// ONLY after a real signed policy/anchor commit in any future protocol.
    fn owner_revoke_for_test(&self, peer: PeerId) -> Result<(), ModelReadError> {
        let mut state = self.state.lock().map_err(|_| ModelReadError::Uncertain)?;
        let next = state
            .policy_revision
            .checked_add(1)
            .ok_or(ModelReadError::Uncertain)?;
        state.grants.remove(&peer);
        state.policy_revision = next;
        state.sessions.clear();
        Ok(())
    }

    /// No TCP, TLS, network principal verification or production admission.
    fn open_read(
        &self,
        claimed_principal: PeerPrincipal,
        resource: ResourceId,
    ) -> Result<ModelReadSession, ModelReadError> {
        if claimed_principal.space_id != self.space || resource != self.resource {
            return Err(ModelReadError::Denied);
        }
        let mut state = self.state.lock().map_err(|_| ModelReadError::Uncertain)?;
        if state.grants.get(&claimed_principal.peer_id)
            != Some(&claimed_principal.membership_epoch)
        {
            return Err(ModelReadError::Denied);
        }
        let id = state
            .next_session
            .checked_add(1)
            .ok_or(ModelReadError::Uncertain)?;
        state.next_session = id;
        let rev = state.policy_revision;
        state.sessions.insert(
            id,
            SessionCursor {
                peer: claimed_principal.peer_id,
                membership_epoch: claimed_principal.membership_epoch,
                policy_revision: rev,
                offset: 0,
            },
        );
        Ok(ModelReadSession {
            state: Arc::clone(&self.state),
            id,
        })
    }
}

/// Ephemeral, model-only stream handle; never a production permission token.
struct ModelReadSession {
    state: Arc<Mutex<ModelReadState>>,
    id: u64,
}

impl ModelReadSession {
    fn read_chunk(&self, requested: usize) -> Result<Vec<u8>, ModelReadError> {
        if requested == 0 || requested > MAX_CHUNK_BYTES {
            return Err(ModelReadError::InvalidChunk);
        }
        let mut state = self.state.lock().map_err(|_| ModelReadError::Uncertain)?;
        let cursor = state.sessions.get(&self.id).ok_or(ModelReadError::StaleSession)?;
        if cursor.policy_revision != state.policy_revision
            || state.grants.get(&cursor.peer) != Some(&cursor.membership_epoch)
        {
            return Err(ModelReadError::StaleSession);
        }
        let start = cursor.offset;
        let end = start.saturating_add(requested).min(state.bytes.len());
        let output = state.bytes[start..end].to_vec();
        if let Some(cursor) = state.sessions.get_mut(&self.id) {
            cursor.offset = end;
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_types::Action;
    use loom_policy::{Decision, DenyAllPolicy, PolicyState, ResourceAuthorizer};
    use std::sync::mpsc;
    use std::thread;

    fn space() -> SpaceId {
        SpaceId::from_bytes([21; 16])
    }
    fn resource() -> ResourceId {
        ResourceId::from_bytes([22; 16])
    }
    fn alice() -> PeerPrincipal {
        PeerPrincipal {
            peer_id: PeerId::from_digest([31; 32]),
            space_id: space(),
            membership_epoch: 7,
        }
    }
    fn bob() -> PeerPrincipal {
        PeerPrincipal {
            peer_id: PeerId::from_digest([32; 32]),
            space_id: space(),
            membership_epoch: 7,
        }
    }
    fn server() -> ModelLanFileServer {
        ModelLanFileServer::new_for_test(space(), resource(), b"hello LAN read model").unwrap()
    }

    #[test]
    fn default_is_no_grants_no_sessions() {
        let host = server();
        assert!(matches!(host.open_read(alice(), resource()), Err(ModelReadError::Denied)));
        assert!(matches!(host.open_read(bob(), resource()), Err(ModelReadError::Denied)));
    }

    #[test]
    fn owner_fixture_allows_exact_peer_resource_and_epoch_only() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let stream = host.open_read(alice(), resource()).unwrap();
        assert_eq!(stream.read_chunk(5).unwrap(), b"hello");
        assert_eq!(stream.read_chunk(40).unwrap(), b" LAN read model");
        assert_eq!(stream.read_chunk(40).unwrap(), b"");
        assert!(matches!(host.open_read(bob(), resource()), Err(ModelReadError::Denied)));
    }

    #[test]
    fn wrong_space_resource_and_membership_epoch_are_denied() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let mut impostor = alice();
        impostor.space_id = SpaceId::from_bytes([99; 16]);
        assert!(matches!(host.open_read(impostor, resource()), Err(ModelReadError::Denied)));
        impostor = alice();
        impostor.membership_epoch = 8;
        assert!(matches!(host.open_read(impostor, resource()), Err(ModelReadError::Denied)));
        assert!(matches!(
            host.open_read(alice(), ResourceId::from_bytes([99; 16])),
            Err(ModelReadError::Denied)
        ));
    }

    #[test]
    fn revoke_invalidates_an_already_open_file_stream_before_next_chunk() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let stream = host.open_read(alice(), resource()).unwrap();
        assert_eq!(stream.read_chunk(5).unwrap(), b"hello");
        host.owner_revoke_for_test(alice().peer_id).unwrap();
        assert_eq!(stream.read_chunk(5), Err(ModelReadError::StaleSession));
        assert!(matches!(host.open_read(alice(), resource()), Err(ModelReadError::Denied)));
    }

    #[test]
    fn grant_after_revoke_cannot_resurrect_an_old_stream() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let old = host.open_read(alice(), resource()).unwrap();
        host.owner_revoke_for_test(alice().peer_id).unwrap();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        assert_eq!(old.read_chunk(4), Err(ModelReadError::StaleSession));
        assert_eq!(host.open_read(alice(), resource()).unwrap().read_chunk(5).unwrap(), b"hello");
    }

    #[test]
    fn membership_key_epoch_rotation_requires_new_session() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let old = host.open_read(alice(), resource()).unwrap();
        host.owner_grant_for_test(alice().peer_id, 8).unwrap();
        assert_eq!(old.read_chunk(5), Err(ModelReadError::StaleSession));
        assert!(matches!(host.open_read(alice(), resource()), Err(ModelReadError::Denied)));
        let mut rotated = alice();
        rotated.membership_epoch = 8;
        assert_eq!(host.open_read(rotated, resource()).unwrap().read_chunk(5).unwrap(), b"hello");
    }

    #[test]
    fn any_policy_change_fails_closed_for_existing_stream() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let stream = host.open_read(alice(), resource()).unwrap();
        host.owner_grant_for_test(bob().peer_id, 7).unwrap();
        assert_eq!(stream.read_chunk(5), Err(ModelReadError::StaleSession));
    }

    #[test]
    fn invalid_chunk_requests_do_not_consume_file() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let stream = host.open_read(alice(), resource()).unwrap();
        assert_eq!(stream.read_chunk(0), Err(ModelReadError::InvalidChunk));
        assert_eq!(stream.read_chunk(MAX_CHUNK_BYTES + 1), Err(ModelReadError::InvalidChunk));
        assert_eq!(stream.read_chunk(5).unwrap(), b"hello");
    }

    #[test]
    fn oversized_fixture_and_invalid_zero_epoch_are_rejected() {
        assert!(matches!(
            ModelLanFileServer::new_for_test(space(), resource(), &[5; MAX_FIXTURE_BYTES + 1]),
            Err(ModelReadError::FixtureTooLarge)
        ));
        let host = server();
        assert_eq!(host.owner_grant_for_test(alice().peer_id, 0), Err(ModelReadError::Denied));
        assert!(matches!(host.open_read(alice(), resource()), Err(ModelReadError::Denied)));
    }

    #[test]
    fn lost_process_state_fails_closed_without_grants() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let stale = host.open_read(alice(), resource()).unwrap();
        let fresh = server();
        assert!(matches!(fresh.open_read(alice(), resource()), Err(ModelReadError::Denied)));
        assert_eq!(stale.read_chunk(5).unwrap(), b"hello");
        // This old handle is process-memory-only and MUST NOT be
        // exported or resurrected by a real daemon restart.
    }

    #[test]
    fn concurrent_revoke_race_orders_before_subsequent_read() {
        let host = server();
        host.owner_grant_for_test(alice().peer_id, 7).unwrap();
        let stream = host.open_read(alice(), resource()).unwrap();
        let (go, rx) = mpsc::channel();
        thread::scope(|scope| {
            scope.spawn(|| {
                host.owner_revoke_for_test(alice().peer_id).unwrap();
                go.send(()).unwrap();
            });
            rx.recv().unwrap();
            assert_eq!(stream.read_chunk(5), Err(ModelReadError::StaleSession));
        });
    }

    #[test]
    fn production_policy_boundary_still_denies_every_file_read() {
        let policy = DenyAllPolicy::new(PolicyState::Ready);
        assert!(matches!(
            policy.authorize(&alice(), resource(), Action::Read),
            Decision::Deny(_)
        ));
    }
}
