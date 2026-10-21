//! Deny-by-default policy boundary. Grant ledger and admission barrier are not yet implemented.
//! Do not substitute a mock permit into a live ServiceOpen.

use loom_identity::PeerPrincipal;
use loom_types::{Action, ResourceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyState {
    NotInitialized,
    Ready,
    PolicyStale,
    SyncConflict,
    SafeReadOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenyReason {
    NoVerifiedGrant,
    StalePolicy,
    ConflictingPolicy,
    NotInitialized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Deny(DenyReason),
}

/// Deliberately no Allow variant until a verified Owner-signed authorization is implemented.
pub trait ResourceAuthorizer: Send + Sync {
    fn authorize(&self, caller: &PeerPrincipal, resource: ResourceId, action: Action) -> Decision;
}

#[derive(Clone, Copy, Debug)]
pub struct DenyAllPolicy {
    state: PolicyState,
}

impl DenyAllPolicy {
    pub const fn new(state: PolicyState) -> Self {
        Self { state }
    }
}

impl Default for DenyAllPolicy {
    fn default() -> Self {
        Self::new(PolicyState::NotInitialized)
    }
}

impl ResourceAuthorizer for DenyAllPolicy {
    fn authorize(
        &self,
        _caller: &PeerPrincipal,
        _resource: ResourceId,
        _action: Action,
    ) -> Decision {
        let reason = match self.state {
            PolicyState::PolicyStale => DenyReason::StalePolicy,
            PolicyState::SyncConflict => DenyReason::ConflictingPolicy,
            PolicyState::Ready => DenyReason::NoVerifiedGrant,
            PolicyState::NotInitialized | PolicyState::SafeReadOnly => DenyReason::NotInitialized,
        };
        Decision::Deny(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_types::{PeerId, SpaceId};

    #[test]
    fn no_state_can_open_a_resource_without_real_credential() {
        let principal = PeerPrincipal {
            peer_id: PeerId::from_digest([1; 32]),
            space_id: SpaceId::from_bytes([2; 16]),
            membership_epoch: 7,
        };
        for state in [
            PolicyState::NotInitialized,
            PolicyState::Ready,
            PolicyState::PolicyStale,
            PolicyState::SyncConflict,
            PolicyState::SafeReadOnly,
        ] {
            for action in [
                Action::Read,
                Action::Write,
                Action::Connect,
                Action::Administer,
            ] {
                assert!(matches!(
                    DenyAllPolicy::new(state).authorize(
                        &principal,
                        ResourceId::from_bytes([3; 16]),
                        action
                    ),
                    Decision::Deny(_)
                ));
            }
        }
    }
}
