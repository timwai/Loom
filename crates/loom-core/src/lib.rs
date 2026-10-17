//! Loom peer orchestrator. L-000 scaffolding has no network or resource access.

use loom_identity::PeerPrincipal;
use loom_policy::{Decision, DenyAllPolicy, PolicyState, ResourceAuthorizer};
use loom_types::{Action, ResourceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeState {
    BootstrapOnly,
    PolicyStale,
    Ready,
}

/// Ready is deliberately impossible to construct through L-000's public API.
#[derive(Default)]
pub struct PeerCore {
    authorizer: DenyAllPolicy,
}

impl PeerCore {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn state(&self) -> RuntimeState {
        RuntimeState::BootstrapOnly
    }

    pub const fn network_listening_enabled(&self) -> bool {
        false
    }

    pub fn authorize(
        &self,
        principal: &PeerPrincipal,
        resource: ResourceId,
        action: Action,
    ) -> Decision {
        self.authorizer.authorize(principal, resource, action)
    }

    pub fn policy_state(&self) -> PolicyState {
        PolicyState::NotInitialized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_types::{PeerId, SpaceId};

    #[test]
    fn bootstrap_must_not_serve_network_or_resources() {
        let core = PeerCore::new();
        assert!(!core.network_listening_enabled());
        assert_eq!(core.state(), RuntimeState::BootstrapOnly);
        let principal = PeerPrincipal {
            peer_id: PeerId::from_digest([1; 32]),
            space_id: SpaceId::from_bytes([2; 16]),
            membership_epoch: 1,
        };
        assert!(matches!(
            core.authorize(&principal, ResourceId::from_bytes([3; 16]), Action::Read),
            Decision::Deny(_)
        ));
    }
}
