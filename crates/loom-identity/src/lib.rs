//! Peer identity and space membership proof abstraction.
//! Signed credential checking is experimental; enrollment, durable revocation
//! and a coordinated admission barrier remain unimplemented.

use loom_crypto::CryptoError;
use loom_types::{PeerId, SpaceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerPrincipal {
    pub peer_id: PeerId,
    pub space_id: SpaceId,
    pub membership_epoch: u64,
}

pub trait MembershipVerifier: Send + Sync {
    fn verify_membership(&self, principal: &PeerPrincipal) -> Result<(), CryptoError>;

    /// Resolve TLS key epoch separately from membership epoch. The default
    /// preserves legacy diagnostic verifiers; signed credentials override it.
    fn resolve_principal(
        &self,
        peer_id: PeerId,
        space_id: SpaceId,
        key_epoch: u64,
    ) -> Result<PeerPrincipal, CryptoError> {
        let principal = PeerPrincipal {
            peer_id,
            space_id,
            membership_epoch: key_epoch,
        };
        self.verify_membership(&principal)?;
        Ok(principal)
    }
}

pub mod signed_membership;

pub struct RejectUnverifiedMembership;

impl MembershipVerifier for RejectUnverifiedMembership {
    fn verify_membership(&self, _principal: &PeerPrincipal) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_membership_always_rejects() {
        let principal = PeerPrincipal {
            peer_id: PeerId::from_digest([1; 32]),
            space_id: SpaceId::from_bytes([2; 16]),
            membership_epoch: 1,
        };
        let verifier = RejectUnverifiedMembership;
        assert_eq!(
            verifier.verify_membership(&principal),
            Err(CryptoError::NotImplemented)
        );
    }
}
