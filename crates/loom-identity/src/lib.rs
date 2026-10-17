//! Peer identity and space membership proof abstraction.
//! Real certificate/key binding, revocation and membership verification are NOT implemented.

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
}

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
