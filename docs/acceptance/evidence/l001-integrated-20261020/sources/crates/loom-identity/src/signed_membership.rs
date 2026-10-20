//! Live credential checking for the experimental TLS channel. Current pins and
//! credentials must be supplied by an authenticated coordinator. Pausing or
//! replacing this verifier does not by itself close an existing socket.
use crate::{MembershipVerifier, PeerPrincipal};
use loom_crypto::{CryptoError, membership::VerifiedMembership};
use loom_types::{PeerId, SpaceId};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct SignedMembershipVerifier {
    current: Mutex<Option<VerifiedMembership>>,
}

impl SignedMembershipVerifier {
    pub fn new(verified: VerifiedMembership) -> Self {
        Self {
            current: Mutex::new(Some(verified)),
        }
    }

    pub fn pause(&self) -> Result<(), CryptoError> {
        *self
            .current
            .lock()
            .map_err(|_| CryptoError::InvalidIdentity)? = None;
        Ok(())
    }

    fn current(&self) -> Result<VerifiedMembership, CryptoError> {
        let value = self
            .current
            .lock()
            .map_err(|_| CryptoError::InvalidIdentity)?
            .ok_or(CryptoError::InvalidIdentity)?;
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::InvalidIdentity)?
            .as_millis()
            .try_into()
            .map_err(|_| CryptoError::InvalidIdentity)?;
        if !value.valid_at(now) {
            return Err(CryptoError::InvalidIdentity);
        }
        Ok(value)
    }
}

impl MembershipVerifier for SignedMembershipVerifier {
    fn verify_membership(&self, principal: &PeerPrincipal) -> Result<(), CryptoError> {
        let value = self.current()?;
        if principal.peer_id == value.peer()
            && principal.space_id == value.space()
            && principal.membership_epoch == value.member_epoch()
        {
            Ok(())
        } else {
            Err(CryptoError::InvalidIdentity)
        }
    }

    fn resolve_principal(
        &self,
        peer: PeerId,
        space: SpaceId,
        key_epoch: u64,
    ) -> Result<PeerPrincipal, CryptoError> {
        let value = self.current()?;
        if peer != value.peer() || space != value.space() || key_epoch != value.key_epoch() {
            return Err(CryptoError::InvalidIdentity);
        }
        Ok(PeerPrincipal {
            peer_id: peer,
            space_id: space,
            membership_epoch: value.member_epoch(),
        })
    }
}
