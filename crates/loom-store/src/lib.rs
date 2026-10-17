//! Transaction persistence boundary; L-001C experimental actor added.
//! The default deliberately does not persist or acknowledge security events.

use loom_types::{ResourceId, SpaceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    NotInitialized,
    Conflict,
    PersistenceFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyVersion {
    pub space_id: SpaceId,
    pub resource_id: ResourceId,
    pub epoch: u64,
}

pub trait SecurityEventStore: Send + Sync {
    fn commit_revocation(
        &self,
        version: PolicyVersion,
        signed_event: &[u8],
    ) -> Result<PolicyVersion, StoreError>;
}

pub struct RejectUninitializedStore;

impl SecurityEventStore for RejectUninitializedStore {
    fn commit_revocation(
        &self,
        _version: PolicyVersion,
        _signed_event: &[u8],
    ) -> Result<PolicyVersion, StoreError> {
        Err(StoreError::NotInitialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_ack_before_persist() {
        let version = PolicyVersion {
            space_id: SpaceId::from_bytes([1; 16]),
            resource_id: ResourceId::from_bytes([2; 16]),
            epoch: 3,
        };
        assert_eq!(
            RejectUninitializedStore.commit_revocation(version, b"unverified"),
            Err(StoreError::NotInitialized)
        );
    }
}

/// Experimental fail-closed SQLite revoke/outbox coordinator.
pub mod sqlite_revocation;

/// External rollback-resistant high-water interface; no production provider.
pub mod rollback_anchor;

mod policy_journal_codec;
/// Unified signed lifecycle journal candidate. Always fail-closed for network use.
pub mod unified_policy_journal;
