//! L-002B: platform-neutral trusted-state capability gate.
//!
//! TPM2, Secure Enclave, Android Keystore/StrongBox, and remote/quorum anchors
//! are **optional** providers. No platform-specific hardware backend is
//! implemented here. Descriptive capabilities are NEVER authorization proof.
//! Software state is volatile, rollbackable and permitted only for local
//! non-security-critical data. NO ServiceOpen / TPM NV / production signer.

use std::sync::Mutex;

/// An implementation hint, not proof that the named hardware exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    Software,
    Tpm2,
    SecureEnclave,
    AndroidKeystore,
    ExternalQuorum,
}

/// Hardware-protected keys do not imply an anti-rollback policy counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProtection {
    Software,
    ClaimedHardwareBound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackCapability {
    Rollbackable,
    ClaimsIndependentAnchor,
}

/// Reported by a provider. Entirely untrusted until independently verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDescriptor {
    pub kind: ProviderKind,
    pub key_protection: KeyProtection,
    pub rollback: RollbackCapability,
    pub scope_binding: Option<[u8; 32]>,
}

impl ProviderDescriptor {
    pub const fn portable_software() -> Self {
        Self {
            kind: ProviderKind::Software,
            key_protection: KeyProtection::Software,
            rollback: RollbackCapability::Rollbackable,
            scope_binding: None,
        }
    }
}

/// A separate vetted bootstrap MUST create this opaque evidence. The model
/// deliberately exposes NO public constructor: providers cannot self-enroll.
/// Even a hardware key alone cannot produce this anti-rollback evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedIndependentAnchor {
    scope_binding: [u8; 32],
    minimum_state_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateUse {
    /// Non-sensitive local configuration or diagnostics only.
    PortableLocalOnly,
    /// Requires an independently protected key, not merely a name/claim.
    HardwareKeyRequired,
    /// Requires a separately verified, monotonic and scoped trusted anchor.
    NonRollbackablePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderGateError {
    /// External hardware/provider description is not an attestation.
    EvidenceUnavailable,
    WrongScope,
    StaleGeneration,
    InadequateCapabilities,
    PersistenceUncertain,
    OversizedState,
    ConcurrentUpdate,
}

/// This result says **only** that a state backend meets its storage
/// requirements. It never authorizes a Peer, Owner, Resource or ServiceOpen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageEligibility {
    LocalStateOnly,
    VerifiedRequirementsOnly,
}

/// The hardware-agnostic security gate is distinct from resource admission.
/// The `evidence` argument MUST come from a separately reviewed verifier,
/// never from the provider's own metadata or the local SQLite database.
pub fn check_provider_requirements(
    descriptor: ProviderDescriptor,
    evidence: Option<&VerifiedIndependentAnchor>,
    expected_scope: [u8; 32],
    observed_generation: u64,
    use_case: StateUse,
) -> Result<StorageEligibility, ProviderGateError> {
    if use_case == StateUse::PortableLocalOnly {
        return Ok(StorageEligibility::LocalStateOnly);
    }

    let proof = evidence.ok_or(ProviderGateError::EvidenceUnavailable)?;
    if proof.scope_binding != expected_scope
        || descriptor.scope_binding != Some(expected_scope)
    {
        return Err(ProviderGateError::WrongScope);
    }
    if observed_generation < proof.minimum_state_generation {
        return Err(ProviderGateError::StaleGeneration);
    }

    match use_case {
        StateUse::PortableLocalOnly => Ok(StorageEligibility::LocalStateOnly),
        StateUse::HardwareKeyRequired => {
            if descriptor.key_protection != KeyProtection::ClaimedHardwareBound {
                Err(ProviderGateError::InadequateCapabilities)
            } else {
                Ok(StorageEligibility::VerifiedRequirementsOnly)
            }
        }
        StateUse::NonRollbackablePolicy => {
            if descriptor.rollback != RollbackCapability::ClaimsIndependentAnchor {
                Err(ProviderGateError::InadequateCapabilities)
            } else {
                Ok(StorageEligibility::VerifiedRequirementsOnly)
            }
        }
    }
}

/// Portable local-settings storage ABI, unrelated to signed policy state.
/// A real backend must implement its own crash consistency and proof logic.
pub trait TrustedStateProvider: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    fn read_local(&self) -> Result<LocalStateSnapshot, ProviderGateError>;
    fn compare_and_write_local(
        &self,
        expected_generation: u64,
        bytes: &[u8],
    ) -> Result<u64, ProviderGateError>;
}

const MAX_LOCAL_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalStateSnapshot {
    pub generation: u64,
    pub bytes: Vec<u8>,
}

/// Volatile, entirely software provider. Portable to any Rust target but
/// does NOT protect signing keys, anti-rollback state or authoritative ACLs.
#[derive(Default)]
pub struct SoftwareStateProvider {
    state: Mutex<LocalStateSnapshot>,
}

impl Default for LocalStateSnapshot {
    fn default() -> Self {
        Self {
            generation: 0,
            bytes: Vec::new(),
        }
    }
}

impl SoftwareStateProvider {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TrustedStateProvider for SoftwareStateProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor::portable_software()
    }

    fn read_local(&self) -> Result<LocalStateSnapshot, ProviderGateError> {
        self.state
            .lock()
            .map(|s| s.clone())
            .map_err(|_| ProviderGateError::PersistenceUncertain)
    }

    fn compare_and_write_local(
        &self,
        expected_generation: u64,
        bytes: &[u8],
    ) -> Result<u64, ProviderGateError> {
        if bytes.len() > MAX_LOCAL_BYTES {
            return Err(ProviderGateError::OversizedState);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderGateError::PersistenceUncertain)?;
        if state.generation != expected_generation {
            return Err(ProviderGateError::ConcurrentUpdate);
        }
        let next = state
            .generation
            .checked_add(1)
            .ok_or(ProviderGateError::PersistenceUncertain)?;
        state.bytes = bytes.to_vec();
        state.generation = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    const SCOPE: [u8; 32] = [11; 32];

    fn fixture_proof(floor: u64) -> VerifiedIndependentAnchor {
        // Test-only fake proof: real provisioning must be implemented in a
        // separately audited hardware/remote provider bootstrap.
        VerifiedIndependentAnchor {
            scope_binding: SCOPE,
            minimum_state_generation: floor,
        }
    }

    fn candidate(kind: ProviderKind) -> ProviderDescriptor {
        ProviderDescriptor {
            kind,
            key_protection: KeyProtection::ClaimedHardwareBound,
            rollback: RollbackCapability::ClaimsIndependentAnchor,
            scope_binding: Some(SCOPE),
        }
    }

    #[test]
    fn portable_software_works_without_any_tpm_or_platform_probe() {
        let software = SoftwareStateProvider::new();
        assert_eq!(software.descriptor(), ProviderDescriptor::portable_software());
        assert_eq!(software.read_local().unwrap().generation, 0);
        assert_eq!(software.compare_and_write_local(0, b"preferences"), Ok(1));
        assert_eq!(software.read_local().unwrap().bytes, b"preferences");
        assert_eq!(
            check_provider_requirements(
                software.descriptor(), None, SCOPE, 1, StateUse::PortableLocalOnly
            ),
            Ok(StorageEligibility::LocalStateOnly)
        );
    }

    #[test]
    fn software_never_satisfies_sensitive_rollback_or_hardware_key_demand() {
        let software = SoftwareStateProvider::new();
        for use_case in [StateUse::HardwareKeyRequired, StateUse::NonRollbackablePolicy] {
            assert_eq!(
                check_provider_requirements(software.descriptor(), None, SCOPE, 0, use_case),
                Err(ProviderGateError::EvidenceUnavailable)
            );
            assert_eq!(
                check_provider_requirements(
                    software.descriptor(), Some(&fixture_proof(0)), SCOPE, 0, use_case
                ),
                Err(ProviderGateError::WrongScope)
            );
        }
    }

    #[test]
    fn self_declared_tpm_enclave_keystore_or_quorum_cannot_self_attest() {
        for kind in [
            ProviderKind::Tpm2,
            ProviderKind::SecureEnclave,
            ProviderKind::AndroidKeystore,
            ProviderKind::ExternalQuorum,
        ] {
            let claim = candidate(kind);
            for mode in [StateUse::HardwareKeyRequired, StateUse::NonRollbackablePolicy] {
                assert_eq!(
                    check_provider_requirements(claim, None, SCOPE, 10, mode),
                    Err(ProviderGateError::EvidenceUnavailable)
                );
            }
        }
    }

    #[test]
    fn hardware_key_claim_is_not_automatically_a_rollback_anchor() {
        let mut key_only = candidate(ProviderKind::SecureEnclave);
        key_only.rollback = RollbackCapability::Rollbackable;
        assert_eq!(
            check_provider_requirements(
                key_only, Some(&fixture_proof(7)), SCOPE, 7, StateUse::NonRollbackablePolicy
            ),
            Err(ProviderGateError::InadequateCapabilities)
        );
        assert_eq!(
            check_provider_requirements(
                key_only, Some(&fixture_proof(7)), SCOPE, 7, StateUse::HardwareKeyRequired
            ),
            Ok(StorageEligibility::VerifiedRequirementsOnly)
        );
    }

    #[test]
    fn independent_anchor_requires_exact_scope_and_non_regression() {
        let candidate = candidate(ProviderKind::ExternalQuorum);
        assert_eq!(
            check_provider_requirements(
                candidate, Some(&fixture_proof(12)), SCOPE, 11, StateUse::NonRollbackablePolicy
            ),
            Err(ProviderGateError::StaleGeneration)
        );
        assert_eq!(
            check_provider_requirements(
                candidate, Some(&fixture_proof(12)), [90; 32], 12,
                StateUse::NonRollbackablePolicy
            ),
            Err(ProviderGateError::WrongScope)
        );
        assert_eq!(
            check_provider_requirements(
                candidate, Some(&fixture_proof(12)), SCOPE, 12,
                StateUse::NonRollbackablePolicy
            ),
            Ok(StorageEligibility::VerifiedRequirementsOnly)
        );
    }

    #[test]
    fn untrusted_claim_without_key_isolation_cannot_upgrade_key_assurance() {
        let mut candidate = candidate(ProviderKind::AndroidKeystore);
        candidate.key_protection = KeyProtection::Software;
        assert_eq!(
            check_provider_requirements(
                candidate, Some(&fixture_proof(0)), SCOPE, 0, StateUse::HardwareKeyRequired
            ),
            Err(ProviderGateError::InadequateCapabilities)
        );
    }

    #[test]
    fn portable_settings_are_rollbackable_and_never_carry_security_approval() {
        let provider = SoftwareStateProvider::new();
        provider.compare_and_write_local(0, b"v1").unwrap();
        assert_eq!(
            provider.compare_and_write_local(0, b"stale"),
            Err(ProviderGateError::ConcurrentUpdate)
        );
        let reopened = SoftwareStateProvider::new();
        assert_eq!(reopened.read_local().unwrap().generation, 0);
        assert_eq!(reopened.read_local().unwrap().bytes, Vec::<u8>::new());
        assert_eq!(
            check_provider_requirements(
                reopened.descriptor(), None, SCOPE, 0, StateUse::NonRollbackablePolicy
            ),
            Err(ProviderGateError::EvidenceUnavailable)
        );
    }

    #[test]
    fn local_state_size_guard_does_not_mutate_generation() {
        let p = SoftwareStateProvider::new();
        assert_eq!(
            p.compare_and_write_local(0, &[3; MAX_LOCAL_BYTES + 1]),
            Err(ProviderGateError::OversizedState)
        );
        assert_eq!(p.read_local().unwrap().generation, 0);
        p.compare_and_write_local(0, &[3; MAX_LOCAL_BYTES]).unwrap();
        assert_eq!(p.read_local().unwrap().generation, 1);
    }

    #[test]
    fn two_concurrent_software_writers_have_one_cas_winner() {
        let p = Arc::new(SoftwareStateProvider::new());
        let a = Arc::clone(&p);
        let b = Arc::clone(&p);
        let t1 = thread::spawn(move || a.compare_and_write_local(0, b"alpha"));
        let t2 = thread::spawn(move || b.compare_and_write_local(0, b"beta"));
        let results = [t1.join().unwrap(), t2.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(p.read_local().unwrap().generation, 1);
    }
}
