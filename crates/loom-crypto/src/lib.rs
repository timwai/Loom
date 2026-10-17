//! Security interfaces only. No signing or trust-all verifier is implemented yet.
//! Network admission MUST remain disabled until ADR-07 and ADR-19 are verified.

use loom_types::PeerId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    NotImplemented,
    InvalidSignature,
    InvalidIdentity,
}

pub trait SignatureVerifier: Send + Sync {
    fn verify(
        &self,
        claimed_signer: PeerId,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
}

/// Deliberately rejects all signatures until the audited implementation lands.
#[derive(Default)]
pub struct DenyAllVerifier;

impl SignatureVerifier for DenyAllVerifier {
    fn verify(
        &self,
        _claimed_signer: PeerId,
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_placeholder_accepts_signature() {
        let verifier = DenyAllVerifier;
        assert_eq!(
            verifier.verify(PeerId::from_digest([1; 32]), b"payload", b"signature"),
            Err(CryptoError::NotImplemented)
        );
    }
}

/// Experimental Ed25519 verification of candidate CBOR security events.
pub mod signed_revocation;

/// Candidate Owner-anchored revoke-only delegation proof (not production trust).
pub mod owner_authority;
