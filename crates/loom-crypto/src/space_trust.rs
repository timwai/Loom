//! Candidate authenticated SpaceRoot -> ResourceOwner + two-witness binding.
//! A root key MUST be pinned independently of the rollbackable SQLite data.
//! This is a verification PoC, NEVER a permission to open a network resource.

use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::{ResourceId, SpaceId};
use sha2::{Digest, Sha256};

use crate::owner_authority::ProvisionedOwnerForSpike;
use crate::witness_checkpoint::{
    SignedCheckpoint, TrustedWitnessForSpike, VerifiedWitnessCheckpoint, WitnessError,
    verify_two_witnesses,
};

const TRUST_DOMAIN: &[u8] = b"LOOM:RESOURCE-TRUST:V1\0";

/// This pin represents a *previously authenticated*, external Space trust root.
/// No network message or SQLite row may create a trusted pin.
#[derive(Clone, Copy, Debug)]
pub struct ExternallyPinnedRootForSpike {
    pub space: SpaceId,
    pub public_key: [u8; 32],
    pub key_epoch: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ResourceTrustManifest {
    pub space: SpaceId,
    pub resource: ResourceId,
    pub owner_public_key: [u8; 32],
    pub owner_key_epoch: u64,
    pub witness_public_keys: [[u8; 32]; 2],
    pub writer_epoch: u64,
    pub root_key_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

pub struct SignedResourceTrust {
    pub manifest: ResourceTrustManifest,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootTrustError {
    InvalidRootSignature,
    WrongRootOrSpace,
    WrongEpoch,
    InvalidManifest,
    InvalidTime,
    DuplicateWitness,
    WitnessVerification(WitnessError),
}

/// Constructed only by successful signature and scope checks; grants NO
/// access and does not attest that the root pin is non-rollbackable.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedResourceTrust {
    manifest: ResourceTrustManifest,
    authenticated_root_public_key: [u8; 32],
}

impl VerifiedResourceTrust {
    pub fn owner(&self) -> ProvisionedOwnerForSpike {
        ProvisionedOwnerForSpike {
            space_id: self.manifest.space,
            resource_id: self.manifest.resource,
            public_key: self.manifest.owner_public_key,
            current_key_epoch: self.manifest.owner_key_epoch,
        }
    }

    pub fn witnesses(&self) -> [TrustedWitnessForSpike; 2] {
        self.manifest
            .witness_public_keys
            .map(TrustedWitnessForSpike::from_public_key)
    }

    pub fn space(&self) -> SpaceId {
        self.manifest.space
    }

    pub fn resource(&self) -> ResourceId {
        self.manifest.resource
    }

    pub fn writer_epoch(&self) -> u64 {
        self.manifest.writer_epoch
    }

    pub fn root_key_epoch(&self) -> u64 {
        self.manifest.root_key_epoch
    }

    pub fn root_public_key(&self) -> [u8; 32] {
        self.authenticated_root_public_key
    }

    /// A stable digest of the exact authorized Owner/witness/epoch manifest.
    /// A Root epoch alone is insufficient to detect policy replacement.
    pub fn manifest_commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"LOOM:ROOT-MANIFEST-COMMITMENT:V1\0");
        hash.update(trust_manifest_transcript(&self.manifest));
        hash.finalize().into()
    }

    pub fn valid_at(&self, now_ms: u64) -> bool {
        self.manifest.issued_at_ms <= now_ms && now_ms < self.manifest.expires_at_ms
    }

    pub fn validity_interval(&self) -> (u64, u64) {
        (self.manifest.issued_at_ms, self.manifest.expires_at_ms)
    }
}

/// Domain-separated fixed-width transcript, without ambiguous protobuf map
/// encoding or unsigned fields; version is part of the domain.
pub fn trust_manifest_transcript(manifest: &ResourceTrustManifest) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRUST_DOMAIN.len() + 168);
    out.extend_from_slice(TRUST_DOMAIN);
    out.extend_from_slice(manifest.space.as_bytes());
    out.extend_from_slice(manifest.resource.as_bytes());
    out.extend_from_slice(&manifest.owner_public_key);
    out.extend_from_slice(&manifest.owner_key_epoch.to_be_bytes());
    out.extend_from_slice(&manifest.witness_public_keys[0]);
    out.extend_from_slice(&manifest.witness_public_keys[1]);
    out.extend_from_slice(&manifest.writer_epoch.to_be_bytes());
    out.extend_from_slice(&manifest.root_key_epoch.to_be_bytes());
    out.extend_from_slice(&manifest.issued_at_ms.to_be_bytes());
    out.extend_from_slice(&manifest.expires_at_ms.to_be_bytes());
    out
}

/// Verifies the *external* pinned Root's Ed25519 signature before constructing
/// the owner/witness configuration. An attacker-supplied root pin is NOT trusted.
pub fn verify_resource_trust_for_spike(
    root: &ExternallyPinnedRootForSpike,
    signed: &SignedResourceTrust,
    now_ms: u64,
) -> Result<VerifiedResourceTrust, RootTrustError> {
    let m = signed.manifest;
    if m.space != root.space {
        return Err(RootTrustError::WrongRootOrSpace);
    }
    if root.key_epoch == 0
        || m.root_key_epoch != root.key_epoch
        || m.owner_key_epoch == 0
        || m.writer_epoch == 0
    {
        return Err(RootTrustError::WrongEpoch);
    }
    if m.issued_at_ms > now_ms || now_ms >= m.expires_at_ms || m.issued_at_ms >= m.expires_at_ms {
        return Err(RootTrustError::InvalidTime);
    }
    if m.witness_public_keys[0] == m.witness_public_keys[1] {
        return Err(RootTrustError::DuplicateWitness);
    }
    if m.owner_public_key == [0; 32] || m.witness_public_keys.contains(&[0; 32]) {
        return Err(RootTrustError::InvalidManifest);
    }
    let verifier = VerifyingKey::from_bytes(&root.public_key)
        .map_err(|_| RootTrustError::InvalidRootSignature)?;
    verifier
        .verify_strict(
            &trust_manifest_transcript(&m),
            &Signature::from_bytes(&signed.signature),
        )
        .map_err(|_| RootTrustError::InvalidRootSignature)?;
    // Check witness public-key encoding even before seeing their receipts.
    for key in m.witness_public_keys {
        VerifyingKey::from_bytes(&key).map_err(|_| RootTrustError::InvalidManifest)?;
    }
    VerifyingKey::from_bytes(&m.owner_public_key).map_err(|_| RootTrustError::InvalidManifest)?;
    Ok(VerifiedResourceTrust {
        manifest: m,
        authenticated_root_public_key: root.public_key,
    })
}

/// Roots and witnesses have distinct domains. Checkpoint writer epoch must
/// match the policy pinned by the Root manifest; no stale writer is accepted.
pub fn verify_root_bound_witnesses(
    trust: &VerifiedResourceTrust,
    receipts: &[SignedCheckpoint],
    now_ms: u64,
) -> Result<VerifiedWitnessCheckpoint, RootTrustError> {
    let checked = verify_two_witnesses(
        &trust.witnesses(),
        receipts,
        trust.space(),
        trust.resource(),
        now_ms,
    )
    .map_err(RootTrustError::WitnessVerification)?;
    if checked.checkpoint().writer_epoch != trust.writer_epoch() {
        return Err(RootTrustError::WrongEpoch);
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness_checkpoint::{Checkpoint, SignedCheckpoint, checkpoint_transcript};
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (
        ExternallyPinnedRootForSpike,
        SignedResourceTrust,
        [SigningKey; 2],
    ) {
        let root_key = SigningKey::from_bytes(&[30; 32]);
        let owner_key = SigningKey::from_bytes(&[11; 32]);
        let a = SigningKey::from_bytes(&[21; 32]);
        let b = SigningKey::from_bytes(&[22; 32]);
        let pin = ExternallyPinnedRootForSpike {
            space: SpaceId::from_bytes([1; 16]),
            public_key: root_key.verifying_key().to_bytes(),
            key_epoch: 7,
        };
        let manifest = ResourceTrustManifest {
            space: pin.space,
            resource: ResourceId::from_bytes([2; 16]),
            owner_public_key: owner_key.verifying_key().to_bytes(),
            owner_key_epoch: 3,
            witness_public_keys: [a.verifying_key().to_bytes(), b.verifying_key().to_bytes()],
            writer_epoch: 1,
            root_key_epoch: pin.key_epoch,
            issued_at_ms: 100,
            expires_at_ms: 300,
        };
        let signed = SignedResourceTrust {
            manifest,
            signature: root_key
                .sign(&trust_manifest_transcript(&manifest))
                .to_bytes(),
        };
        (pin, signed, [a, b])
    }

    fn receipts(
        manifest: &ResourceTrustManifest,
        keys: &[SigningKey; 2],
        seq: u64,
        head: [u8; 32],
    ) -> [SignedCheckpoint; 2] {
        let cp = Checkpoint {
            space: manifest.space,
            resource: manifest.resource,
            writer_epoch: manifest.writer_epoch,
            seq,
            head_hash: head,
            revocation_root: head,
            issued_at_ms: 120,
            expires_at_ms: 250,
        };
        let bytes = checkpoint_transcript(&cp);
        [0, 1].map(|index| SignedCheckpoint {
            witness_key_id: TrustedWitnessForSpike::from_public_key(
                keys[index].verifying_key().to_bytes(),
            )
            .key_id,
            checkpoint: cp,
            signature: keys[index].sign(&bytes).to_bytes(),
        })
    }

    #[test]
    fn signed_root_binds_owner_and_two_distinct_witnesses() {
        let (root, signed, keys) = fixture();
        let trust = verify_resource_trust_for_spike(&root, &signed, 150).unwrap();
        assert_eq!(trust.owner().resource_id, signed.manifest.resource);
        assert_eq!(trust.owner().public_key, signed.manifest.owner_public_key);
        assert_eq!(
            verify_root_bound_witnesses(
                &trust,
                &receipts(&signed.manifest, &keys, 1, [8; 32]),
                150,
            )
            .unwrap()
            .checkpoint()
            .seq,
            1
        );
    }

    #[test]
    fn root_key_substitution_and_manipulated_owner_rejected() {
        let (root, mut signed, _) = fixture();
        signed.manifest.owner_public_key = [8; 32];
        assert_eq!(
            verify_resource_trust_for_spike(&root, &signed, 150).unwrap_err(),
            RootTrustError::InvalidRootSignature
        );
        let (mut root, signed, _) = fixture();
        root.public_key = SigningKey::from_bytes(&[44; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_resource_trust_for_spike(&root, &signed, 150).unwrap_err(),
            RootTrustError::InvalidRootSignature
        );
    }

    #[test]
    fn root_epoch_cross_space_and_expiry_rejected() {
        let (mut root, signed, _) = fixture();
        root.space = SpaceId::from_bytes([8; 16]);
        assert_eq!(
            verify_resource_trust_for_spike(&root, &signed, 150).unwrap_err(),
            RootTrustError::WrongRootOrSpace
        );
        let (mut root, signed, _) = fixture();
        root.key_epoch = 8;
        assert_eq!(
            verify_resource_trust_for_spike(&root, &signed, 150).unwrap_err(),
            RootTrustError::WrongEpoch
        );
        let (root, signed, _) = fixture();
        assert_eq!(
            verify_resource_trust_for_spike(&root, &signed, 301).unwrap_err(),
            RootTrustError::InvalidTime
        );
    }

    #[test]
    fn cannot_replace_or_duplicate_authorized_witness() {
        let (root, mut signed, _) = fixture();
        signed.manifest.witness_public_keys[1] = signed.manifest.witness_public_keys[0];
        assert_eq!(
            verify_resource_trust_for_spike(&root, &signed, 150).unwrap_err(),
            RootTrustError::DuplicateWitness
        );
        let (root, signed, mut keys) = fixture();
        let trust = verify_resource_trust_for_spike(&root, &signed, 150).unwrap();
        keys[1] = SigningKey::from_bytes(&[33; 32]);
        assert!(
            verify_root_bound_witnesses(
                &trust,
                &receipts(&signed.manifest, &keys, 1, [8; 32]),
                150,
            )
            .is_err()
        );
    }

    #[test]
    fn writer_epoch_and_checkpoint_signature_are_bound_to_root_policy() {
        let (root, signed, keys) = fixture();
        let trust = verify_resource_trust_for_spike(&root, &signed, 150).unwrap();
        let mut other = signed.manifest;
        other.writer_epoch = 2;
        let mut receipts = receipts(&other, &keys, 1, [8; 32]);
        assert_eq!(
            verify_root_bound_witnesses(&trust, &receipts, 150).unwrap_err(),
            RootTrustError::WrongEpoch
        );
        receipts[0].signature[3] ^= 1;
        assert!(verify_root_bound_witnesses(&trust, &receipts, 150).is_err());
    }
}
