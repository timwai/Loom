//! Signed security-event verification SPIKE, not a network admission decision.
//! Pinned issuer input MUST eventually be resolved via validated Owner grants,
//! identity chain, revocation and independent anti-rollback witnesses.

use ed25519_dalek::{Signature, VerifyingKey};
use loom_types::{PeerId, ResourceId, SpaceId};
use loom_wire::security_event::{
    CanonicalSecurityEvent, EventKind, decode_security_event, signing_input,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyEventError {
    NonCanonical,
    InvalidSignature,
    InvalidPinnedIssuer,
    InvalidSpace,
    InvalidEpoch,
    Expired,
    WrongEventKind,
    InvalidRevokePayload,
    InvalidSequence,
}

/// Only a caller-provided pin during this spike. NOT a verified Owner trust chain.
/// The signed-event verifier does not grant services or authenticate membership.
#[derive(Clone, Copy, Debug)]
pub struct PinnedIssuerForSpike {
    pub key_id: [u8; 32],
    pub public_key: [u8; 32],
    pub space_id: SpaceId,
    pub minimum_key_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct VerifiedRevocation {
    canonical: Vec<u8>,
    signature: [u8; 64],
    space_id: SpaceId,
    resource_id: ResourceId,
    revoked_peer: PeerId,
    action_mask: u8,
    seq: u64,
}

impl VerifiedRevocation {
    pub fn space_id(&self) -> SpaceId {
        self.space_id
    }

    pub fn resource_id(&self) -> ResourceId {
        self.resource_id
    }

    pub fn revoked_peer(&self) -> PeerId {
        self.revoked_peer
    }

    pub fn action_mask(&self) -> u8 {
        self.action_mask
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Durable envelope: 4-byte CBOR length, canonical CBOR, 64-byte signature.
    /// This format remains a candidate, and MUST be versioned before release.
    pub fn persistence_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + self.canonical.len() + 64);
        result.extend_from_slice(&(self.canonical.len() as u32).to_be_bytes());
        result.extend_from_slice(&self.canonical);
        result.extend_from_slice(&self.signature);
        result
    }
}

fn verify_bytes(
    event_bytes: &[u8],
    signature_bytes: &[u8],
    pin: &PinnedIssuerForSpike,
) -> Result<CanonicalSecurityEvent, VerifyEventError> {
    let event = decode_security_event(event_bytes).map_err(|_| VerifyEventError::NonCanonical)?;
    if event.signer_key_id != pin.key_id {
        return Err(VerifyEventError::InvalidPinnedIssuer);
    }
    if event.space_id != *pin.space_id.as_bytes() {
        return Err(VerifyEventError::InvalidSpace);
    }
    if event.issuer_epoch < pin.minimum_key_epoch {
        return Err(VerifyEventError::InvalidEpoch);
    }
    let verifier = VerifyingKey::from_bytes(&pin.public_key)
        .map_err(|_| VerifyEventError::InvalidPinnedIssuer)?;
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| VerifyEventError::InvalidSignature)?;
    let message = signing_input(event_bytes).map_err(|_| VerifyEventError::NonCanonical)?;
    verifier
        .verify_strict(&message, &signature)
        .map_err(|_| VerifyEventError::InvalidSignature)?;
    Ok(event)
}

/// Verifies canonical encoding, Ed25519 signature and the exact pinned signer.
/// It deliberately does not produce any ResourceGrant or ServiceOpen permit.
pub fn verify_signed_event_for_spike(
    event_bytes: &[u8],
    signature_bytes: &[u8],
    pin: &PinnedIssuerForSpike,
) -> Result<CanonicalSecurityEvent, VerifyEventError> {
    verify_bytes(event_bytes, signature_bytes, pin)
}

/// Revocation payload V1 candidate: resource-id[16] || peer-id[32] || actions[1].
/// Signed revocation seq must be >0. Issuer *authority* to revoke this resource
/// remains a separate unimplemented Owner ACL/chain validation gate.
pub fn verify_revocation_for_spike(
    event_bytes: &[u8],
    signature_bytes: &[u8],
    pin: &PinnedIssuerForSpike,
    now_ms: u64,
) -> Result<VerifiedRevocation, VerifyEventError> {
    let event = verify_bytes(event_bytes, signature_bytes, pin)?;
    if event.kind != EventKind::Revocation {
        return Err(VerifyEventError::WrongEventKind);
    }
    if event.seq == 0 {
        return Err(VerifyEventError::InvalidSequence);
    }
    if !(event.issued_at_ms <= now_ms && now_ms < event.expires_at_ms) {
        return Err(VerifyEventError::Expired);
    }
    if event.payload.len() != 49 {
        return Err(VerifyEventError::InvalidRevokePayload);
    }
    let resource: [u8; 16] = event.payload[..16]
        .try_into()
        .map_err(|_| VerifyEventError::InvalidRevokePayload)?;
    let revoked: [u8; 32] = event.payload[16..48]
        .try_into()
        .map_err(|_| VerifyEventError::InvalidRevokePayload)?;
    let action_mask = event.payload[48];
    if revoked == [0; 32] || action_mask == 0 || action_mask & !0x0f != 0 {
        return Err(VerifyEventError::InvalidRevokePayload);
    }
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| VerifyEventError::InvalidSignature)?;
    Ok(VerifiedRevocation {
        canonical: event_bytes.to_vec(),
        signature,
        space_id: pin.space_id,
        resource_id: ResourceId::from_bytes(resource),
        revoked_peer: PeerId::from_digest(revoked),
        action_mask,
        seq: event.seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loom_wire::security_event::{EventKind, encode_security_event};

    fn hex(content: &str) -> Vec<u8> {
        content
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn fixture_pin() -> PinnedIssuerForSpike {
        let mut key_id = [0u8; 32];
        for (n, value) in key_id.iter_mut().enumerate() {
            *value = 16 + n as u8;
        }
        let public_key: [u8; 32] = hex(include_str!(
            "../../../test-vectors/wire-v1/event-01.pubkey.hex"
        ))
        .try_into()
        .unwrap();
        let mut space = [0u8; 16];
        for (i, value) in space.iter_mut().enumerate() {
            *value = i as u8;
        }
        PinnedIssuerForSpike {
            key_id,
            public_key,
            space_id: SpaceId::from_bytes(space),
            minimum_key_epoch: 2,
        }
    }

    #[test]
    fn verifies_independent_go_js_ed25519_vector() {
        let pin = fixture_pin();
        let event = hex(include_str!(
            "../../../test-vectors/wire-v1/event-01.cbor.hex"
        ));
        let sig = hex(include_str!(
            "../../../test-vectors/wire-v1/event-01.signature.hex"
        ));
        let verified = verify_signed_event_for_spike(&event, &sig, &pin).unwrap();
        assert_eq!(verified.kind, EventKind::Revocation);
        assert_eq!(verified.seq, 8);
        let mut forged = event.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(verify_signed_event_for_spike(&forged, &sig, &pin).is_err());
        let mut wrong_sig = sig.clone();
        wrong_sig[20] ^= 1;
        assert_eq!(
            verify_signed_event_for_spike(&event, &wrong_sig, &pin),
            Err(VerifyEventError::InvalidSignature)
        );
        let mut wrong_pin = pin;
        wrong_pin.key_id[0] ^= 1;
        assert_eq!(
            verify_signed_event_for_spike(&event, &sig, &wrong_pin),
            Err(VerifyEventError::InvalidPinnedIssuer)
        );
    }

    fn signed_revoke() -> (Vec<u8>, [u8; 64], PinnedIssuerForSpike) {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let space = SpaceId::from_bytes([1; 16]);
        let pin = PinnedIssuerForSpike {
            key_id: [9u8; 32],
            public_key: signing_key.verifying_key().to_bytes(),
            space_id: space,
            minimum_key_epoch: 3,
        };
        let mut payload = vec![2u8; 16];
        payload.extend_from_slice(&[4u8; 32]);
        payload.push(0x03);
        let event = CanonicalSecurityEvent {
            kind: EventKind::Revocation,
            space_id: *space.as_bytes(),
            signer_key_id: pin.key_id,
            issuer_epoch: 3,
            issued_at_ms: 100,
            expires_at_ms: 200,
            seq: 1,
            payload,
        };
        let bytes = encode_security_event(&event).unwrap();
        let message = signing_input(&bytes).unwrap();
        let sig = signing_key.sign(&message).to_bytes();
        (bytes, sig, pin)
    }

    #[test]
    fn typed_revocation_requires_scope_signature_epoch_and_time() {
        let (bytes, sig, pin) = signed_revoke();
        let verified = verify_revocation_for_spike(&bytes, &sig, &pin, 150).unwrap();
        assert_eq!(verified.resource_id(), ResourceId::from_bytes([2; 16]));
        assert_eq!(verified.revoked_peer(), PeerId::from_digest([4; 32]));
        assert_eq!(verified.action_mask(), 3);
        assert_eq!(verified.seq(), 1);
        assert_eq!(verified.persistence_bytes().len(), bytes.len() + 68);
        assert_eq!(
            verify_revocation_for_spike(&bytes, &sig, &pin, 205).unwrap_err(),
            VerifyEventError::Expired
        );
        let mut wrong_space = pin;
        wrong_space.space_id = SpaceId::from_bytes([11; 16]);
        assert_eq!(
            verify_revocation_for_spike(&bytes, &sig, &wrong_space, 150).unwrap_err(),
            VerifyEventError::InvalidSpace
        );
        let mut wrong_epoch = pin;
        wrong_epoch.minimum_key_epoch = 4;
        assert_eq!(
            verify_revocation_for_spike(&bytes, &sig, &wrong_epoch, 150).unwrap_err(),
            VerifyEventError::InvalidEpoch
        );
        let mut changed = bytes;
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify_revocation_for_spike(&changed, &sig, &pin, 150).is_err());
    }

    #[test]
    fn malformed_revocation_payload_is_not_authorized_by_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let (bytes, _sig, pin) = signed_revoke();
        let mut event = decode_security_event(&bytes).unwrap();
        event.payload.truncate(3);
        let bytes = encode_security_event(&event).unwrap();
        let sig = signing_key.sign(&signing_input(&bytes).unwrap()).to_bytes();
        assert_eq!(
            verify_revocation_for_spike(&bytes, &sig, &pin, 150).unwrap_err(),
            VerifyEventError::InvalidRevokePayload
        );
    }
}
