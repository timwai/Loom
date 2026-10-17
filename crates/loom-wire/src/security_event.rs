//! Candidate RFC 8949 core deterministic CBOR subset for signed security events.
//! This module validates canonical bytes; it does **not** authorize an event,
//! validate its typed payload, or verify Ed25519. Those are separate gates.
//!
//! Representation: definite map of exactly nine ascending integer keys (0..=8).
//! 0=major-version(1), 1=event-kind(1..=5), 2=space-id(bytes[16]),
//! 3=signer-key-id(bytes[32]), 4=issuer-epoch(u64),
//! 5=issued-at-ms(u64), 6=expires-at-ms(u64), 7=seq(u64), 8=payload(bytes).
//! All integers/lengths must use their shortest encoding. Unknown fields fail.

pub const MAX_SECURITY_EVENT_BYTES: usize = 64 * 1024;
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 60 * 1024;
const SIGNING_DOMAIN: &[u8] = b"LOOM:SECURITY-EVENT:V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventCodecError {
    Incomplete,
    TooLarge,
    NonCanonical,
    InvalidType,
    UnsupportedVersion,
    UnsupportedEventKind,
    InvalidLength,
    InvalidTimeRange,
    TrailingBytes,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    MembershipGrant = 1,
    OwnerGrant = 2,
    Revocation = 3,
    Checkpoint = 4,
    PeerKeyBinding = 5,
}

impl EventKind {
    fn from_u64(value: u64) -> Result<Self, EventCodecError> {
        match value {
            1 => Ok(Self::MembershipGrant),
            2 => Ok(Self::OwnerGrant),
            3 => Ok(Self::Revocation),
            4 => Ok(Self::Checkpoint),
            5 => Ok(Self::PeerKeyBinding),
            _ => Err(EventCodecError::UnsupportedEventKind),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalSecurityEvent {
    pub kind: EventKind,
    pub space_id: [u8; 16],
    pub signer_key_id: [u8; 32],
    pub issuer_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub seq: u64,
    /// Opaque *at this layer*. The typed authorization decoder MUST validate it.
    pub payload: Vec<u8>,
}

fn write_arg(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=255 => out.extend_from_slice(&[prefix | 24, value as u8]),
        256..=65535 => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
    write_arg(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

fn validate_semantics(event: &CanonicalSecurityEvent) -> Result<(), EventCodecError> {
    if event.issued_at_ms >= event.expires_at_ms {
        return Err(EventCodecError::InvalidTimeRange);
    }
    if event.payload.len() > MAX_EVENT_PAYLOAD_BYTES {
        return Err(EventCodecError::TooLarge);
    }
    Ok(())
}

pub fn encode_security_event(event: &CanonicalSecurityEvent) -> Result<Vec<u8>, EventCodecError> {
    validate_semantics(event)?;
    let mut out = Vec::with_capacity(128 + event.payload.len());
    write_arg(&mut out, 5, 9);
    write_arg(&mut out, 0, 0);
    write_arg(&mut out, 0, 1);
    write_arg(&mut out, 0, 1);
    write_arg(&mut out, 0, event.kind as u64);
    write_arg(&mut out, 0, 2);
    write_bytes(&mut out, &event.space_id);
    write_arg(&mut out, 0, 3);
    write_bytes(&mut out, &event.signer_key_id);
    write_arg(&mut out, 0, 4);
    write_arg(&mut out, 0, event.issuer_epoch);
    write_arg(&mut out, 0, 5);
    write_arg(&mut out, 0, event.issued_at_ms);
    write_arg(&mut out, 0, 6);
    write_arg(&mut out, 0, event.expires_at_ms);
    write_arg(&mut out, 0, 7);
    write_arg(&mut out, 0, event.seq);
    write_arg(&mut out, 0, 8);
    write_bytes(&mut out, &event.payload);
    if out.len() > MAX_SECURITY_EVENT_BYTES {
        return Err(EventCodecError::TooLarge);
    }
    Ok(out)
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], EventCodecError> {
        let end = self.offset.checked_add(size).ok_or(EventCodecError::TooLarge)?;
        let data = self.input.get(self.offset..end).ok_or(EventCodecError::Incomplete)?;
        self.offset = end;
        Ok(data)
    }

    fn head(&mut self, major: u8) -> Result<u64, EventCodecError> {
        let marker = self.take(1)?[0];
        if marker >> 5 != major {
            return Err(EventCodecError::InvalidType);
        }
        let additional = marker & 0x1f;
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.take(1)?[0]);
                if value < 24 {
                    return Err(EventCodecError::NonCanonical);
                }
                Ok(value)
            }
            25 => {
                let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| EventCodecError::Incomplete)?;
                let value = u64::from(u16::from_be_bytes(bytes));
                if value <= u8::MAX as u64 {
                    return Err(EventCodecError::NonCanonical);
                }
                Ok(value)
            }
            26 => {
                let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| EventCodecError::Incomplete)?;
                let value = u64::from(u32::from_be_bytes(bytes));
                if value <= u16::MAX as u64 {
                    return Err(EventCodecError::NonCanonical);
                }
                Ok(value)
            }
            27 => {
                let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| EventCodecError::Incomplete)?;
                let value = u64::from_be_bytes(bytes);
                if value <= u32::MAX as u64 {
                    return Err(EventCodecError::NonCanonical);
                }
                Ok(value)
            }
            // Includes reserved and indefinite-length forms.
            _ => Err(EventCodecError::NonCanonical),
        }
    }

    fn uint(&mut self) -> Result<u64, EventCodecError> {
        self.head(0)
    }

    fn bytes(&mut self, max: usize) -> Result<&'a [u8], EventCodecError> {
        let size = self.head(2)?;
        if size > max as u64 {
            return Err(EventCodecError::TooLarge);
        }
        self.take(size as usize)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], EventCodecError> {
        self.bytes(N)?.try_into().map_err(|_| EventCodecError::InvalidLength)
    }
}

pub fn decode_security_event(bytes: &[u8]) -> Result<CanonicalSecurityEvent, EventCodecError> {
    if bytes.len() > MAX_SECURITY_EVENT_BYTES {
        return Err(EventCodecError::TooLarge);
    }
    let mut cur = Cursor { input: bytes, offset: 0 };
    if cur.head(5)? != 9 {
        return Err(EventCodecError::InvalidLength);
    }
    for key in 0..=0 {
        if cur.uint()? != key {
            return Err(EventCodecError::NonCanonical);
        }
    }
    if cur.uint()? != 1 {
        return Err(EventCodecError::UnsupportedVersion);
    }
    if cur.uint()? != 1 {
        return Err(EventCodecError::NonCanonical);
    }
    let kind = EventKind::from_u64(cur.uint()?)?;
    if cur.uint()? != 2 {
        return Err(EventCodecError::NonCanonical);
    }
    let space_id = cur.fixed::<16>()?;
    if cur.uint()? != 3 {
        return Err(EventCodecError::NonCanonical);
    }
    let signer_key_id = cur.fixed::<32>()?;
    if cur.uint()? != 4 {
        return Err(EventCodecError::NonCanonical);
    }
    let issuer_epoch = cur.uint()?;
    if cur.uint()? != 5 {
        return Err(EventCodecError::NonCanonical);
    }
    let issued_at_ms = cur.uint()?;
    if cur.uint()? != 6 {
        return Err(EventCodecError::NonCanonical);
    }
    let expires_at_ms = cur.uint()?;
    if cur.uint()? != 7 {
        return Err(EventCodecError::NonCanonical);
    }
    let seq = cur.uint()?;
    if cur.uint()? != 8 {
        return Err(EventCodecError::NonCanonical);
    }
    let payload = cur.bytes(MAX_EVENT_PAYLOAD_BYTES)?.to_vec();
    if cur.offset != bytes.len() {
        return Err(EventCodecError::TrailingBytes);
    }
    let event = CanonicalSecurityEvent {
        kind, space_id, signer_key_id, issuer_epoch, issued_at_ms, expires_at_ms, seq, payload,
    };
    validate_semantics(&event)?;
    // Re-encoding comparison means the accepted form has exactly one representation.
    if encode_security_event(&event)?.as_slice() != bytes {
        return Err(EventCodecError::NonCanonical);
    }
    Ok(event)
}

/// Domain-separated transcript for Ed25519 sign/verify, NOT a signed event.
pub fn signing_input(canonical: &[u8]) -> Result<Vec<u8>, EventCodecError> {
    decode_security_event(canonical)?;
    let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + 4 + canonical.len());
    bytes.extend_from_slice(SIGNING_DOMAIN);
    bytes.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    bytes.extend_from_slice(canonical);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> CanonicalSecurityEvent {
        let mut signer = [0_u8; 32];
        for (i, value) in signer.iter_mut().enumerate() {
            *value = (i as u8) + 16;
        }
        let mut space = [0_u8; 16];
        for (i, value) in space.iter_mut().enumerate() {
            *value = i as u8;
        }
        CanonicalSecurityEvent {
            kind: EventKind::Revocation,
            space_id: space,
            signer_key_id: signer,
            issuer_epoch: 2,
            issued_at_ms: 1_710_000_000_123,
            expires_at_ms: 1_710_000_030_123,
            seq: 8,
            payload: vec![0xa1, 0x01, 0xf5],
        }
    }

    fn unhex(input: &str) -> Vec<u8> {
        let bytes = input.trim().as_bytes();
        assert_eq!(bytes.len() % 2, 0);
        bytes.chunks_exact(2).map(|pair| {
            let s = core::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(s, 16).expect("valid hex")
        }).collect()
    }

    #[test]
    fn independent_golden_vector() {
        let event = fixture();
        let expected = unhex(include_str!("../../../test-vectors/wire-v1/event-01.cbor.hex"));
        let expected_transcript = unhex(include_str!("../../../test-vectors/wire-v1/event-01.signing.hex"));
        let encoded = encode_security_event(&event).expect("encode");
        assert_eq!(encoded, expected);
        assert_eq!(decode_security_event(&encoded).expect("decode"), event);
        assert_eq!(signing_input(&encoded).expect("signing input"), expected_transcript);
    }

    #[test]
    fn truncation_and_random_mutations_never_panic() {
        let good = encode_security_event(&fixture()).expect("encode");
        for end in 0..good.len() {
            assert!(decode_security_event(&good[..end]).is_err());
        }
        for index in 0..good.len() {
            for bit in [1, 0x80] {
                let mut changed = good.clone();
                changed[index] ^= bit;
                let _ = decode_security_event(&changed);
            }
        }
    }

    #[test]
    fn unknown_duplicate_unsorted_and_overlong_fields_rejected() {
        let good = encode_security_event(&fixture()).expect("encode");
        let mut duplicate_key = good.clone();
        duplicate_key[3] = 0;
        assert_eq!(decode_security_event(&duplicate_key), Err(EventCodecError::NonCanonical));
        let mut wrong_order = good.clone();
        wrong_order[3] = 2;
        assert!(decode_security_event(&wrong_order).is_err());
        let mut nonminimal_version = good.clone();
        nonminimal_version.splice(2..3, [0x18, 0x01]);
        assert_eq!(decode_security_event(&nonminimal_version), Err(EventCodecError::NonCanonical));
        let mut unknown_field = good.clone();
        unknown_field[0] = 0xaa;
        assert_eq!(decode_security_event(&unknown_field), Err(EventCodecError::InvalidLength));
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(decode_security_event(&extra), Err(EventCodecError::TrailingBytes));
        let mut wrong_version = good.clone();
        wrong_version[2] = 2;
        assert_eq!(decode_security_event(&wrong_version), Err(EventCodecError::UnsupportedVersion));
        let mut indefinite = good.clone();
        indefinite[0] = 0xbf;
        assert_eq!(decode_security_event(&indefinite), Err(EventCodecError::NonCanonical));
        let mut tag = good.clone();
        tag[0] = 0xc9;
        assert_eq!(decode_security_event(&tag), Err(EventCodecError::InvalidType));
    }

    #[test]
    fn time_and_payload_limits_enforced() {
        let mut event = fixture();
        event.expires_at_ms = event.issued_at_ms;
        assert_eq!(encode_security_event(&event), Err(EventCodecError::InvalidTimeRange));
        event.expires_at_ms += 1;
        event.payload = vec![0; MAX_EVENT_PAYLOAD_BYTES + 1];
        assert_eq!(encode_security_event(&event), Err(EventCodecError::TooLarge));
        assert_eq!(
            decode_security_event(&vec![0; MAX_SECURITY_EVENT_BYTES + 1]),
            Err(EventCodecError::TooLarge)
        );
    }
}
