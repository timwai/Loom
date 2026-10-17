//! Bounded, canonical base-128 framing. This is NOT a signed event codec.
//! Signed event encoding (ADR-07) remains a separately gated PoC.

pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_PREFIX_BYTES: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    Incomplete,
    TooLarge,
    InvalidLength,
    NonCanonical,
}

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut value = payload.len();
    let mut result = Vec::with_capacity(5 + payload.len());
    while value >= 0x80 {
        result.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    result.push(value as u8);
    result.extend_from_slice(payload);
    Ok(result)
}

/// Returns the first complete payload and unconsumed bytes.
pub fn decode_frame(input: &[u8]) -> Result<(&[u8], &[u8]), FrameError> {
    let mut length: u64 = 0;
    let mut prefix_end = None;
    for (index, &byte) in input.iter().take(MAX_PREFIX_BYTES).enumerate() {
        length |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(FrameError::NonCanonical);
            }
            prefix_end = Some(index + 1);
            break;
        }
    }
    let prefix_len = match prefix_end {
        Some(v) => v,
        None if input.len() < MAX_PREFIX_BYTES => return Err(FrameError::Incomplete),
        None => return Err(FrameError::InvalidLength),
    };
    if length > MAX_FRAME_BYTES as u64 {
        return Err(FrameError::TooLarge);
    }
    let end = prefix_len + length as usize;
    if input.len() < end {
        return Err(FrameError::Incomplete);
    }
    Ok((&input[prefix_len..end], &input[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_roundtrip_and_remaining_bytes() {
        let encoded = encode_frame(b"hello").expect("short frame");
        let mut concatenated = encoded.clone();
        concatenated.extend_from_slice(&encoded);
        let (payload, rest) = decode_frame(&concatenated).expect("frame");
        assert_eq!(payload, b"hello");
        assert_eq!(rest, encoded);
    }

    #[test]
    fn rejects_overlong_and_oversized_prefix() {
        assert_eq!(decode_frame(&[0x80, 0x00]), Err(FrameError::NonCanonical));
        assert_eq!(decode_frame(&[0xff; 5]), Err(FrameError::InvalidLength));
        assert_eq!(decode_frame(&[0x80]), Err(FrameError::Incomplete));
        assert_eq!(decode_frame(&[0x80, 0x80, 0x40]), Err(FrameError::TooLarge));
        assert_eq!(
            encode_frame(&vec![0u8; MAX_FRAME_BYTES + 1]),
            Err(FrameError::TooLarge)
        );
    }

    #[test]
    fn maximum_frame_is_accepted() {
        let encoded = encode_frame(&vec![1u8; MAX_FRAME_BYTES]).expect("in bounds");
        let (data, leftover) = decode_frame(&encoded).expect("in bounds");
        assert_eq!(data.len(), MAX_FRAME_BYTES);
        assert!(leftover.is_empty());
    }
}

/// Candidate canonical security-event wire codec (protocol not frozen).
pub mod security_event;
