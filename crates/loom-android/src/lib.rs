//! Narrow Java/Rust verification boundary for the Android acceptance APK.
//! Bounded protected UDP diagnostics; no TUN ownership, trusted enrollment or
//! production ServiceOpen is exposed.
#[cfg(unix)]
use jni::objects::{JObject, JValue};
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass},
    sys::{jbyteArray, jint, jlong},
};
use loom_crypto::{
    membership::{
        MembershipRequirements, MembershipWriterDelegation, SignedMembershipWriter,
        verify_membership,
    },
    space_trust::ExternallyPinnedRootForSpike,
};
use loom_types::SpaceId;

const MAX_ENVELOPE: usize = 66_000;
const HEADER: usize = 196;

/// The callback borrows the FD; it must not close or adopt it. Rust retains the
/// socket and drops it on every success, refusal and I/O error. Only numeric
/// IPv4 is accepted: no DNS/connect/send occurs before protection succeeds.
#[cfg(unix)]
pub fn protected_udp_echo(
    address: std::net::SocketAddrV4,
    payload: &[u8],
    protect: impl FnOnce(i32) -> Result<bool, &'static str>,
) -> Result<Vec<u8>, &'static str> {
    use std::os::fd::AsRawFd;
    if payload.is_empty() || payload.len() > 256 || address.port() == 0 {
        return Err("invalid echo request");
    }
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|_| "UDP bind failed")?;
    if !protect(socket.as_raw_fd())? {
        return Err("protect refused before connect");
    }
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .map_err(|_| "timeout setup failed")?;
    socket.connect(address).map_err(|_| "UDP connect failed")?;
    socket.send(payload).map_err(|_| "UDP send failed")?;
    let mut reply = [0u8; 257];
    let length = socket
        .recv(&mut reply)
        .map_err(|_| "protected UDP receive failed")?;
    if reply[..length] != *payload {
        return Err("protected UDP echo mismatch");
    }
    Ok(reply[..length].to_vec())
}

fn throw_if_clear(env: &mut JNIEnv<'_>, class: &str, message: &str) {
    if matches!(env.exception_check(), Ok(false)) {
        let _ = env.throw_new(class, message);
    }
}

/// Lab-only envelope, not a network protocol or pin enrollment mechanism.
/// Root/expected sequence inputs are provided by the caller. Returning fields
/// proves signature checks only, never independent freshness or authorization.
pub fn verify_membership_envelope(input: &[u8], now_ms: u64) -> Result<[u8; 56], &'static str> {
    if input.len() < HEADER + 64 || input.len() > MAX_ENVELOPE {
        return Err("invalid envelope length");
    }
    fn bytes<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], &'static str> {
        input
            .get(offset..offset + N)
            .and_then(|x| x.try_into().ok())
            .ok_or("truncated envelope")
    }
    let root = ExternallyPinnedRootForSpike {
        public_key: bytes(input, 0)?,
        key_epoch: u64::from_be_bytes(bytes(input, 32)?),
        space: SpaceId::from_bytes(bytes(input, 40)?),
    };
    let delegation = MembershipWriterDelegation {
        space: root.space,
        root_epoch: root.key_epoch,
        writer_public_key: bytes(input, 56)?,
        writer_epoch: u64::from_be_bytes(bytes(input, 88)?),
        issued_at_ms: u64::from_be_bytes(bytes(input, 96)?),
        expires_at_ms: u64::from_be_bytes(bytes(input, 104)?),
    };
    let writer = SignedMembershipWriter {
        delegation,
        root_signature: bytes(input, 112)?,
    };
    let requirements = MembershipRequirements {
        writer_epoch: u64::from_be_bytes(bytes(input, 176)?),
        sequence: u64::from_be_bytes(bytes(input, 184)?),
    };
    let length = u32::from_be_bytes(bytes(input, 192)?) as usize;
    let end = HEADER.checked_add(length).ok_or("oversized event")?;
    if end.checked_add(64) != Some(input.len()) {
        return Err("invalid event length");
    }
    let verified = verify_membership(
        &root,
        &writer,
        requirements,
        &input[HEADER..end],
        &input[end..],
        now_ms,
    )
    .map_err(|_| "membership verification refused")?;
    let mut result = [0; 56];
    result[..32].copy_from_slice(verified.peer().digest());
    result[32..40].copy_from_slice(&verified.key_epoch().to_be_bytes());
    result[40..48].copy_from_slice(&verified.member_epoch().to_be_bytes());
    result[48..56].copy_from_slice(&verified.sequence().to_be_bytes());
    Ok(result)
}

/// Strict IPv4/UDP packet boundary. 1=validated UDP, 0=IPv6/control/unsupported;
/// malformed input returns an error. Never forwards a packet or grants a route.
pub fn classify_packet(packet: &[u8]) -> Result<i32, &'static str> {
    let version = packet.first().ok_or("empty packet")? >> 4;
    if version == 6 {
        return if packet.len() >= 40
            && 40 + u16::from_be_bytes([packet[4], packet[5]]) as usize == packet.len()
        {
            Ok(0)
        } else {
            Err("invalid IPv6 length")
        };
    }
    if version != 4 || packet.len() < 20 {
        return Err("invalid IP header");
    }
    let header = (packet[0] & 15) as usize * 4;
    if header < 20
        || header > packet.len()
        || u16::from_be_bytes([packet[2], packet[3]]) as usize != packet.len()
    {
        return Err("invalid IPv4 length");
    }
    let sum: u32 = packet[..header]
        .chunks_exact(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]) as u32)
        .sum();
    let folded = (sum & 0xffff) + (sum >> 16);
    if ((folded & 0xffff) + (folded >> 16)) != 0xffff {
        return Err("invalid IPv4 checksum");
    }
    if packet[9] != 17 {
        return Ok(0);
    }
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return Err("fragmented UDP refused");
    }
    if packet.len() < header + 8
        || u16::from_be_bytes([packet[header + 4], packet[header + 5]]) as usize
            != packet.len() - header
    {
        return Err("invalid UDP length");
    }
    Ok(1)
}

// SAFETY: these unique symbols exactly match NativeCore's static Java native
// declarations. JNI-owned arrays are bounded then copied through jni's safe API;
// no JNI reference crosses a thread/call and Rust panics cannot unwind into ART.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_fun_loom_lab_NativeCore_verifyMembership(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    input: JByteArray<'_>,
    now: jlong,
) -> jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<jbyteArray, &'static str> {
            if now < 0 {
                return Err("invalid clock");
            }
            let length = env.get_array_length(&input).map_err(|_| "null array")? as usize;
            if length > MAX_ENVELOPE {
                return Err("oversized envelope");
            }
            let input = env
                .convert_byte_array(&input)
                .map_err(|_| "array copy failed")?;
            let verified = verify_membership_envelope(&input, now as u64)?;
            Ok(env
                .byte_array_from_slice(&verified)
                .map_err(|_| "result allocation failed")?
                .into_raw())
        },
    ));
    match result {
        Ok(Ok(value)) => value,
        _ => {
            throw_if_clear(
                &mut env,
                "java/lang/IllegalArgumentException",
                "Loom membership verification refused",
            );
            std::ptr::null_mut()
        }
    }
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_fun_loom_lab_NativeCore_classifyPacket(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    input: JByteArray<'_>,
) -> jint {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<i32, &'static str> {
            let length = env.get_array_length(&input).map_err(|_| "null array")?;
            if !(1..=65535).contains(&length) {
                return Err("invalid packet length");
            }
            classify_packet(
                &env.convert_byte_array(&input)
                    .map_err(|_| "array copy failed")?,
            )
        },
    ));
    match result {
        Ok(Ok(value)) => value,
        _ => {
            throw_if_clear(
                &mut env,
                "java/lang/IllegalArgumentException",
                "Loom packet validation refused",
            );
            -1
        }
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_fun_loom_lab_NativeCore_protectedEcho(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    protector: JObject<'_>,
    address: JByteArray<'_>,
    port: jint,
    payload: JByteArray<'_>,
) -> jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<jbyteArray, &'static str> {
            if env
                .get_array_length(&address)
                .map_err(|_| "invalid address")?
                != 4
                || !(1..=65535).contains(&port)
            {
                return Err("invalid endpoint");
            }
            let length = env
                .get_array_length(&payload)
                .map_err(|_| "invalid payload")?;
            if !(1..=256).contains(&length) {
                return Err("invalid payload length");
            }
            let bytes = env
                .convert_byte_array(&address)
                .map_err(|_| "address copy failed")?;
            let address = std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                port as u16,
            );
            let payload = env
                .convert_byte_array(&payload)
                .map_err(|_| "payload copy failed")?;
            let reply = protected_udp_echo(address, &payload, |fd| {
                env.call_method(&protector, "protect", "(I)Z", &[JValue::Int(fd)])
                    .and_then(|value| value.z())
                    .map_err(|_| "protect callback failed")
            })?;
            Ok(env
                .byte_array_from_slice(&reply)
                .map_err(|_| "reply allocation failed")?
                .into_raw())
        },
    ));
    match result {
        Ok(Ok(value)) => value,
        _ => {
            throw_if_clear(
                &mut env,
                "java/lang/IllegalStateException",
                "Loom protected socket refused",
            );
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn protection_refusal_or_exception_never_sends_datagram() {
        use std::net::UdpSocket;
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        let std::net::SocketAddr::V4(address) = server.local_addr().unwrap() else {
            unreachable!()
        };
        assert_eq!(
            protected_udp_echo(address, b"canary", |_| Ok(false)),
            Err("protect refused before connect")
        );
        assert_eq!(
            protected_udp_echo(address, b"canary", |_| Err("injected callback failure")),
            Err("injected callback failure")
        );
        assert!(server.recv_from(&mut [0u8; 256]).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn protected_echo_and_oversized_or_wrong_response() {
        for response in [b"canary".as_slice(), b"incorrect".as_slice(), &[b'x'; 257]] {
            let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            server
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let std::net::SocketAddr::V4(address) = server.local_addr().unwrap() else {
                unreachable!()
            };
            let response = response.to_vec();
            let good = response == b"canary";
            let sender = std::thread::spawn(move || {
                let (_, peer) = server.recv_from(&mut [0u8; 256]).unwrap();
                server.send_to(&response, peer).unwrap();
            });
            let result = protected_udp_echo(address, b"canary", |_| Ok(true));
            assert_eq!(result.is_ok(), good);
            sender.join().unwrap();
        }
    }
    #[test]
    fn truncated_and_oversized_envelopes_never_panic() {
        for n in 0..400 {
            assert!(verify_membership_envelope(&vec![0; n], 1).is_err());
        }
        assert!(verify_membership_envelope(&vec![0; MAX_ENVELOPE + 1], 1).is_err());
    }
    #[test]
    fn malformed_packets_never_panic() {
        for first in 0..=255 {
            for size in 0..90 {
                let packet = vec![first; size];
                let _ = classify_packet(&packet);
            }
        }
        let mut ip6 = vec![0; 40];
        ip6[0] = 0x60;
        assert_eq!(classify_packet(&ip6), Ok(0));
        ip6[5] = 1;
        assert!(classify_packet(&ip6).is_err());
    }
    #[test]
    fn actual_tun_canary_and_header_tampering() {
        let hex = "450000377d444000401107120a4d0001ac110001cc8c4e1f00235ca64c4f4f4d2d554e50524f5445435445442d54554e2d43414e415259";
        let packet: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(classify_packet(&packet), Ok(1));
        let mut tampered = packet.clone();
        tampered[8] ^= 1;
        assert!(classify_packet(&tampered).is_err());
        let mut tampered = packet.clone();
        tampered[25] ^= 1;
        assert!(classify_packet(&tampered).is_err());
        for end in 0..packet.len() {
            assert!(classify_packet(&packet[..end]).is_err());
        }
    }
}
