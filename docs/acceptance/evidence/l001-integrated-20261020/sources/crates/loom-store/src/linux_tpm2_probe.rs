//! Linux TPM 2.0 read-only capability probe (L-001N).
//!
//! TPM presence, family=2.0 and NV index enumeration DO NOT prove a secure
//! monotonic CAS suitable for Loom's signed policy-chain high-water.
//! No NV index is defined, incremented, written, cleared, or provisioned.
//! The exposed IndependentUnifiedPolicyAnchor implementation is intentionally
//! DENY-ALL until independent device-backed atomicity is proven.

use crate::unified_policy_anchor::{
    IndependentUnifiedPolicyAnchor, UnifiedAnchorError, UnifiedPolicyHighWater,
};
use loom_types::{ResourceId, SpaceId};

#[cfg(any(target_os = "linux", test))]
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
#[cfg(any(target_os = "linux", test))]
const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;
#[cfg(any(target_os = "linux", test))]
const TPM_CAP_HANDLES: u32 = 1;
#[cfg(any(target_os = "linux", test))]
const TPM_CAP_PROPERTIES: u32 = 6;
#[cfg(any(target_os = "linux", test))]
const TPM_PT_FAMILY_INDICATOR: u32 = 0x0000_0100;
#[cfg(any(target_os = "linux", test))]
const TPM_PT_MANUFACTURER: u32 = 0x0000_0105;
#[cfg(any(target_os = "linux", test))]
const TPM_NV_FIRST: u32 = 0x0100_0000;
#[cfg(any(target_os = "linux", test))]
const TPM_NV_LAST: u32 = 0x01ff_ffff;
#[cfg(any(target_os = "linux", test))]
const TPM_FAMILY_20: u32 = 0x322e_3000; // "2.0\0"
#[cfg(any(target_os = "linux", test))]
const MAX_NV_PAGE: u32 = 32;
#[cfg(any(target_os = "linux", test))]
const MAX_REPLY: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmProbeError {
    UnsupportedPlatform,
    DeviceMissing,
    NotCharacterDevice,
    VersionNotTwo,
    PermissionOrIo,
    MalformedResponse,
    TpmRejected(u32),
    CapabilityMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxTpm2Candidate {
    pub device_index: u8,
    pub family: u32,
    pub manufacturer: u32,
    /// Only the first enumerated page. A further page may exist.
    pub nv_handles: Vec<u32>,
    pub nv_list_incomplete: bool,
    /// TPM_GetCapability neither attests to trustworthiness nor proves CAS.
    pub device_certified: bool,
    pub anchor_ready: bool,
}

impl IndependentUnifiedPolicyAnchor for LinuxTpm2Candidate {
    fn read(
        &self,
        _space: SpaceId,
        _resource: ResourceId,
    ) -> Result<UnifiedPolicyHighWater, UnifiedAnchorError> {
        Err(UnifiedAnchorError::MissingOrUntrusted)
    }

    fn compare_and_advance(
        &self,
        _expected: UnifiedPolicyHighWater,
        _next: UnifiedPolicyHighWater,
    ) -> Result<(), UnifiedAnchorError> {
        Err(UnifiedAnchorError::MissingOrUntrusted)
    }
}

/// The TPM chip command is a *read-only* TPM2_GetCapability. Its request and
/// response contain no passwords, data writes or authorization sessions.
#[cfg(any(target_os = "linux", test))]
fn request(capability: u32, property: u32, count: u32) -> [u8; 22] {
    let mut output = [0u8; 22];
    output[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    output[2..6].copy_from_slice(&22u32.to_be_bytes());
    output[6..10].copy_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
    output[10..14].copy_from_slice(&capability.to_be_bytes());
    output[14..18].copy_from_slice(&property.to_be_bytes());
    output[18..22].copy_from_slice(&count.to_be_bytes());
    output
}

/// Low-level raw read-only TPM command transport. A mock is used in CI;
/// the actual Linux provider uses a Linux TPM resource-manager char device.
#[cfg(any(target_os = "linux", test))]
trait TpmTransport {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmProbeError>;
}

#[cfg(any(target_os = "linux", test))]
struct CapabilityPage {
    more: bool,
    values: Vec<(u32, u32)>,
}

#[cfg(any(target_os = "linux", test))]
fn parse_response(
    bytes: &[u8],
    expected_cap: u32,
    max_count: u32,
) -> Result<CapabilityPage, TpmProbeError> {
    if bytes.len() < 10 || bytes.len() > MAX_REPLY {
        return Err(TpmProbeError::MalformedResponse);
    }
    let u16_at = |i: usize| u16::from_be_bytes([bytes[i], bytes[i + 1]]);
    let u32_at = |i: usize| u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
    if u16_at(0) != TPM_ST_NO_SESSIONS || u32_at(2) as usize != bytes.len() {
        return Err(TpmProbeError::MalformedResponse);
    }
    let code = u32_at(6);
    if code != 0 {
        return Err(TpmProbeError::TpmRejected(code));
    }
    // A TPM failure response contains just its 10-byte header. A successful
    // GetCapability must also contain the capability payload and count.
    if bytes.len() < 19 {
        return Err(TpmProbeError::MalformedResponse);
    }
    if bytes[10] > 1 {
        return Err(TpmProbeError::MalformedResponse);
    }
    let capability = u32_at(11);
    if capability != expected_cap {
        return Err(TpmProbeError::CapabilityMismatch);
    }
    let count = u32_at(15);
    if count > max_count {
        return Err(TpmProbeError::MalformedResponse);
    }
    let item_len = if capability == TPM_CAP_HANDLES {
        4usize
    } else if capability == TPM_CAP_PROPERTIES {
        8usize
    } else {
        return Err(TpmProbeError::CapabilityMismatch);
    };
    if 19usize.checked_add((count as usize).saturating_mul(item_len)) != Some(bytes.len()) {
        return Err(TpmProbeError::MalformedResponse);
    }
    let mut values = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let offset = 19 + index * item_len;
        if capability == TPM_CAP_HANDLES {
            values.push((u32_at(offset), 0));
        } else {
            values.push((u32_at(offset), u32_at(offset + 4)));
        }
    }
    Ok(CapabilityPage {
        more: bytes[10] == 1,
        values,
    })
}

#[cfg(any(target_os = "linux", test))]
fn property(io: &mut impl TpmTransport, property: u32) -> Result<u32, TpmProbeError> {
    let message = io.exchange(&request(TPM_CAP_PROPERTIES, property, 1))?;
    let page = parse_response(&message, TPM_CAP_PROPERTIES, 1)?;
    if page.more
        || page.values.as_slice().first().map(|&(key, _)| key) != Some(property)
        || page.values.len() != 1
    {
        return Err(TpmProbeError::CapabilityMismatch);
    }
    Ok(page.values[0].1)
}

#[cfg(any(target_os = "linux", test))]
fn probe_with_transport(
    version: u32,
    device_index: u8,
    io: &mut impl TpmTransport,
) -> Result<LinuxTpm2Candidate, TpmProbeError> {
    if version != 2 {
        return Err(TpmProbeError::VersionNotTwo);
    }
    let family = property(io, TPM_PT_FAMILY_INDICATOR)?;
    if family != TPM_FAMILY_20 {
        return Err(TpmProbeError::VersionNotTwo);
    }
    let manufacturer = property(io, TPM_PT_MANUFACTURER)?;
    let command = request(TPM_CAP_HANDLES, TPM_NV_FIRST, MAX_NV_PAGE);
    let page = parse_response(&io.exchange(&command)?, TPM_CAP_HANDLES, MAX_NV_PAGE)?;
    let mut previous = None;
    let mut handles = Vec::with_capacity(page.values.len());
    for (value, _) in page.values {
        if !(TPM_NV_FIRST..=TPM_NV_LAST).contains(&value)
            || previous.is_some_and(|prev| value <= prev)
        {
            return Err(TpmProbeError::MalformedResponse);
        }
        handles.push(value);
        previous = Some(value);
    }
    Ok(LinuxTpm2Candidate {
        device_index,
        family,
        manufacturer,
        nv_handles: handles,
        nv_list_incomplete: page.more,
        device_certified: false,
        anchor_ready: false,
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::FileTypeExt;
    use std::path::Path;

    struct Device(File);

    impl TpmTransport for Device {
        fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmProbeError> {
            let written = self
                .0
                .write(command)
                .map_err(|_| TpmProbeError::PermissionOrIo)?;
            if written != command.len() {
                return Err(TpmProbeError::PermissionOrIo);
            }
            // A single read is used: the Linux TPM character-device ABI
            // presents a response message, not a streaming protocol.
            let mut response = [0u8; MAX_REPLY];
            let count = self
                .0
                .read(&mut response)
                .map_err(|_| TpmProbeError::PermissionOrIo)?;
            if count < 10 {
                return Err(TpmProbeError::MalformedResponse);
            }
            Ok(response[..count].to_vec())
        }
    }

    pub(super) fn probe() -> Result<LinuxTpm2Candidate, TpmProbeError> {
        for index in 0u8..16 {
            let version_path = format!("/sys/class/tpm/tpm{index}/tpm_version_major");
            let version = match std::fs::read_to_string(&version_path) {
                Ok(value) => value,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(TpmProbeError::PermissionOrIo),
            };
            let version: u32 = version
                .trim()
                .parse()
                .map_err(|_| TpmProbeError::MalformedResponse)?;
            if version != 2 {
                continue;
            }
            let device = format!("/dev/tpmrm{index}");
            let path = Path::new(&device);
            let metadata = std::fs::metadata(path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    TpmProbeError::DeviceMissing
                } else {
                    TpmProbeError::PermissionOrIo
                }
            })?;
            if !metadata.file_type().is_char_device() {
                return Err(TpmProbeError::NotCharacterDevice);
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|_| TpmProbeError::PermissionOrIo)?;
            return probe_with_transport(version, index, &mut Device(file));
        }
        Err(TpmProbeError::DeviceMissing)
    }
}

/// Probe the host's Linux TPM resource-manager device **without writing NV**.
/// No fallback to an unsafe TPM 1.2 device or non-character test file.
/// Device permissions and an actual TPM2 response are required.
/// Calling this on non-Linux platforms rejects explicitly.
pub fn probe_linux_tpm2() -> Result<LinuxTpm2Candidate, TpmProbeError> {
    #[cfg(target_os = "linux")]
    {
        linux::probe()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(TpmProbeError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        frames: Vec<Vec<u8>>,
        calls: Vec<[u8; 22]>,
    }
    impl Mock {
        fn new(frames: Vec<Vec<u8>>) -> Self {
            Self {
                frames,
                calls: Vec::new(),
            }
        }
    }
    impl TpmTransport for Mock {
        fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmProbeError> {
            let command: [u8; 22] = command
                .try_into()
                .map_err(|_| TpmProbeError::MalformedResponse)?;
            self.calls.push(command);
            if self.frames.is_empty() {
                return Err(TpmProbeError::PermissionOrIo);
            }
            Ok(self.frames.remove(0))
        }
    }

    fn response(cap: u32, pairs: &[(u32, u32)], more: bool) -> Vec<u8> {
        let stride = if cap == TPM_CAP_HANDLES { 4 } else { 8 };
        let mut output = Vec::with_capacity(19 + pairs.len() * stride);
        output.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        output.extend_from_slice(&((19 + pairs.len() * stride) as u32).to_be_bytes());
        output.extend_from_slice(&0u32.to_be_bytes()); // TPM_RC_SUCCESS
        output.push(u8::from(more));
        output.extend_from_slice(&cap.to_be_bytes());
        output.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
        for &(name, value) in pairs {
            output.extend_from_slice(&name.to_be_bytes());
            if cap == TPM_CAP_PROPERTIES {
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
        output
    }

    fn valid() -> Mock {
        Mock::new(vec![
            response(
                TPM_CAP_PROPERTIES,
                &[(TPM_PT_FAMILY_INDICATOR, TPM_FAMILY_20)],
                false,
            ),
            response(
                TPM_CAP_PROPERTIES,
                &[(TPM_PT_MANUFACTURER, 0x494e5443)],
                false,
            ),
            response(
                TPM_CAP_HANDLES,
                &[(TPM_NV_FIRST + 1, 0), (TPM_NV_FIRST + 3, 0)],
                false,
            ),
        ])
    }

    #[test]
    fn valid_tpm2_capabilities_are_read_only_and_not_an_anchor() {
        let mut mock = valid();
        let result = probe_with_transport(2, 0, &mut mock).unwrap();
        assert_eq!(result.nv_handles, vec![TPM_NV_FIRST + 1, TPM_NV_FIRST + 3]);
        assert_eq!(result.manufacturer, 0x494e5443);
        assert!(!result.device_certified && !result.anchor_ready);
        assert_eq!(mock.calls.len(), 3);
        assert_eq!(
            mock.calls[0],
            request(TPM_CAP_PROPERTIES, TPM_PT_FAMILY_INDICATOR, 1)
        );
        assert_eq!(
            mock.calls[1],
            request(TPM_CAP_PROPERTIES, TPM_PT_MANUFACTURER, 1)
        );
        assert_eq!(
            mock.calls[2],
            request(TPM_CAP_HANDLES, TPM_NV_FIRST, MAX_NV_PAGE)
        );
    }

    #[test]
    fn cannot_fallback_to_v1_or_wrong_reported_family() {
        let mut mock = valid();
        assert_eq!(
            probe_with_transport(1, 0, &mut mock),
            Err(TpmProbeError::VersionNotTwo)
        );
        assert_eq!(mock.calls.len(), 0);
        let mut mock = valid();
        mock.frames[0] = response(TPM_CAP_PROPERTIES, &[(TPM_PT_FAMILY_INDICATOR, 0)], false);
        assert_eq!(
            probe_with_transport(2, 0, &mut mock),
            Err(TpmProbeError::VersionNotTwo)
        );
    }

    #[test]
    fn malformed_length_count_tag_and_capability_rejected() {
        let good = response(TPM_CAP_HANDLES, &[(TPM_NV_FIRST, 0)], false);
        let mut truncated = good.clone();
        truncated.pop();
        assert!(parse_response(&truncated, TPM_CAP_HANDLES, MAX_NV_PAGE).is_err());
        let mut oversized_count = good.clone();
        oversized_count[15..19].copy_from_slice(&999u32.to_be_bytes());
        assert!(parse_response(&oversized_count, TPM_CAP_HANDLES, MAX_NV_PAGE).is_err());
        let mut wrong_tag = good.clone();
        wrong_tag[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
        assert!(parse_response(&wrong_tag, TPM_CAP_HANDLES, MAX_NV_PAGE).is_err());
        assert!(matches!(
            parse_response(&good, TPM_CAP_PROPERTIES, 32),
            Err(TpmProbeError::CapabilityMismatch)
        ));
        let mut error = good;
        error[6..10].copy_from_slice(&0x922u32.to_be_bytes());
        assert_eq!(
            parse_response(&error, TPM_CAP_HANDLES, 32).err(),
            Some(TpmProbeError::TpmRejected(0x922))
        );
    }

    #[test]
    fn standard_ten_byte_tpm_error_header_is_reported_as_rejection() {
        let mut response = Vec::new();
        response.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        response.extend_from_slice(&10u32.to_be_bytes());
        response.extend_from_slice(&0x0000_0922u32.to_be_bytes());
        assert_eq!(
            parse_response(&response, TPM_CAP_PROPERTIES, 1).err(),
            Some(TpmProbeError::TpmRejected(0x922))
        );
    }

    #[test]
    fn duplicate_unsorted_or_out_of_range_nv_handles_are_rejected() {
        for items in [
            vec![(TPM_NV_FIRST + 2, 0), (TPM_NV_FIRST + 2, 0)],
            vec![(TPM_NV_FIRST + 2, 0), (TPM_NV_FIRST + 1, 0)],
            vec![(0x0200_0000, 0)],
        ] {
            let mut mock = valid();
            mock.frames[2] = response(TPM_CAP_HANDLES, &items, false);
            assert_eq!(
                probe_with_transport(2, 0, &mut mock),
                Err(TpmProbeError::MalformedResponse)
            );
        }
    }

    #[test]
    fn nv_page_overflow_is_reported_not_assumed_complete() {
        let mut mock = valid();
        mock.frames[2] = response(TPM_CAP_HANDLES, &[(TPM_NV_FIRST, 0)], true);
        let result = probe_with_transport(2, 0, &mut mock).unwrap();
        assert!(result.nv_list_incomplete);
    }

    #[test]
    fn candidate_anchor_never_returns_a_saved_value_or_advances() {
        let mut mock = valid();
        let candidate = probe_with_transport(2, 0, &mut mock).unwrap();
        let space = SpaceId::from_bytes([1; 16]);
        let resource = ResourceId::from_bytes([2; 16]);
        assert_eq!(
            candidate.read(space, resource),
            Err(UnifiedAnchorError::MissingOrUntrusted)
        );
        let placeholder = UnifiedPolicyHighWater {
            space,
            resource,
            root_public_key: [1; 32],
            root_key_epoch: 1,
            genesis_manifest: [2; 32],
            current_manifest: [2; 32],
            writer_epoch: 1,
            policy_sequence: 0,
            policy_head: [0; 32],
            revocation_root: [0; 32],
        };
        assert_eq!(
            candidate.compare_and_advance(placeholder, placeholder),
            Err(UnifiedAnchorError::MissingOrUntrusted)
        );
    }
}
