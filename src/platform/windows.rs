//! Windows-side platform surface.
//!
//! Reads EFI variables via `GetFirmwareEnvironmentVariableExW` (requires an
//! administrator process holding `SE_SYSTEM_ENVIRONMENT_NAME`) and SMBIOS
//! via `GetSystemFirmwareTable`.

use anyhow::{anyhow, Result};
use std::ptr;

/// Windows multi-char constant 'RSMB' (BIOS firmware table provider).
const SMBIOS_PROVIDER: u32 = 0x5253_4D42;

#[link(name = "kernel32")]
extern "system" {
    fn GetFirmwareEnvironmentVariableExW(
        lpName: *const u16,
        lpGuid: *const u16,
        pBuffer: *mut u8,
        nSize: u32,
        pdwAttributes: *mut u32,
    ) -> u32;

    fn GetSystemFirmwareTable(
        FirmwareTableProviderSignature: u32,
        FirmwareTableID: u32,
        pFirmwareTableBuffer: *mut u8,
        BufferSize: u32,
    ) -> u32;
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn braced(guid: &str) -> String {
    if guid.starts_with('{') {
        guid.to_string()
    } else {
        format!("{{{}}}", guid)
    }
}

pub fn read_efi_var(name: &str, guid: &str) -> Result<Vec<u8>> {
    let name_w = to_wide(name);
    let guid_w = to_wide(&braced(guid));
    let mut buf = vec![0u8; 64 * 1024];
    let mut attrs = 0u32;
    let got = unsafe {
        GetFirmwareEnvironmentVariableExW(
            name_w.as_ptr(),
            guid_w.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut attrs,
        )
    };
    if got == 0 {
        return Err(anyhow!(
            "GetFirmwareEnvironmentVariableExW({}, {}) failed. Requires an \
             administrator process with SE_SYSTEM_ENVIRONMENT_NAME enabled, on a \
             UEFI-booted machine.",
            name,
            guid
        ));
    }
    buf.truncate(got as usize);
    Ok(buf)
}

/// Windows does not expose a variable-enumeration API that works without a
/// known GUID. Returning `None` lets the caller surface "probe unavailable"
/// instead of claiming the variable is absent based on a guessed GUID.
pub fn efi_var_exists(_name: &str) -> Option<bool> {
    None
}

pub fn read_smbios() -> Result<Vec<u8>> {
    unsafe {
        let size = GetSystemFirmwareTable(SMBIOS_PROVIDER, 0, ptr::null_mut(), 0);
        if size == 0 {
            return Err(anyhow!("GetSystemFirmwareTable(RSMB) size query failed"));
        }
        let mut buf = vec![0u8; size as usize];
        let got = GetSystemFirmwareTable(SMBIOS_PROVIDER, 0, buf.as_mut_ptr(), size);
        if got == 0 {
            return Err(anyhow!("GetSystemFirmwareTable(RSMB) read failed"));
        }
        buf.truncate(got as usize);
        // Strip the RawSMBIOSData header: 1B Used20CallingMethod, 1B Major,
        // 1B Minor, 1B DmiRevision, 4B Length.
        if buf.len() > 8 {
            Ok(buf[8..].to_vec())
        } else {
            Err(anyhow!("SMBIOS payload too short"))
        }
    }
}
