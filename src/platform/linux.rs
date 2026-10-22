//! Linux-side platform surface.
//!
//! EFI variables are read from `/sys/firmware/efi/efivars/<name>-<guid>`
//! (first four bytes are the EFI attributes mask; the remainder is the
//! variable payload). SMBIOS is read from `/sys/firmware/dmi/tables/DMI`.
//! Both nodes require root to read on typical distributions.

use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

const EFIVARS_DIR: &str = "/sys/firmware/efi/efivars";
const DMI_RAW: &str = "/sys/firmware/dmi/tables/DMI";

pub fn read_efi_var(name: &str, guid: &str) -> Result<Vec<u8>> {
    let path = format!("{}/{}-{}", EFIVARS_DIR, name, guid);
    let raw = fs::read(&path).map_err(|e| {
        anyhow!(
            "read {} failed: {} (needs root; the system must be UEFI-booted \
             with efivarfs mounted)",
            path,
            e
        )
    })?;
    if raw.len() < 4 {
        return Err(anyhow!("efi variable {} truncated", name));
    }
    Ok(raw[4..].to_vec())
}

/// Enumerate `/sys/firmware/efi/efivars` and look for any entry whose name
/// starts with `<name>-`. This works regardless of GUID.
pub fn efi_var_exists(name: &str) -> Option<bool> {
    let p = Path::new(EFIVARS_DIR);
    let dir = fs::read_dir(p).ok()?;
    for entry in dir.flatten() {
        let fname = entry.file_name();
        let s = fname.to_string_lossy();
        if let Some(rest) = s.strip_prefix(name) {
            if rest.starts_with('-') {
                return Some(true);
            }
        }
    }
    Some(false)
}

pub fn read_smbios() -> Result<Vec<u8>> {
    fs::read(DMI_RAW).map_err(|e| {
        anyhow!(
            "read {} failed: {} (needs root; some distros require \
             CONFIG_DMIID + sysfs dmi tables)",
            DMI_RAW,
            e
        )
    })
}
