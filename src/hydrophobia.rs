//! Hydroph0bia (CVE-2025-4275) indicator probe.
//!
//! Hydroph0bia is a trust-boundary defect in the Insyde H2O SecureFlash DXE
//! driver: an attacker-reachable NVRAM variable is treated as an authority
//! for firmware-update signature verification. The two platform-visible
//! indicators we check for are:
//!
//! 1. SMBIOS BIOS Information (type 0) that identifies the firmware as
//!    Insyde H2O.
//! 2. The `SecureFlashCertData` runtime variable, created by the vulnerable
//!    SecureFlash driver.
//!
//! Neither indicator proves exploitability on its own. The combined result
//! is informational; the authoritative source is the Insyde advisory for
//! the exact BIOS build.

use anyhow::Result;
use serde::Serialize;

use crate::platform;

/// The variable name created by the vulnerable Insyde SecureFlash driver.
/// GUID is intentionally not probed by name on Windows; see the platform
/// layer for why.
const SECURE_FLASH_CERT: &str = "SecureFlashCertData";

#[derive(Serialize)]
pub struct HydrophobiaReport {
    status: Status,
    bios_vendor: Option<String>,
    bios_version: Option<String>,
    system_manufacturer: Option<String>,
    system_product: Option<String>,
    insyde_detected: bool,
    secure_flash_cert_var: VarProbe,
    verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Clean,
    Warning,
    Flagged,
    Error,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum VarProbe {
    Present,
    Absent,
    Unavailable,
}

impl From<Option<bool>> for VarProbe {
    fn from(o: Option<bool>) -> Self {
        match o {
            Some(true) => VarProbe::Present,
            Some(false) => VarProbe::Absent,
            None => VarProbe::Unavailable,
        }
    }
}

impl VarProbe {
    fn label(&self) -> &'static str {
        match self {
            VarProbe::Present => "present",
            VarProbe::Absent => "absent",
            VarProbe::Unavailable => "probe unavailable on this platform",
        }
    }
}

impl HydrophobiaReport {
    pub fn error(msg: String) -> Self {
        Self {
            status: Status::Error,
            bios_vendor: None,
            bios_version: None,
            system_manufacturer: None,
            system_product: None,
            insyde_detected: false,
            secure_flash_cert_var: VarProbe::Unavailable,
            verdict: "Hydroph0bia probe failed".into(),
            error: Some(msg),
        }
    }

    pub fn severity(&self) -> i32 {
        match self.status {
            Status::Clean => 0,
            Status::Warning | Status::Error => 1,
            Status::Flagged => 2,
        }
    }

    pub fn print(&self) {
        println!();
        println!("[2] Hydroph0bia / CVE-2025-4275 probe");
        println!("------------------------------------------");
        if let Some(err) = &self.error {
            println!("  status  : ERROR");
            println!("  reason  : {}", err);
            return;
        }
        println!("  bios vendor         : {}", self.bios_vendor.as_deref().unwrap_or("?"));
        println!("  bios version        : {}", self.bios_version.as_deref().unwrap_or("?"));
        println!(
            "  system manufacturer : {}",
            self.system_manufacturer.as_deref().unwrap_or("?")
        );
        println!(
            "  system product      : {}",
            self.system_product.as_deref().unwrap_or("?")
        );
        println!(
            "  insyde h2o          : {}",
            if self.insyde_detected { "yes" } else { "no" }
        );
        println!(
            "  SecureFlashCertData : {}",
            self.secure_flash_cert_var.label()
        );
        println!("  verdict             : {}", self.verdict);
    }
}

pub fn scan() -> Result<HydrophobiaReport> {
    let smbios = platform::read_smbios()?;
    let (vendor, version, sys_mfr, sys_prod) = parse_smbios_strings(&smbios);
    let insyde = vendor.as_deref().map(is_insyde).unwrap_or(false);
    let probe = platform::efi_var_exists(SECURE_FLASH_CERT);
    let probe_v = VarProbe::from(probe);

    let (status, verdict) = match (insyde, probe) {
        (true, Some(true)) => (
            Status::Flagged,
            "Insyde H2O firmware is present AND the SecureFlashCertData variable is \
             exposed in NVRAM. This matches the Hydroph0bia (CVE-2025-4275) exposure \
             pattern. Treat the current firmware build as potentially vulnerable until \
             Insyde's advisory confirms your BIOS build carries the fix."
                .to_string(),
        ),
        (true, Some(false)) => (
            Status::Warning,
            "Insyde H2O detected without the SecureFlashCertData variable. This is \
             consistent with either a patched build or an Insyde variant that does not \
             ship SecureFlash. Confirm against Insyde's advisory for the exact BIOS \
             version."
                .to_string(),
        ),
        (true, None) => (
            Status::Warning,
            "Insyde H2O detected but the variable probe is unavailable from this \
             OS surface. Re-run from a Linux live USB (or a UEFI shell) to confirm."
                .to_string(),
        ),
        (false, Some(true)) => (
            Status::Warning,
            "SecureFlashCertData variable is present on a platform that does not \
             advertise Insyde H2O in SMBIOS. Investigate: SMBIOS may be rebranded, \
             or an unrelated firmware component is reusing the variable name."
                .to_string(),
        ),
        (false, Some(false)) => (
            Status::Clean,
            "No Hydroph0bia indicators observed on this platform.".to_string(),
        ),
        (false, None) => (
            Status::Clean,
            "SMBIOS does not advertise Insyde H2O; variable probe skipped.".to_string(),
        ),
    };

    Ok(HydrophobiaReport {
        status,
        bios_vendor: vendor,
        bios_version: version,
        system_manufacturer: sys_mfr,
        system_product: sys_prod,
        insyde_detected: insyde,
        secure_flash_cert_var: probe_v,
        verdict,
        error: None,
    })
}

fn is_insyde(vendor: &str) -> bool {
    vendor.to_ascii_lowercase().contains("insyde")
}

/// Minimal SMBIOS walker. Pulls BIOS vendor + version from type 0 and
/// System Manufacturer + Product from type 1. Stops at type 127 or at
/// malformed records.
fn parse_smbios_strings(
    buf: &[u8],
) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let mut vendor = None;
    let mut version = None;
    let mut sys_mfr = None;
    let mut sys_prod = None;

    let mut p = 0usize;
    while p + 4 <= buf.len() {
        let stype = buf[p];
        let len = buf[p + 1] as usize;
        if len < 4 || p + len > buf.len() {
            break;
        }

        // Collect strings following the formatted section.
        let mut strings: Vec<String> = Vec::new();
        let mut sp = p + len;
        loop {
            if sp >= buf.len() {
                break;
            }
            if buf[sp] == 0 {
                // Two consecutive nulls terminate the record.
                if sp + 1 < buf.len() && buf[sp + 1] == 0 {
                    sp += 2;
                    break;
                }
                sp += 1;
                continue;
            }
            let start = sp;
            while sp < buf.len() && buf[sp] != 0 {
                sp += 1;
            }
            strings.push(
                std::str::from_utf8(&buf[start..sp])
                    .unwrap_or_default()
                    .to_string(),
            );
        }

        let read_idx = |i: u8| -> Option<String> {
            if i == 0 {
                None
            } else {
                strings.get(i as usize - 1).cloned()
            }
        };

        match stype {
            0 if len >= 6 => {
                vendor = read_idx(buf[p + 4]);
                version = read_idx(buf[p + 5]);
            }
            1 if len >= 6 => {
                sys_mfr = read_idx(buf[p + 4]);
                sys_prod = read_idx(buf[p + 5]);
            }
            127 => break,
            _ => {}
        }

        if sp <= p + len {
            break;
        }
        p = sp;
    }

    (vendor, version, sys_mfr, sys_prod)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insyde_match_is_case_insensitive() {
        assert!(is_insyde("Insyde Corp."));
        assert!(is_insyde("INSYDE SOFTWARE CORP"));
        assert!(!is_insyde("American Megatrends Inc."));
    }

    #[test]
    fn empty_smbios_yields_nones() {
        let (v, w, m, p) = parse_smbios_strings(&[]);
        assert!(v.is_none() && w.is_none() && m.is_none() && p.is_none());
    }
}
