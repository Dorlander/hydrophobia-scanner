//! firmware-audit entry point.
//!
//! Produces a single unified report that covers two independent defensive
//! checks against the current machine:
//!   1. Secure Boot `db` enumeration + known-exposed-certificate match.
//!   2. Insyde H2O Hydroph0bia (CVE-2025-4275) indicator probe.
//!
//! The tool is read-only. It does not modify firmware, variables, or boot
//! configuration.

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

mod hydrophobia;
mod secureboot;

#[cfg(windows)]
#[path = "platform/windows.rs"]
mod platform;

#[cfg(target_os = "linux")]
#[path = "platform/linux.rs"]
mod platform;

#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    use anyhow::{anyhow, Result};
    pub fn read_efi_var(_name: &str, _guid: &str) -> Result<Vec<u8>> {
        Err(anyhow!("efi variable access is not supported on this platform"))
    }
    pub fn efi_var_exists(_name: &str) -> Option<bool> {
        None
    }
    pub fn read_smbios() -> Result<Vec<u8>> {
        Err(anyhow!("smbios access is not supported on this platform"))
    }
}

#[derive(Parser)]
#[command(
    name = "firmware-audit",
    version,
    about = "Defensive firmware integrity scanner.",
    long_about = "Scans the running machine's Secure Boot db for exposed vendor \
                  signing certificates and probes for Insyde H2O Hydroph0bia \
                  (CVE-2025-4275) indicators. Read-only; no firmware state is \
                  changed."
)]
struct Args {
    /// Emit machine-readable JSON instead of a human report.
    #[arg(long)]
    json: bool,

    /// Skip the Hydroph0bia check and only run the Secure Boot db scan.
    #[arg(long, conflicts_with = "hydrophobia_only")]
    secureboot_only: bool,

    /// Skip the Secure Boot db scan and only run the Hydroph0bia check.
    #[arg(long)]
    hydrophobia_only: bool,
}

#[derive(Default, Serialize)]
struct Report {
    tool: &'static str,
    tool_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    secureboot: Option<secureboot::SecurebootReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hydrophobia: Option<hydrophobia::HydrophobiaReport>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut report = Report {
        tool: "firmware-audit",
        tool_version: env!("CARGO_PKG_VERSION"),
        ..Default::default()
    };

    if !args.hydrophobia_only {
        report.secureboot = Some(
            secureboot::scan().unwrap_or_else(|e| secureboot::SecurebootReport::error(e.to_string())),
        );
    }
    if !args.secureboot_only {
        report.hydrophobia = Some(
            hydrophobia::scan().unwrap_or_else(|e| hydrophobia::HydrophobiaReport::error(e.to_string())),
        );
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text(&report);
    }

    std::process::exit(worst_severity(&report));
}

fn worst_severity(r: &Report) -> i32 {
    let mut level = 0;
    if let Some(sb) = &r.secureboot {
        level = level.max(sb.severity());
    }
    if let Some(h) = &r.hydrophobia {
        level = level.max(h.severity());
    }
    level
}

fn print_text(r: &Report) {
    println!("firmware-audit {} report", r.tool_version);
    println!("==========================================");
    if let Some(sb) = &r.secureboot {
        sb.print();
    }
    if let Some(h) = &r.hydrophobia {
        h.print();
    }
    println!("==========================================");
}
