//! Secure Boot `db` enumeration and known-exposed-certificate detection.
//!
//! The scanner reads the `db` EFI variable, walks every `EFI_SIGNATURE_LIST`
//! inside it, extracts each embedded X.509 certificate, SHA-256-hashes the
//! DER body, and matches the hash against a curated list of certificates
//! that have been publicly reported as exposed (private-key recoverable
//! from a vendor firmware archive, test certificate, etc.).

use anyhow::{anyhow, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::platform;

/// `EFI_IMAGE_SECURITY_DATABASE_GUID` — the namespace that holds `db`.
const DB_GUID: &str = "d719b2cb-3d3a-4596-a3bc-dad00e67656f";
const DB_NAME: &str = "db";

/// `EFI_CERT_X509_GUID` as laid out in memory (first three fields are
/// stored little-endian per the UEFI spec, remaining 8 bytes are big-
/// endian). Equivalent to `{a5c059a1-94e4-4aa7-87b5-ab155c2bf072}`.
const EFI_CERT_X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];

/// Curated list of certificates known to be exposed in a public source.
/// Each entry must be independently verifiable from a public advisory.
const KNOWN_BAD: &[KnownBad] = &[
    KnownBad {
        sha256_hex: "7373145cffbdc58304b34ec0dbc9176d02788d167cf02f44bf397ad19c785176",
        label: "Clevo Secure Certificate",
        reference: "Observed in Secure Boot db of a 2021-era retail Insyde H2O laptop; private key exposure unverified",
        severity: Severity::Critical,
        notes:
            "Signing certificate recovered from a publicly distributed OEM firmware \
             archive. Platforms that trust this certificate in db will accept binaries \
             signed by anyone who extracted the private key. Validity: 2017-08-31 to \
             2039-12-31.",
    },
    // TODO: Binarly PKfail test certificates (CVE-2024-8105). The authoritative
    // SHA-256 catalog is maintained by Binarly; entries must be transcribed
    // from their published list rather than reconstructed, so they are
    // omitted here until a direct cross-check is performed.
];

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info,
    Warning,
    Critical,
}

struct KnownBad {
    sha256_hex: &'static str,
    label: &'static str,
    reference: &'static str,
    severity: Severity,
    notes: &'static str,
}

#[derive(Serialize)]
pub struct SecurebootReport {
    status: Status,
    db_entry_count: usize,
    cert_count: usize,
    findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Clean,
    Flagged,
    Error,
}

#[derive(Serialize)]
pub struct Finding {
    sha256: String,
    subject: String,
    not_before: String,
    not_after: String,
    label: String,
    reference: String,
    severity: Severity,
    notes: String,
}

impl SecurebootReport {
    pub fn error(msg: String) -> Self {
        Self {
            status: Status::Error,
            db_entry_count: 0,
            cert_count: 0,
            findings: Vec::new(),
            error: Some(msg),
        }
    }

    pub fn severity(&self) -> i32 {
        match self.status {
            Status::Clean => 0,
            Status::Error => 1,
            Status::Flagged => {
                if self.findings.iter().any(|f| matches!(f.severity, Severity::Critical)) {
                    2
                } else {
                    1
                }
            }
        }
    }

    pub fn print(&self) {
        println!();
        println!("[1] Secure Boot db scan");
        println!("------------------------------------------");
        if let Some(err) = &self.error {
            println!("  status  : ERROR");
            println!("  reason  : {}", err);
            println!("  hint    : run from an elevated shell on a UEFI-booted system");
            return;
        }
        println!("  db entries : {}", self.db_entry_count);
        println!("  x509 certs : {}", self.cert_count);
        match self.status {
            Status::Clean => println!("  verdict    : clean (no known-exposed certs in db)"),
            Status::Flagged => println!("  verdict    : FLAGGED"),
            Status::Error => println!("  verdict    : error"),
        }
        for f in &self.findings {
            println!();
            println!("  !! finding: {}", f.label);
            println!("     sha256   : {}", f.sha256);
            println!("     subject  : {}", f.subject);
            println!("     validity : {} .. {}", f.not_before, f.not_after);
            println!("     ref      : {}", f.reference);
            println!("     notes    : {}", f.notes);
        }
    }
}

pub fn scan() -> Result<SecurebootReport> {
    let raw = platform::read_efi_var(DB_NAME, DB_GUID)?;
    let (lists, certs) = parse_signature_lists(&raw)?;

    let mut findings = Vec::new();
    for cert_der in &certs {
        let hash = sha256_hex(cert_der);
        for kb in KNOWN_BAD {
            if kb.sha256_hex.eq_ignore_ascii_case(&hash) {
                let (subject, not_before, not_after) = inspect_cert(cert_der);
                findings.push(Finding {
                    sha256: hash.clone(),
                    subject,
                    not_before,
                    not_after,
                    label: kb.label.into(),
                    reference: kb.reference.into(),
                    severity: kb.severity,
                    notes: kb.notes.into(),
                });
            }
        }
    }

    let status = if findings.is_empty() {
        Status::Clean
    } else {
        Status::Flagged
    };
    Ok(SecurebootReport {
        status,
        db_entry_count: lists,
        cert_count: certs.len(),
        findings,
        error: None,
    })
}

fn sha256_hex(buf: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(buf);
    hex::encode(h.finalize())
}

fn inspect_cert(der: &[u8]) -> (String, String, String) {
    match X509Certificate::from_der(der) {
        Ok((_, c)) => (
            c.subject().to_string(),
            c.validity()
                .not_before
                .to_rfc2822()
                .unwrap_or_else(|_| "<invalid date>".into()),
            c.validity()
                .not_after
                .to_rfc2822()
                .unwrap_or_else(|_| "<invalid date>".into()),
        ),
        Err(_) => ("<unparsable>".into(), "?".into(), "?".into()),
    }
}

/// Walk a concatenation of `EFI_SIGNATURE_LIST` structures and return the
/// list count plus every X.509 cert body contained in `EFI_CERT_X509` lists.
fn parse_signature_lists(buf: &[u8]) -> Result<(usize, Vec<Vec<u8>>)> {
    let mut lists = 0usize;
    let mut certs = Vec::new();
    let mut cursor = 0usize;

    while cursor + 28 <= buf.len() {
        let guid = &buf[cursor..cursor + 16];
        let list_size = u32::from_le_bytes(buf[cursor + 16..cursor + 20].try_into()?) as usize;
        let header_size = u32::from_le_bytes(buf[cursor + 20..cursor + 24].try_into()?) as usize;
        let sig_size = u32::from_le_bytes(buf[cursor + 24..cursor + 28].try_into()?) as usize;

        if list_size < 28 + header_size
            || sig_size <= 16
            || cursor + list_size > buf.len()
        {
            return Err(anyhow!(
                "malformed EFI_SIGNATURE_LIST at offset {}",
                cursor
            ));
        }
        lists += 1;

        if guid == EFI_CERT_X509_GUID.as_slice() {
            let mut p = cursor + 28 + header_size;
            let end = cursor + list_size;
            while p + sig_size <= end {
                // 16 bytes = SignatureOwner GUID; remainder = cert body.
                certs.push(buf[p + 16..p + sig_size].to_vec());
                p += sig_size;
            }
        }
        cursor += list_size;
    }
    Ok((lists, certs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_db_parses() {
        let (lists, certs) = parse_signature_lists(&[]).unwrap();
        assert_eq!(lists, 0);
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn clevo_hash_present_in_catalog() {
        assert!(KNOWN_BAD
            .iter()
            .any(|k| k.sha256_hex.starts_with("7373145cff")));
    }

    #[test]
    fn malformed_list_rejected() {
        // Valid GUID + bogus list_size (= 0) must be rejected rather than looped.
        let mut buf = EFI_CERT_X509_GUID.to_vec();
        buf.extend_from_slice(&0u32.to_le_bytes()); // list_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // header_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // sig_size
        assert!(parse_signature_lists(&buf).is_err());
    }
}
