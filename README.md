# firmware-audit

A read-only defensive scanner that audits a running UEFI machine for two
independent firmware-trust failures:

1. **Secure Boot `db` exposure** — any X.509 certificate in the current
   `db` whose private key is publicly recoverable (for example, the Clevo
   "Secure Certificate" exposed through the B10717 firmware archive,
   CVE-2025-11577). The scanner enumerates every X.509 cert in `db`,
   SHA-256-hashes each one, and matches against a curated list of
   known-exposed certificates.
2. **Hydroph0bia (CVE-2025-4275, Insyde H2O)** — identifies Insyde H2O
   platforms from SMBIOS and probes NVRAM for the `SecureFlashCertData`
   variable created by the vulnerable SecureFlash DXE driver.

The tool makes no firmware modifications. It reads only.

## Build

```
cargo build --release
```

Rust 1.70 or newer. Dependencies: `anyhow`, `clap`, `hex`, `sha2`, `serde`,
`serde_json`, `x509-parser`.

## Run

Elevated privileges are required to read EFI runtime variables.

```
# Windows (elevated PowerShell)
.\target\release\firmware-audit.exe

# Linux
sudo ./target/release/firmware-audit
```

Flags:

| Flag                 | Effect                                       |
| -------------------- | -------------------------------------------- |
| `--json`             | Emit machine-readable JSON instead of text   |
| `--secureboot-only`  | Only run the Secure Boot db scan             |
| `--hydrophobia-only` | Only run the Hydroph0bia probe               |

Exit code: `0` clean, `1` warning, `2` critical finding.

## Example output

### Clean host

```
firmware-audit 0.1.0 report
==========================================

[1] Secure Boot db scan
------------------------------------------
  db entries : 2
  x509 certs : 2
  verdict    : clean (no known-exposed certs in db)

[2] Hydroph0bia / CVE-2025-4275 probe
------------------------------------------
  bios vendor         : American Megatrends Inc.
  bios version        : F.42
  system manufacturer : HP
  system product      : EliteBook 840 G5
  insyde h2o          : no
  SecureFlashCertData : absent
  verdict             : No Hydroph0bia indicators observed on this platform.
==========================================
```

### Flagged host (illustrative)

```
[1] Secure Boot db scan
------------------------------------------
  db entries : 3
  x509 certs : 3
  verdict    : FLAGGED

  !! finding: Clevo Secure Certificate
     sha256   : 7373145cffbdc58304b34ec0dbc9176d02788d167cf02f44bf397ad19c785176
     subject  : CN=Secure Certificate
     validity : 2017-08-31 00:00:00 UTC .. 2039-12-31 23:59:59 UTC
     ref      : CVE-2025-11577 (Clevo B10717 firmware archive leak)
     notes    : Signing certificate recovered from a publicly distributed OEM
                firmware archive. Platforms that trust this certificate in db
                will accept binaries signed by anyone who extracted the private
                key.

[2] Hydroph0bia / CVE-2025-4275 probe
------------------------------------------
  bios vendor         : INSYDE Corp.
  bios version        : 1.07.FB08
  insyde h2o          : yes
  SecureFlashCertData : present
  verdict             : Insyde H2O firmware is present AND the SecureFlashCertData
                        variable is exposed in NVRAM. This matches the Hydroph0bia
                        (CVE-2025-4275) exposure pattern. Treat the current firmware
                        build as potentially vulnerable until Insyde's advisory
                        confirms your BIOS build carries the fix.
```

## Note on Microsoft baseline certificates

On a stock Secure Boot `db` you will typically see the two Microsoft-rooted
certificates below in addition to any vendor entries. These are **expected**;
`firmware-audit` does not flag them.

| Certificate                            | Not Before   | Not After    |
| -------------------------------------- | ------------ | ------------ |
| Microsoft Corporation UEFI CA 2011     | 2011-06-27   | **2026-06-27** |
| Microsoft Windows Production PCA 2011  | 2011-10-19   | 2026-10-19   |

Both Microsoft CAs expire during 2026. The replacement roots — Microsoft
UEFI CA 2023 and Microsoft Windows UEFI CA 2023 — are expected to be
`dbUpdate`'d into platforms during 2024–2026 by vendor firmware updates
and by Microsoft's Secure Boot servicing rollout.

If your `cert_count` is `2` and you see no findings, your `db` is at the
Microsoft baseline. Upgrading to the 2023 roots is a vendor action.

## Scope and limitations

- Reports only on the local machine.
- Reads EFI runtime variables through the standard OS surfaces
  (`GetFirmwareEnvironmentVariableExW` on Windows, `/sys/firmware/efi/efivars`
  on Linux). No kernel driver, no SPI access, no firmware modification.
- The known-bad list is deliberately conservative; see `src/secureboot.rs`
  for the curated catalog and the `TODO` note for pending Binarly PKfail
  entries (CVE-2024-8105). Only certificates verifiable against a public
  advisory are included.
- The Windows build cannot enumerate NVRAM variables without a known GUID.
  On Windows, the Hydroph0bia probe reports `probe unavailable`; re-run
  from a Linux live USB (or a UEFI shell) to confirm variable presence.
- Clevo certificate validity shown in example output: **2017-08-31 to
  2039-12-31** (per the certificate's own `Validity` field).

## Threat model

`firmware-audit` is for defenders auditing their own fleet. It helps answer
"is my platform trusting a known-exposed signing certificate?" and "does my
Insyde H2O build match the public Hydroph0bia pattern?" It does not install,
remove, bypass, or alter any firmware trust anchor.

## License

Apache-2.0.
