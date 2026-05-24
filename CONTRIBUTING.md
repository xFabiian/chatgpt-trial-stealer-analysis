# Contributing

Thank you for your interest in improving this malware analysis repository!

## What Contributions Are Welcome

- **New IOCs** — Additional hashes, URLs, domains, IPs, or host-based indicators
- **Analysis improvements** — Deeper reverse engineering, new findings
- **Removal script updates** — Bug fixes, broader coverage, new malware variants
- **Documentation** — Typos, clarity improvements, translations
- **Detection rules** — YARA rules, Sigma rules, Suricata/Snort signatures (in a `detection/` folder)

## What Is NOT Accepted

- **Malware binaries** — Do not submit actual malware samples
- **Offensive tooling** — This is a defensive repository only
- **Exploitation guides** — No content that facilitates misuse

## How to Contribute

### Adding IOCs

1. Add your IOCs to the appropriate file in `iocs/`:
   - `network.txt` — IPs, domains, URLs
   - `hashes.txt` — File hashes (SHA-256 preferred)
   - `host_windows.txt` — Windows-specific indicators
   - `host_macos.txt` — macOS-specific indicators
2. Include a comment with the date and brief context
3. Submit a Pull Request

### Adding Detection Rules

1. Create files in `detection/` with descriptive names
2. Supported formats: `.yar` (YARA), `.yaml` (Sigma), `.rules` (Suricata/Snort)
3. Include metadata comments with author, date, and description

### Improving Removal Scripts

1. Test your changes in an isolated environment
2. Document what the script does and how it works
3. Add comments explaining each step
4. Submit a Pull Request with a description of the changes

## IOC Format

Please follow the existing format in IOC files:

```
# === Category Header ===
# Comment with context if needed
indicator_value    # inline comment with description
```

## Code Style

- **PowerShell**: Use verb-noun naming, include `-ErrorAction SilentlyContinue` where appropriate
- **Bash**: Use `#!/bin/bash`, quote variables, check for command existence
- **Comments**: Explain *why*, not just *what*

## Review Process

1. All IOCs are verified before merge
2. Removal scripts are reviewed for safety and correctness
3. Analysis claims should be reproducible or cite sources

## Questions?

Open a GitHub Discussion or issue — happy to help!
