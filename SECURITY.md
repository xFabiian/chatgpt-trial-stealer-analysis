# Security Policy

## Purpose

This repository contains **Indicators of Compromise (IOCs), malware analysis, and removal scripts** for the "ChatGPT Plus Free Trial" info-stealer campaign. All content is for **educational and defensive security research purposes only**.

## ⚠️ Important Safety Notices

1. **No malware binaries are distributed** in this repository. Only IOCs (hashes, URLs, patterns), analysis write-ups, and removal scripts are included.
2. **Removal scripts are provided for defensive use only.** Review any script before executing it — never blindly run code from the internet.
3. **Do not execute any commands from the scam** described in this repository. They will infect your machine.

## Reporting Vulnerabilities

If you discover issues with the analysis, IOCs, or removal scripts:

1. Open a GitHub Issue with the `[BUG]` prefix for incorrect IOCs or broken scripts
2. Open a GitHub Issue with the `[UPDATE]` prefix for new samples or IOCs
3. For sensitive discoveries (e.g., still-active C2 infrastructure), email is preferred — see below

## IOC Submission

If you have new IOCs related to this campaign:

- Open a Pull Request adding them to the appropriate file in `iocs/`
- Include a brief description of how the IOC was discovered
- Format: one IOC per line, with comments for context

## Content Warnings

This repository discusses:
- Malware behavior and techniques
- Credential theft mechanisms
- Social engineering tactics

All descriptions are for **defensive purposes only** — understanding the threat to better defend against it.

## Disclaimer

The maintainers are **not affiliated with** and do not **endorse** any of the malicious actors, campaigns, or infrastructure described in this repository. This work is independent security research.
