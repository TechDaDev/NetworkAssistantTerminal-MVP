---
skill_name: nmap_scanning
display_name: Controlled Nmap Scanning
description: Use this skill when deeper service inspection is needed with approved nmap profiles on private targets, while enforcing strict safety controls against raw flags, public targets, and aggressive scan modes.
category: nmap
risk_level: medium
tools:
  - nmap_check
  - nmap_scan_local
  - nmap_scan_host
  - nmap_scan_device
  - show_report
triggers:
  - nmap check
  - nmap scan local
  - deeper service scan
  - nmap scan device
requires_confirmation:
  - nmap_scan_local
  - nmap_scan_host
  - nmap_scan_device
forbidden:
  - raw_nmap_flags
  - public_targets
  - vulnerability_scripts
---

# Controlled Nmap Scanning Skill

Use controlled Nmap only for private/local targets with safe profiles: `ping`, `common-ports`, and `service-light`.

After a scan, display the saved scan result or latest report. Do not accept raw flags, hostnames, public IPs, aggressive timing, UDP scans, all-port scans, or vulnerability scripts.
