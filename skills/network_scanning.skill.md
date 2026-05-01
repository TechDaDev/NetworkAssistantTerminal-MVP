---
skill_name: network_scanning
display_name: Network Scanning
category: scan
risk_level: medium
tools:
  - detect_network
  - scan_network
  - answer_network_fact
  - show_devices
  - show_report
  - diagnose_network
  - nmap_scan_local
triggers:
  - scan my network
  - find devices
  - discover devices
  - what is my gateway
  - what is the gateway ip
  - what is my local ip
  - what subnet am i connected to
  - what is connected to my network
  - show open ports
  - check services
requires_confirmation:
  - scan_network
  - nmap_scan_local
forbidden:
  - public_scans
  - huge_cidrs
  - raw_nmap_flags
---

# Network Scanning Skill

Use this skill when the user wants to discover local devices, see what is connected, or summarize open management/service ports.

## Workflow

1. Detect the local private network.
2. Ask confirmation before scanning.
3. Run the built-in safe scan by default.
4. Save scan results to inventory.
5. Immediately show discovered devices.
6. If the user asked for a summary or diagnosis, run `diagnose_network` after showing devices.
7. Recommend enrichment, controlled Nmap, or topology only when the result suggests it.

Use Nmap only when the user asks for deeper service detail or explicitly asks for Nmap. Do not run public scans, hostnames, raw flags, vulnerability scripts, UDP scans, or CIDRs larger than `/24`.

## Gateway / Local Network Fact Questions

Use `answer_network_fact` when the user asks about:
- gateway IP
- gateway vendor
- gateway type
- gateway ports
- local IP
- local subnet
- network interface

Answer from local network detection and inventory first.
If inventory is missing, ask for scan/enrich.
Do not generate a plugin.
Do not generate a custom plan.
