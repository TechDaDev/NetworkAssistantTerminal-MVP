---
skill_name: diagnostics
display_name: Diagnostics
description: Use this skill when the user wants troubleshooting summaries, device diagnostics, connectivity checks, management-port analysis, or quick factual answers about the local gateway and subnet without making device changes.
category: diagnostics
risk_level: low
tools:
  - diagnose_network
  - diagnose_device
  - diagnose_management_ports
  - diagnose_connectivity
  - answer_network_fact
triggers:
  - diagnose network
  - diagnose device
  - show risky management ports
  - ping check
  - what is my gateway
  - what is the gateway ip
  - what is the vendor of the gateway
  - what is the vendor of the network gateway
  - what type is the gateway
  - what ports are open on the gateway
  - what subnet am i connected to
  - what is my local ip
  - what is my network interface
requires_confirmation: []
forbidden:
  - configuration_commands
---

# Diagnostics Skill

Use diagnostics after scans, enrichment, or device inspection. Summarize findings directly in the agent response and include the next useful safe command only when needed.

Diagnostics do not change devices.

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
