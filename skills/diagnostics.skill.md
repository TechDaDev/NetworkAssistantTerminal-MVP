---
skill_name: diagnostics
display_name: Diagnostics
category: diagnostics
risk_level: low
tools:
  - diagnose_network
  - diagnose_device
  - diagnose_management_ports
  - diagnose_connectivity
triggers:
  - diagnose network
  - diagnose device
  - show risky management ports
  - ping check
requires_confirmation: []
forbidden:
  - configuration_commands
---

# Diagnostics Skill

Use diagnostics after scans, enrichment, or device inspection. Summarize findings directly in the agent response and include the next useful safe command only when needed.

Diagnostics do not change devices.
