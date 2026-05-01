---
skill_name: topology
display_name: Topology
description: Use this skill when the user wants topology building, explanation, export, risk checks, or report generation from local evidence and optional manual overlays, with no direct device configuration changes.
category: topology
risk_level: low
tools:
  - build_topology
  - show_topology
  - explain_topology
  - export_topology
  - topology_report
  - topology_risk_check
  - manual_topology_node
  - manual_topology_edge
  - manual_topology_note
triggers:
  - build topology
  - show topology
  - explain topology
  - topology report
requires_confirmation: []
forbidden:
  - device_changes
---

# Topology Skill

Build topology from local evidence, show it, explain confidence, export it, or produce a report. Manual overlay tools add local corrections only. No topology workflow changes device configuration.
