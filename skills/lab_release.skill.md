---
skill_name: lab_release
display_name: Lab and Release
description: Use this skill for operational readiness checks such as doctor, release readiness, lab checklist validation, and safe environment inspection commands that do not change live network devices.
category: lab
risk_level: low
tools:
  - lab_checklist
  - lab_validate_device
  - lab_validate_plan
  - lab_integration_check
  - doctor
  - release_readiness
  - config_show
  - version
triggers:
  - lab checklist
  - release readiness
  - doctor
  - version
requires_confirmation: []
forbidden:
  - network_changes_from_doctor
---

# Lab and Release Skill

Use lab and release tools to inspect readiness, configuration, version, and lab validation state. Doctor and readiness do not make network changes.
