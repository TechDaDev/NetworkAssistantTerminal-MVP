---
skill_name: ssh_readonly_collection
display_name: SSH Read-Only Collection
description: Use this skill for credential-safe read-only SSH connectivity checks and allowlisted command collection on known devices, without allowing raw SSH command execution or configuration changes.
category: ssh_readonly
risk_level: medium
tools:
  - credentials_add_guidance
  - credentials_test
  - connect_test
  - connect_collect_readonly
triggers:
  - test ssh
  - test credentials
  - collect device info
  - read configuration
requires_confirmation:
  - credentials_test
  - connect_test
  - connect_collect_readonly
forbidden:
  - raw_ssh_command_execution
  - configuration_commands
---

# SSH Read-Only Collection Skill

Use saved encrypted credentials only. Run connection tests and allowlisted read-only collection commands. If credentials are missing, guide the user to add them.

Never run raw SSH commands, shell commands, or configuration commands.
