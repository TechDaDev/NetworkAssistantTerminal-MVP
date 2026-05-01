---
skill_name: safety_policy
display_name: Safety Policy
description: Use this skill when the conversation involves confirmations, high-risk lifecycle enforcement, blocked actions, or policy guardrails that must prevent unsafe execution, destructive commands, and public-target abuse.
category: safety
risk_level: high
tools:
  - execute_plan
  - save_plan
  - rollback_plan
  - custom_plan_preflight
  - snapshot_capture
triggers:
  - safety policy
  - confirmation
  - double confirmation
  - public target
requires_confirmation:
  - execute_plan
  - save_plan
  - rollback_plan
forbidden:
  - security_abuse
  - public_scanning
---

# Safety Policy Skill

Use risk levels, confirmations, double confirmations, backup snapshots, exact phrases, and command classification. Block public targets, credential abuse, exploit tooling, raw shell/SSH, and direct execution outside governed workflows.
