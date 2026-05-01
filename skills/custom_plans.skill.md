---
skill_name: custom_plans
display_name: Custom ChangePlans
description: Use this skill when the request is an advanced Cisco IOS or MikroTik RouterOS change that is not covered by fixed planners, and the agent must generate a governed custom ChangePlan with review, preflight, and execution safeguards.
category: custom_plan
risk_level: high
tools:
  - custom_plan_generate
  - custom_plan_show
  - custom_plan_review
  - custom_plan_approve
  - custom_plan_preflight
  - execute_plan
  - verify_plan
  - rollback_plan
triggers:
  - configure mikrotik load balancing
  - setup failover
  - add static route
  - add nat rule
  - add firewall rule
  - configure cisco acl
requires_confirmation:
  - custom_plan_generate
  - execute_plan
forbidden:
  - plugin_generation_for_config_when_custom_plan_fits
---

# Custom ChangePlans Skill

Use custom plans for advanced network configuration tasks not covered by fixed tools. Ask missing-input questions instead of guessing. Show policy summary, risk summary, proposed commands, rollback, and verification commands. Execute only through approval, preflight, backup snapshot, exact confirmation, verification, logging, and rollback.
