---
skill_name: mikrotik_operations
display_name: MikroTik Operations
description: Use this skill when the user asks for MikroTik planning tasks such as address or DHCP setup, failover, NAT, firewall, or routing changes that must be performed through governed plans and confirmations.
category: planning
risk_level: high
tools:
  - create_mikrotik_address_plan
  - create_mikrotik_dhcp_plan
  - custom_plan_generate
  - custom_plan_preflight
  - execute_plan
  - verify_plan
  - rollback_plan
triggers:
  - configure mikrotik
  - configure dhcp
  - configure mikrotik load balancing
  - setup failover
  - add nat rule
  - add firewall rule
requires_confirmation:
  - custom_plan_generate
  - execute_plan
  - rollback_plan
forbidden:
  - arbitrary_routeros_commands
---

# MikroTik Operations Skill

Use fixed MikroTik address/DHCP plan tools when available. Use custom RouterOS ChangePlans for advanced load balancing, failover, NAT, firewall, and routing. RouterOS changes are immediate; there is no save step. Backup, verification, and rollback are mandatory for execution.
