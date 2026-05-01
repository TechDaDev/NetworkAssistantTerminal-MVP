---
skill_name: cisco_operations
display_name: Cisco Operations
description: Use this skill when the user asks for Cisco switch or router configuration planning such as VLAN creation, access-port setup, interface description changes, routing, or ACL-related planning tasks that must follow the governed plan lifecycle.
category: planning
risk_level: high
tools:
  - create_cisco_vlan_plan
  - create_cisco_description_plan
  - create_cisco_access_port_plan
  - custom_plan_generate
  - custom_plan_preflight
  - execute_plan
  - verify_plan
  - save_plan
  - rollback_plan
triggers:
  - add vlan
  - configure access port
  - configure cisco static route
  - configure cisco acl
requires_confirmation:
  - custom_plan_generate
  - execute_plan
  - save_plan
  - rollback_plan
forbidden:
  - arbitrary_raw_commands
---

# Cisco Operations Skill

Use fixed Cisco plan tools when available. For advanced Cisco routing, ACLs, route maps, helper addresses, and interface work, use custom ChangePlan generation. Execution requires review, approval, preflight, backup snapshot, exact confirmation, verification, and rollback support.

Do not run arbitrary raw Cisco commands outside the governed lifecycle.
