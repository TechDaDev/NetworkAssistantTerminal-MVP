---
skill_name: router_connection
display_name: Router / Gateway Connection
category: ssh_readonly
risk_level: medium
tools:
  - detect_network
  - show_device
  - scan_network
  - enrich_devices
  - credentials_add_guidance
  - credentials_test
  - connect_test
  - connect_collect_readonly
  - router_connect_workflow
triggers:
  - connect to my router
  - connect to router
  - connect to gateway
  - login to router
  - inspect my router
  - inspect router
  - inspect gateway
  - check my router
  - check router
  - collect router info
  - collect gateway info
  - read router configuration
  - show router information
requires_confirmation:
  - scan_network
  - connect_collect_readonly
forbidden:
  - plugin_generation_for_router_connection
  - raw_ssh_command_execution
  - configuration_commands
---

# Router / Gateway Connection Skill

Use this skill when the user wants to connect to, inspect, check, log into, or collect information from their router or default gateway.

## Workflow

1. Detect the local gateway.
2. Treat the gateway as the likely router.
3. Check whether the gateway exists in inventory.
4. If missing, ask confirmation to run scan/enrich.
5. If found, show device summary.
6. Check whether saved credentials exist.
7. If credentials are missing, guide the user to run `nat credentials add <gateway-ip>`.
8. If credentials exist, ask confirmation for read-only SSH connection and collection.
9. Run only read-only connection/collection tools.

## Do Not

- Do not generate a plugin for router connection requests.
- Do not execute configuration commands.
- Do not run arbitrary SSH commands.

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
