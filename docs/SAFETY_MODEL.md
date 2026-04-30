# Safety Model

Network Assistant is local-first and intentionally conservative.

## Local Network Restrictions

- Scanning is limited to local/private networks.
- Public IP scanning is blocked by safety policy.
- Built-in and Nmap CIDR scans are limited to `/24` or smaller.
- Nmap is optional and controlled: only `ping`, `common-ports`, and `service-light` profiles are allowed.
- Raw Nmap flags, hostnames, public targets, vulnerability scripts, aggressive scans, UDP scans, and all-port scans are blocked.
- Documentation fetching is explicit and disabled by default.

## Command Allowlists

- Read-only device commands are allowlisted by platform.
- Dangerous patterns are blocked before command execution.
- Snapshot commands are read-only and policy-checked.
- `/export terse` is allowed for MikroTik snapshots; `/export file` and `/import` are blocked.

## Planning Lifecycle

Configuration changes use this lifecycle:

```text
plan -> review -> approve -> preflight -> execute -> verify -> save/rollback
```

The lifecycle exists to prevent accidental device changes.

DeepSeek-generated custom Cisco IOS and MikroTik RouterOS plans use the same lifecycle. DeepSeek may draft precheck, proposed, rollback, and verification commands, but Python remains the safety controller and executor. Generated commands are classified before approval/preflight/execution. Security-abuse commands are blocked, and disruptive routing/firewall/NAT/DHCP/management commands require double confirmation.

## Plugin Tool Factory

Generated plugin tools are pure local helpers, not execution adapters. They are limited to these categories:

- planner
- parser
- validator
- reporter
- diagnostic

Plugins are saved to `plugins/pending` first. Pending plugins never run. Static validation checks syntax, required metadata, safe tool names, category/risk values, forbidden imports, forbidden calls, top-level side effects, and code size. Approval is required before a plugin moves to `plugins/approved` and becomes runnable.

Generated plugins may not open SSH, use sockets, call subprocess, install packages, read credentials, read `.env`, write arbitrary files, call external APIs, call the LLM, or modify devices directly. Planner plugins may produce proposed commands, rollback commands, and verification commands, but execution must go through the existing `ChangePlan` lifecycle.

## Tool and Skill Selection

The agent uses a structured Tool Capability Index and operational skill files before any LLM/plugin fallback. Router connection, scanning, diagnostics, topology, snapshots, knowledge, and governed planning requests must use existing tools when available.

Clearly non-network requests are refused before LLM planning. Plugin generation is only offered for network-related reusable planner/parser/validator/reporter/diagnostic tools when existing tools, approved plugins, and custom ChangePlan generation are not enough.

Task chaining is allowed for safe follow-up display and summary steps, such as `scan_network -> show_devices` or `build_topology -> show_topology`. Execution, save, and rollback are never auto-run as follow-up tools.

## Approval and Confirmation

- Plans require human review and approval before execution.
- Execution requires exact confirmation: `EXECUTE PLAN <id>`.
- Cisco save requires exact confirmation: `SAVE CONFIG PLAN <id>`.
- Rollback requires exact confirmation: `ROLLBACK PLAN <id>`.

## Preflight

Preflight verifies stored or refreshed read-only evidence before execution.

- Plans with missing evidence warn or fail.
- Plans with unsafe commands fail.
- Plans with topology-aware high-risk warnings can be downgraded or blocked.

## Snapshots

- Real execution captures a pre-change snapshot before config commands are applied.
- Execution is blocked if the pre-change snapshot fails.
- Post-change and rollback snapshots are attempted and logged.
- Snapshot export and restore guidance are informational only.

## Verify and Rollback

- Execution runs read-only post-checks.
- Failed verification triggers automatic rollback where supported.
- Manual rollback remains available through direct CLI confirmation.
- RouterOS changes are persistent immediately, so rollback is especially important.

## Agent and Chat Boundaries

- Low-risk actions can run in agent mode.
- Medium-risk actions require confirmation in agent mode.
- High-risk actions such as execute/save/rollback are blocked from chat/agent and require direct CLI confirmation.
- Controlled Nmap scans are medium-risk and require confirmation in agent mode. `nmap check` is low-risk.
- Custom generated plans are high-risk. Agent mode must show the plan, ask approval, run preflight, capture a backup snapshot, require exact execution confirmation, verify, and roll back on failed verification.
- Plugin generation is medium-risk and requires confirmation. Plugin approval is separate from generation, and approved plugins still cannot bypass plan execution gates.

## Integration Test Gates

- Integration tests are skipped by default.
- `RUN_INTEGRATION_TESTS=true` is required to run real lab integration tests.
- `ALLOW_REAL_CONFIG_TESTS=true` is required for real config execution.
- `ALLOW_REAL_DHCP_TESTS=true` is additionally required for real MikroTik DHCP execution.
