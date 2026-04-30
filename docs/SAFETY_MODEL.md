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

## Integration Test Gates

- Integration tests are skipped by default.
- `RUN_INTEGRATION_TESTS=true` is required to run real lab integration tests.
- `ALLOW_REAL_CONFIG_TESTS=true` is required for real config execution.
- `ALLOW_REAL_DHCP_TESTS=true` is additionally required for real MikroTik DHCP execution.
