# Change Workflow

Network Assistant uses a gated lifecycle:

```text
plan -> review -> approve -> preflight -> execute -> verify -> save/rollback
```

## Plan

Plans generate proposed commands, rollback commands, validation findings, and risk notes. Creating a plan does not touch the device.

## Review and Approve

```bash
nat plan review <id>
nat plan approve <id>
```

Approval records a human decision. It does not execute commands.

## Preflight

```bash
nat plan preflight <id>
nat plan preflight <id> --refresh
```

Preflight validates stored or refreshed read-only evidence. `--refresh` runs only allowlisted read-only commands.

## Execute

```bash
nat plan execute <id> --dry-run
nat plan execute <id>
```

Real execution requires:

- approved plan
- `preflight_status=passed`
- supported plan type
- saved credentials
- strict command validation
- exact confirmation: `EXECUTE PLAN <id>`
- successful pre-change snapshot

## Verify

```bash
nat plan verify <id>
```

Verification runs read-only checks.

## Save and Rollback

Cisco IOS save is explicit:

```bash
nat plan save <id>
```

It requires exact confirmation: `SAVE CONFIG PLAN <id>`.

MikroTik RouterOS applies changes immediately and has no separate save step.

Rollback is explicit:

```bash
nat plan rollback <id>
```

It requires exact confirmation: `ROLLBACK PLAN <id>`.

## Cisco Notes

Supported execution includes VLAN creation, interface descriptions, and access-port assignment. Trunk, route, firewall, ACL, and arbitrary config execution are not supported.

## MikroTik Notes

Supported execution includes IP address and DHCP server plans. Firewall, route, NAT, bridge, VLAN, and arbitrary RouterOS execution are not supported.
