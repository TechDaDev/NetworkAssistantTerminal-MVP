# Lab Validation Guide

## Purpose

Phase 16 is for proving the existing Cisco IOS VLAN and MikroTik RouterOS address execution paths in an isolated lab before adding any more write operations.

Do not run these validation steps against production routers, switches, or firewalls.

## Supported Lab Targets

- Cisco IOSv or IOSvL2 in GNS3 or EVE-NG for Cisco VLAN execution.
- MikroTik CHR in VirtualBox, GNS3, EVE-NG, or Proxmox for RouterOS address execution.
- The Network Assistant host on the same private lab subnet.

## Suggested IP Plan

```text
Assistant host: 192.168.88.30
MikroTik CHR:  192.168.88.10
Cisco IOSvL2:  192.168.88.20
Gateway:       192.168.88.1
```

Keep this lab on an isolated host-only, NAT, or dedicated virtual network.

## MikroTik CHR Lab Setup

1. Create a MikroTik CHR VM and attach it to the lab network.
2. Give it a management address such as `192.168.88.10/24`.
3. Enable SSH for the lab account.
4. Confirm the lab account can run read-only commands:

```bash
ssh admin@192.168.88.10
/interface print
/ip address print
```

5. Do not test on your home gateway or production edge router.

## Cisco IOSv/IOSvL2 Lab Setup

1. Add an IOSvL2 node in GNS3 or EVE-NG.
2. Put a management interface on `192.168.88.20/24`.
3. Enable SSH and local authentication.
4. Confirm the lab account can run:

```text
show vlan brief
show interfaces status
show interfaces trunk
```

5. Use non-production VLAN IDs such as `30` or `40`.

## Required Credentials

Create a credential encryption key first:

```bash
python main.py security generate-key
```

Add the key to `.env`:

```env
CREDENTIAL_SECRET_KEY=your-generated-key
```

Then add lab credentials:

```bash
python main.py credentials add 192.168.88.10
python main.py credentials add 192.168.88.20
```

Use platform hints:

```text
MikroTik CHR: mikrotik_routeros
Cisco IOSvL2: cisco_ios
```

## Validation Workflow

Run the checklist:

```bash
python main.py lab checklist
```

Discover and enrich lab devices:

```bash
python main.py scan
python main.py enrich
python main.py devices
```

Test credentials and collect read-only evidence:

```bash
python main.py credentials test 192.168.88.10
python main.py connect collect 192.168.88.10
python main.py lab validate-device 192.168.88.10

python main.py credentials test 192.168.88.20
python main.py connect collect 192.168.88.20
python main.py lab validate-device 192.168.88.20
```

## Cisco VLAN Execution Test

Create a Cisco VLAN plan:

```bash
python main.py plan vlan \
  --device 192.168.88.20 \
  --vlan-id 30 \
  --name LAB \
  --ports "Gi0/5-Gi0/10"
```

Review, approve, and preflight:

```bash
python main.py plan review <plan-id>
python main.py plan approve <plan-id>
python main.py plan preflight <plan-id> --refresh
python main.py lab validate-plan <plan-id>
python main.py plan execute <plan-id> --dry-run
```

Only in the isolated lab, execute with exact confirmation:

```bash
python main.py plan execute <plan-id>
```

When prompted, type:

```text
EXECUTE PLAN <plan-id>
```

Verify:

```bash
python main.py plan verify <plan-id>
python main.py plan execution-history <plan-id>
```

Do not save automatically. If you intentionally want to test save behavior:

```bash
python main.py plan save <plan-id>
```

When prompted, type:

```text
SAVE CONFIG PLAN <plan-id>
```

## MikroTik Address Execution Test

Create a MikroTik address plan:

```bash
python main.py plan mikrotik-address \
  --device 192.168.88.10 \
  --interface bridge \
  --address 192.168.50.1/24 \
  --comment "LAB gateway"
```

Review, approve, and preflight:

```bash
python main.py plan review <plan-id>
python main.py plan approve <plan-id>
python main.py plan preflight <plan-id> --refresh
python main.py lab validate-plan <plan-id>
python main.py plan execute <plan-id> --dry-run
```

Only in the isolated lab, execute with exact confirmation:

```bash
python main.py plan execute <plan-id>
```

When prompted, type:

```text
EXECUTE PLAN <plan-id>
```

RouterOS applies the address immediately. There is no separate save step:

```bash
python main.py plan save <plan-id>
```

Expected result: the command refuses and explains that MikroTik changes are persistent immediately.

## Rollback Test

Cisco rollback:

```bash
python main.py plan rollback <plan-id>
```

When prompted, type:

```text
ROLLBACK PLAN <plan-id>
```

MikroTik rollback:

```bash
python main.py plan rollback <plan-id>
```

When prompted, type:

```text
ROLLBACK PLAN <plan-id>
```

Confirm results:

```bash
python main.py plan verify <plan-id>
python main.py plan execution-history <plan-id>
```

## Negative Safety Tests

These tests should fail safely:

```bash
python main.py plan execute <plan-id>
```

Type the wrong confirmation phrase. Expected result: blocked.

```bash
python main.py plan preflight <draft-plan-id>
```

Expected result: blocked because the plan is not approved.

```bash
python main.py chat
```

Try:

```text
execute plan <id>
save plan <id>
rollback plan <id>
```

Expected result: chat refuses and points to direct CLI confirmation.

## Automated Offline Tests

Normal tests do not require real devices:

```bash
pytest
```

Optional real-device tests are marked and run explicitly:

```bash
pytest -m integration
```

They are skipped unless `RUN_INTEGRATION_TESTS=true` is set. Dry-run/read-only lab workflows:

```bash
RUN_INTEGRATION_TESTS=true pytest -m integration
```

Real config execution requires an isolated lab and another explicit flag:

```bash
RUN_INTEGRATION_TESTS=true ALLOW_REAL_CONFIG_TESTS=true pytest -m integration
```

MikroTik DHCP real execution requires a third explicit flag:

```bash
RUN_INTEGRATION_TESTS=true ALLOW_REAL_CONFIG_TESTS=true ALLOW_REAL_DHCP_TESTS=true pytest -m integration
```

Check integration readiness without network actions:

```bash
python main.py lab integration-check
```

Check SSH connectivity only:

```bash
python main.py lab integration-check --connect
```

Show stored lab-related plans, execution logs, and snapshot counts:

```bash
python main.py lab integration-report
```

See `docs/INTEGRATION_TESTING.md` for exact environment variables and commands.

## Troubleshooting

- If preflight returns `warning`, run `python main.py connect collect <ip>` and then preflight again.
- If credentials fail, verify SSH, username, password, platform hint, and lab reachability.
- If Cisco VLAN verification is ambiguous, inspect `show vlan brief` and `show interfaces status` output in command history.
- If MikroTik address verification is ambiguous, inspect `/ip address print` and `/interface print` output in command history.
- If a command is blocked, inspect the plan with `python main.py plan show <id>` and confirm it matches the supported template exactly.
