# Agent Mode

Start the deterministic terminal agent:

```bash
nat agent
```

Dry policy mode parses and evaluates policy without running tools:

```bash
nat agent --dry-policy
```

## Examples

Inventory:

```text
show devices
show device 192.168.88.1
latest report
```

Diagnostics:

```text
diagnose network
inspect 192.168.88.1
show risky management ports
```

Topology:

```text
build topology
show topology
explain topology
workflow topology report
```

Knowledge:

```text
knowledge search routeros ssh
ask summarize latest scan
```

Planning:

```text
prepare cisco access port
prepare mikrotik dhcp
```

## Guided Workflows

- `workflow scan and diagnose`
- `workflow topology report`
- `prepare cisco access port`
- `prepare mikrotik dhcp`

Planning workflows create draft plans only. They do not review, approve, preflight, execute, save, or rollback.

## Risk Levels

- Low-risk actions run directly.
- Medium-risk actions ask for confirmation.
- High-risk actions are blocked and redirected to direct CLI.

Execution/save/rollback require direct CLI exact confirmation.

## Blocked Actions

Agent mode does not run arbitrary SSH, shell commands, LLM-generated commands, plan execution, config save, or rollback.
