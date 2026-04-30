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
generate plugin for parsing interface status
```

## Guided Workflows

- `workflow scan and diagnose`
- `workflow topology report`
- `prepare cisco access port`
- `prepare mikrotik dhcp`

Planning workflows create draft plans only. They do not review, approve, preflight, execute, save, or rollback.

## Plugin Tools

When the agent cannot satisfy a request with registered tools, it can ask permission to generate a pure local plugin. Generated plugins are saved as pending, statically validated, shown to the user, and require explicit approval before they become available.

Plugin tools are limited to planner, parser, validator, reporter, and diagnostic work. They cannot open SSH, run shell commands, call subprocess, access sockets, read credentials, install packages, call external APIs, or modify network devices directly.

If an approved planner plugin produces network commands, the agent must offer to save them as a normal `ChangePlan`. Device execution still goes through approval, preflight, snapshot, exact confirmation, verification, rollback, and logging.

## Risk Levels

- Low-risk actions run directly.
- Medium-risk actions ask for confirmation.
- High-risk actions are blocked and redirected to direct CLI.
- Plugin generation is medium-risk and requires confirmation. Plugin activation requires a second approval after validation.

Execution/save/rollback require direct CLI exact confirmation.

## Blocked Actions

Agent mode does not run arbitrary SSH, shell commands, raw plugin code, unapproved plugins, plan execution, config save, or rollback.
