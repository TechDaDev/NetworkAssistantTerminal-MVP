# Agent Mode

Start the deterministic terminal agent:

```bash
nat agent
```

Dry policy mode parses and evaluates policy without running tools:

```bash
nat agent --dry-policy
```

Trace mode for planner decisions:

```text
trace on
trace status
trace off
```

## Examples

Inventory:

```text
show devices
show device 192.168.88.1
latest report
what tools do you have?
what skills do you have?
```

Diagnostics:

```text
diagnose network
inspect 192.168.88.1
show risky management ports
scan my network
what is connected to my network
connect to my router
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

Plugin generation is not used for normal operational tasks. Router/gateway connection requests use the built-in `router_connect_workflow`; scan requests use `scan_network` and automatically show discovered devices. Advanced Cisco/MikroTik configuration requests use fixed planning tools or custom ChangePlan generation before plugins.

## Tools and Skills

```bash
nat tools list
nat tools search "router"
nat tools show router_connect_workflow
nat skills list
nat skills search "router"
nat skills show router_connection
```

The tool capability index describes available tools, inputs, risk, forbidden uses, and follow-up tools. Skill files are operational playbooks that guide tool selection and workflow chaining.

## Skill-First Selection Flow

Agent mode now follows an OpenClaw-like skill-first path for natural-language requests:

1. Run control command checks (`help`, `exit`, `clear`, `trace on/off/status`, tool/skill list).
2. Run domain/safety guards first (public scans, raw SSH/shell, destructive intent).
3. Retrieve relevant skill candidates from `skills/*.skill.md` using triggers, token overlap, and tool affinity.
4. Retrieve relevant tool candidates from the tool capability index.
5. Use the skill planner to choose exactly one skill and one registered tool.
6. Load only the selected skill body for execution context.
7. Validate the selected tool through agent policy before execution.
8. Render human-readable output; raw JSON is trace-only.

Deterministic parsing is still used for explicit CLI-like commands, emergency safety blocks, and non-LLM fallback.

## Trace Visibility

Normal output shows clean summaries, tables, and next safe actions.

Trace mode additionally shows:

- candidate skills
- candidate tools
- selected skill
- selected tool
- planner reason and confidence
- policy decision
- raw tool payload

## Adding a New Skill

Use YAML front matter with a strong natural-language description:

```yaml
---
skill_name: example_skill
display_name: Example Skill
description: Use this skill when the user asks for ...
category: diagnostics
risk_level: low
tools:
	- show_devices
triggers:
	- show devices
requires_confirmation: []
forbidden:
	- unsafe_action
---
```

Guidelines:

- Keep the description specific and request-oriented.
- List only tools that the skill is allowed to invoke.
- Include realistic trigger phrases users actually type.
- Keep forbidden intents explicit so planner and reviewers can enforce policy.

## Risk Levels

- Low-risk actions run directly.
- Medium-risk actions ask for confirmation.
- High-risk actions are blocked and redirected to direct CLI.
- Plugin generation is medium-risk and requires confirmation. Plugin activation requires a second approval after validation.

Execution/save/rollback require direct CLI exact confirmation.

## Blocked Actions

Agent mode does not run arbitrary SSH, shell commands, raw plugin code, unapproved plugins, plan execution, config save, or rollback. Clearly non-network requests are refused before LLM planning.
