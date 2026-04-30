# Plugin Tools

Plugin tools are pure local Python helpers generated for tasks that do not fit the built-in tool registry. They extend planning, parsing, validation, reporting, and diagnostics without giving generated code direct device or shell access.

## Allowed Categories

- `planner`: produces plan material such as proposed commands, rollback commands, verification commands, risk summary, and policy summary.
- `parser`: turns command output or local text into structured data.
- `validator`: checks supplied commands, plans, or evidence and returns findings.
- `reporter`: creates Markdown or text reports from local input data.
- `diagnostic`: analyzes provided evidence and returns findings or recommendations.

## Lifecycle

```text
generate -> pending -> validate -> approve -> approved -> run
```

Generated plugins are written to `plugins/pending/<tool_name>.py`. Pending plugins cannot run. Approval moves a validation-passed plugin to `plugins/approved/<tool_name>.py`. Disabled plugins move to `plugins/disabled`.

## Required Interface

Each plugin must define:

```python
TOOL_NAME = "safe_tool_name"
TOOL_VERSION = "0.1.0"
TOOL_DESCRIPTION = "Short description."
TOOL_CATEGORY = "reporter"
TOOL_RISK_LEVEL = "low"

INPUT_SCHEMA = {}
OUTPUT_SCHEMA = {
    "success": "bool",
    "summary": "str",
    "data": "dict",
    "warnings": "list[str]",
}

def run(inputs: dict) -> dict:
    return {"success": True, "summary": "ok", "data": {}, "warnings": []}
```

## Validation Rules

Static validation checks Python syntax, required constants, `run(inputs)`, safe tool names, allowed categories, allowed risk levels, forbidden imports, forbidden calls, top-level side effects, and code size.

Allowed imports are intentionally small: `re`, `json`, `ipaddress`, `math`, `statistics`, `datetime`, and `typing`.

Forbidden behavior includes SSH, sockets, subprocess, package installation, arbitrary file reads/writes, `.env` or credential access, external APIs, LLM calls, and direct router/switch configuration.

## Commands

```bash
nat plugin generate --goal "create a local report from device facts" --category reporter
nat plugin list
nat plugin show safe_reporter
nat plugin validate safe_reporter
nat plugin approve safe_reporter
nat plugin reject safe_reporter
nat plugin disable safe_reporter
nat plugin run safe_reporter --input-json '{}'
```

Medium and high risk plugin runs ask for confirmation unless `--yes` is used.

## Planner Output

Planner plugins can return proposed network commands in `data`. They still cannot execute those commands. If the output includes `platform`, `target_device_ip`, `proposed_commands`, `rollback_commands`, and `verification_commands`, the agent can offer to save it as a custom `ChangePlan`.

Once saved, the normal governed lifecycle applies: review, approve, preflight, backup snapshot, exact confirmation, execution, verification, rollback, and logging.
