# Skill Registry

The skill registry loads operational Markdown playbooks from `skills/*.skill.md`. Each skill has YAML front matter plus a workflow body. Skills guide the agent and LLM planner; they do not grant permissions or bypass policy.

The skill index version label is:

```text
SKILL_INDEX_VERSION: 1.0
```

## Commands

```bash
nat skills list
nat skills search "router"
nat skills show router_connection
```

## Skill Format

Each skill includes:

- `skill_name`
- `display_name`
- `category`
- `risk_level`
- `tools`
- `triggers`
- `requires_confirmation`
- `forbidden`

The body explains the operational workflow and safety boundaries.

## Retrieval

Skill retrieval uses deterministic scoring:

- exact trigger phrase matches
- keyword overlap
- related tool overlap
- category matches

No embeddings are required in this phase.

## Network-Only Guard

The agent rejects clearly non-network requests before LLM planning. It specializes in local network operations: routers, switches, topology, scanning, diagnostics, backups, and governed configuration workflows.

## Plugin Fallback

Plugin generation is not a default fallback. It is only offered when the task is network-related, no existing tool or approved plugin fits, custom ChangePlan generation is not enough, and the request is suitable for a reusable planner/parser/validator/reporter/diagnostic plugin.
