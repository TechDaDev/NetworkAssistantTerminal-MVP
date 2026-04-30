# Tool Capability Index

The Tool Capability Index is a structured map of the agent’s built-in tools. It tells the agent and LLM planner what tools exist, when to use them, required inputs, risk level, forbidden uses, expected outputs, related tools, follow-up tools, and related skills.

The index is deterministic and sorted by `tool_name`. Its static version label is:

```text
TOOL_CAPABILITY_INDEX_VERSION: 1.0
```

## Commands

```bash
nat tools list
nat tools search "router"
nat tools show connect_collect_readonly
```

## Selection Order

The agent uses this order:

1. Network-only domain guard.
2. Deterministic intent parser.
3. Tool capability retrieval.
4. Skill retrieval.
5. Existing tool execution and task chaining.
6. Custom command plan generation for advanced config tasks.
7. Approved plugin tools.
8. Plugin generation only for reusable planner/parser/validator/reporter/diagnostic tools.

## Task Chaining

Tools can define follow-up tools so the agent completes the user’s outcome.

- `scan_network` chains to `show_devices`.
- Scan requests asking for a summary also chain to `diagnose_network`.
- Nmap scans chain to scan result/report display.
- `build_topology` chains to `show_topology` or `topology_report`.
- Plan creation chains to plan display and next lifecycle guidance.
- Execution, save, and rollback are never auto-run as follow-ups.

## LLM Planner Use

The LLM planner receives relevant retrieved tools, not an unstructured guess. It is instructed to prefer existing registered tools, use custom ChangePlans for advanced configuration, and use plugin generation only when a reusable plugin/tool is appropriate.

The static prompt prefix is stable and sorted to make provider-side prompt caching possible. Dynamic request data, session memory, inventory summaries, retrieved tools, and selected skill bodies are placed later.
