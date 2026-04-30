# v1.0.0-rc2 Release Notes

Network Assistant v1.0.0-rc2 is a local-first terminal network assistant for lab and controlled local network operations.

## Included

- Installable CLI: `network-assistant` and `nat`
- Local scan and SQLite inventory
- Passive enrichment and diagnostics
- Encrypted credential storage
- Read-only SSH collection with command allowlists
- DeepSeek read-only reasoning over local context
- Local knowledge RAG with SQLite FTS
- Explicit documentation fetching
- Evidence-based topology mapping, manual correction, exports, and reports
- Config planning lifecycle
- Approval, preflight, exact confirmation, snapshots, verification, rollback
- Controlled Cisco VLAN/interface/access-port execution
- Controlled MikroTik address/DHCP execution
- Snapshot export and restore guidance
- Agent mode with audit logging, risk policy, and guided workflows
- Lab integration harness skipped by default
- Release commands: `init`, `doctor`, `config`, `release readiness`
- Added controlled optional Nmap integration with safe profiles, private-network enforcement, XML parsing, inventory saving, agent/chat/server routes, and doctor detection.

## Not Included

- Web dashboard
- Arbitrary SSH commands
- LLM autonomous execution
- Firewall, NAT, route, Cisco trunk, or MikroTik bridge/VLAN execution
- Production restore automation
- Internet search from normal `ask`

## Recommended Validation

```bash
nat doctor
nat release readiness
pytest
python -m compileall app tests
pytest -m integration
```

Real integration execution should be run only against isolated Cisco IOSv/IOSvL2 and MikroTik CHR labs.
