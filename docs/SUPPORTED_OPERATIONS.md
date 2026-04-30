# Supported Operations

## Supported Read-Only Operations

- Local/private network detection and safe scan
- Optional controlled Nmap scans with safe profiles only: `ping`, `common-ports`, and `service-light`
- DeepSeek-generated custom Cisco IOS and MikroTik RouterOS command plans saved as governed `ChangePlan` records
- Passive enrichment
- Read-only SSH collection through command allowlists
- Device diagnostics
- Command history and device reports
- Topology build/show/export/report
- Manual topology correction in the local database
- Snapshot list/show/export and restore guidance
- Local knowledge add/search/import/fetch-url when explicitly enabled
- DeepSeek `ask` using local context only when explicitly enabled
- Agent mode for policy-controlled low/medium-risk workflows
- Lab integration readiness and skipped-by-default integration tests

## Supported Controlled Execution

Execution is available only through approved plans, passed preflight, exact confirmation, strict command templates, snapshots, verification, and rollback logging.

- Cisco IOS VLAN plan execution
- Cisco IOS interface description execution
- Cisco IOS access-port execution
- MikroTik RouterOS IP address execution
- MikroTik RouterOS DHCP server execution
- DeepSeek-generated custom Cisco IOS and MikroTik RouterOS plan execution after approval, preflight, mandatory backup snapshot, exact confirmation, verification, and rollback-on-verification-failure

## Not Supported

- Arbitrary SSH commands
- LLM-generated command execution outside saved, validated, user-approved custom plans
- Firewall execution
- NAT execution
- Route execution
- Cisco trunk execution
- Cisco routing/ACL execution
- MikroTik firewall/route/NAT/bridge/VLAN execution
- Production restore automation
- Cisco `configure replace`
- MikroTik `/import` restore automation
- Chat/agent execution for high-risk actions
- Internet search from normal `ask`
- Raw Nmap execution, arbitrary Nmap flags, vulnerability scripts, aggressive scans, UDP scans, all-port scans, public targets, and hostname targets
- Credential theft, password bypass, exploit tooling, hidden downloads/imports, reset/reboot, or secret/user-management commands in generated custom plans
