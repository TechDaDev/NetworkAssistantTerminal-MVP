# Network Assistant

Network Assistant is a safe local terminal tool for a network technician. The current terminal MVP covers local network discovery, common service detection, device enrichment, SQLite inventory storage, and local knowledge search.

## Installable CLI

Development install:

```bash
pip install -e .
network-assistant init
network-assistant doctor
nat agent
nat scan
nat nmap check
nat topology build
```

The direct Python entry point still works:

```bash
python main.py --help
python main.py version
```

Release-readiness helpers:

```bash
nat init
nat doctor
nat config show
nat config paths
```

`config show` never prints API keys, credential keys, or passwords.

## Current Scope

This version can:

- Detect the active network interface, local IP, subnet/CIDR, gateway, and MAC address.
- Refuse public networks and networks larger than `/24`.
- Discover live hosts on the detected local private subnet.
- Scan only common management/service ports on discovered live hosts.
- Optionally run controlled Nmap profiles against private/local targets when the system `nmap` binary is installed.
- Generate honest device/vendor/type guesses from simple rules.
- Enrich stored devices with passive facts such as MAC vendor hints, HTTP titles, SSH banners, gateway status, and SNMP port notes.
- Store scan-derived observations in `DeviceObservation`.
- Store reusable manual vendor/model knowledge in `DeviceKnowledge`.
- Search local knowledge with SQLite FTS5 when available, with SQL fallback.
- Store local SSH credentials encrypted with a user-provided Fernet key.
- Test read-only SSH access to known devices.
- Run only allowlisted read-only commands and save command output history.
- Collect safe read-only device profiles for Cisco IOS, MikroTik RouterOS, and Linux SSH targets.
- Ask DeepSeek read-only questions over stored local inventory, observations, command history previews, scan summaries, and local knowledge.
- Run guided local diagnostics for the network, devices, management/service ports, and private-IP connectivity.
- Start a localhost-only API server and use a Matrix-style terminal chat client.
- Create local configuration change plans with proposed and rollback commands.
- Create DeepSeek-generated custom Cisco IOS and MikroTik RouterOS command plans that are saved, validated, approved, backed up, executed, verified, and rolled back through the existing lifecycle.
- Generate pure local plugin tools for planner, parser, validator, reporter, and diagnostic tasks, then validate and approve them before use.
- Use a structured tool capability index and operational skill registry so the agent can select one best-fit skill first, then one allowed tool, chain follow-up actions, and avoid plugin generation for normal router/scanning workflows.
- Review, approve, reject, archive, and preflight-check change plans before execution eligibility.
- Execute only approved, preflight-passed Cisco IOS VLAN plans and MikroTik address plans through an exact confirmation gate.
- Verify executed plans, explicitly save Cisco IOS config with `write memory`, and manually rollback supported plans with confirmation.
- Validate Cisco IOSv/IOSvL2 and MikroTik CHR lab readiness without running SSH or executing plans.
- Run an offline pytest safety suite for command validators, policy blocks, chat refusals, and URL/LLM safety.
- Run an interactive skill-first agent mode for safe natural-language network tasks.
- Build evidence-based local topology snapshots from inventory, gateway, CDP/LLDP, and ARP evidence.
- Add local-only manual topology nodes, edges, and notes to correct or annotate topology snapshots.
- Import, store, search, and show reusable local device knowledge documents for read-only RAG context.
- Save scan results to `data/network_assistant.db`.
- Print clean terminal reports.

## OpenClaw-Like Skill Selection

Natural-language routing in agent mode is now skill-first:

1. Domain/safety guards run first.
2. Relevant skills are retrieved from `skills/*.skill.md`.
3. Relevant tools are retrieved from the tool capability index.
4. The planner selects exactly one skill and one tool from known options.
5. Only the selected skill body is loaded for execution context.
6. Policy remains the final authority before execution.

Deterministic parsing is still used for explicit CLI-style commands, emergency safety blocks, and fallback when LLM planning is disabled.

Trace mode (`trace on`) shows candidate skills/tools, selected skill/tool, planner reason, and raw payloads for debugging. Normal mode shows only human-readable summaries and tables.

To add a new skill, include strong YAML front matter fields (`skill_name`, `display_name`, `description`, `category`, `risk_level`, `tools`, `triggers`, `requires_confirmation`, `forbidden`) and keep the description focused on real user request language.

This version does not:

- Provide a web dashboard.
- Log in automatically or without user-provided credentials.
- Guess passwords or brute force credentials.
- Exploit vulnerabilities.
- Change device configuration outside the narrow Cisco IOS VLAN and MikroTik address execution paths.
- Let DeepSeek or any other LLM execute tools or change devices.
- Use internet search for device documentation or enrichment.
- Guess, brute force, or retry passwords.
- Run non-allowlisted commands.
- Let the LLM scan, connect to devices, run commands, ask for passwords, search the internet, or modify configurations.
- Run SSH or configuration commands from diagnostic workflows.
- Bind the local server to external interfaces or provide remote/multi-user access.
- Execute configuration plans or call Netmiko configuration methods outside the controlled config executor.
- Execute arbitrary plans, LLM-generated commands, routing changes, firewall changes, trunk changes, MikroTik firewall/DHCP/route/bridge/VLAN changes, or startup-config saves.
- Save configuration automatically after execution.
- Treat lab validation commands as permission to execute anything.
- Let agent mode run arbitrary shell, SSH, RouterOS, Cisco config, or LLM-generated commands.
- Run raw Nmap commands, arbitrary Nmap flags, vulnerability scripts, aggressive scans, UDP scans, all-port scans, public-IP scans, or hostname scans.
- Let DeepSeek directly open SSH or execute commands. Generated custom commands must be saved as a `ChangePlan` and pass classification, approval, preflight, backup, confirmation, verification, and logging.
- Let generated plugin tools open SSH, call subprocess, access sockets, read credentials, install packages, call external APIs, write arbitrary files, or modify devices directly.
- Answer clearly unrelated non-network requests such as poems, recipes, images, biology summaries, or general chatbot tasks.
- Execute, save, rollback, delete credentials, or delete knowledge from agent mode.
- Treat ARP or same-subnet adjacency as proof of physical cabling.

## Installation

Use Python 3.12 or newer.

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Generate a local credential encryption key and place it in `.env`:

```bash
python main.py security generate-key
```

```env
CREDENTIAL_SECRET_KEY=your-generated-key
```

DeepSeek reasoning is disabled by default. To use `ask`, add:

```env
LLM_ENABLED=true
DEEPSEEK_API_KEY=your-deepseek-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
```

Documentation fetching is disabled by default. To explicitly fetch public vendor docs into local knowledge, add:

```env
DOC_FETCH_ENABLED=true
DOC_FETCH_ALLOW_NON_OFFICIAL=false
DOC_FETCH_TIMEOUT_SECONDS=15
```

Some ARP discovery methods may require sudo/admin privileges:

```bash
sudo python main.py scan
```

The app still tries fallback discovery without sudo.

Nmap is optional and is detected as a system binary:

```bash
sudo apt install nmap
python main.py nmap check
```

The Nmap integration is controlled, not a terminal wrapper. Supported commands are:

```bash
python main.py nmap check
python main.py nmap scan-local --profile ping
python main.py nmap scan-local --profile common-ports
python main.py nmap scan-host 192.168.88.1 --profile common-ports
python main.py nmap scan-device 192.168.88.1 --profile service-light
```

Allowed profiles are `ping`, `common-ports`, and `service-light`. Targets must be private IPs or private CIDRs of `/24` or smaller. Results are saved to the existing inventory and port tables.

## Usage

```bash
python main.py detect
python main.py scan
python main.py devices
python main.py report
python main.py reset-db
python main.py enrich
python main.py device 192.168.88.1
python main.py update-device 192.168.88.1 --vendor MikroTik --model "hEX RB750Gr3" --type router
python main.py knowledge add
python main.py knowledge import-file docs/mikrotik.md --vendor MikroTik --doc-type command_reference --tags "routeros,ssh" --trusted
python main.py knowledge list
python main.py knowledge show 1
python main.py knowledge search "mikrotik ssh commands"
python main.py knowledge delete 1
python main.py knowledge fetch-url https://help.mikrotik.com/docs/ --vendor MikroTik --model "hEX RB750Gr3" --doc-type command_reference --trusted
python main.py knowledge fetch-docs --vendor Cisco --model "Catalyst 2960"
python main.py security generate-key
python main.py credentials add 192.168.88.1
python main.py credentials list
python main.py credentials test 192.168.88.1
python main.py credentials delete 192.168.88.1
python main.py connect test 192.168.88.1
python main.py connect collect 192.168.88.1
python main.py command run 192.168.88.1 "show version"
python main.py command history 192.168.88.1
python main.py ask "Summarize my latest scan"
python main.py ask "Which devices have management ports open?"
python main.py diagnose network
python main.py diagnose device 192.168.88.20
python main.py diagnose management-ports
python main.py diagnose connectivity 192.168.88.1
python main.py serve
python main.py chat
python main.py agent
python main.py agent --dry-policy
python main.py agent logs
python main.py agent logs show 1
python main.py plan vlan --device 192.168.88.20 --vlan-id 30 --name LAB --ports "Gi0/5-Gi0/10"
python main.py plan cisco-description --device 192.168.88.20 --interface Gi0/5 --description "LAB-PC-01"
python main.py plan cisco-access-port --device 192.168.88.20 --interface Gi0/5 --vlan-id 30 --description "LAB-PC-01"
python main.py plan mikrotik-address --device 192.168.88.1 --interface bridge --address 192.168.50.1/24 --comment "LAB gateway"
python main.py plan mikrotik-dhcp --device 192.168.88.1 --name lab-dhcp --interface bridge --network 192.168.50.0/24 --gateway 192.168.50.1 --pool-name lab-pool --pool-range 192.168.50.100-192.168.50.200 --dns 8.8.8.8,1.1.1.1 --comment "LAB DHCP"
python main.py plan list
python main.py plan show 1
python main.py plan review 1
python main.py plan approve 1
python main.py plan reject 1 --note "not needed"
python main.py plan archive 1
python main.py plan preflight 1
python main.py plan preflight 1 --refresh
python main.py plan execute 1 --dry-run
python main.py plan execute 1
python main.py plan execution-history 1
python main.py plan verify 1
python main.py plan save 1
python main.py plan rollback 1
python main.py lab checklist
python main.py lab validate-device 192.168.88.10
python main.py lab validate-plan 1
python main.py topology build
python main.py topology show
python main.py topology export --format mermaid
python main.py topology export --format json
python main.py topology export-file --format mermaid --output topology.md
python main.py topology export-file --format json --output topology.json
python main.py topology export-file --format html --output topology.html
python main.py topology export-file --format html --output topology-offline.html --offline
python main.py topology report --output network_topology_report.md
python main.py topology explain
python main.py topology risk-check --plan-id 1
python main.py topology manual-node add --key core-switch --label "Core Switch" --type switch --ip 192.168.88.2
python main.py topology manual-edge add --source gateway_192_168_88_1 --target core-switch --relation manual --label "uplink ether2"
python main.py topology manual-note add --target-type node --target-key core-switch --note "Located in lab rack"
python main.py topology manual-node list
python main.py topology manual-edge list
python main.py topology manual-note list
python main.py topology rebuild-with-manual
python main.py plugin generate --goal "create a local report from device facts" --category reporter
python main.py plugin list
python main.py plugin show safe_reporter
python main.py plugin validate safe_reporter
python main.py plugin approve safe_reporter
python main.py plugin run safe_reporter --input-json '{}'
python main.py plugin disable safe_reporter
python main.py tools list
python main.py tools search router
python main.py tools show router_connect_workflow
python main.py skills list
python main.py skills search router
python main.py skills show router_connection
pytest
pytest -m integration
```

## Safety Rules

Phase 1 scans only detected private local networks:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

Networks larger than `/24` are blocked. Public IP ranges are blocked. The scanner only performs discovery and checks these common ports:

```text
22, 23, 53, 80, 443, 8080, 8443, 161, 8291, 8728, 8729, 445, 139, 3389
```

Read-only device access is also constrained. Commands must match the local allowlist in `app/command_policy.py`, and dangerous patterns such as `configure`, `write`, `erase`, `delete`, `reload`, `reboot`, `shutdown`, `set`, `add`, `remove`, `password`, `copy`, `format`, and `reset` are blocked.

The Phase 4 DeepSeek layer is reasoning-only. It builds compact context from local SQLite data, redacts likely secrets, and sends that context to DeepSeek only when `LLM_ENABLED=true` and `DEEPSEEK_API_KEY` is configured. It does not execute scans, connections, SSH commands, or configuration changes.

Phase 5 diagnostics are guided workflows. They analyze existing SQLite data and only run explicitly safe checks such as private/local ping in `diagnose connectivity`. They do not perform SSH login, command execution, port scanning, configuration changes, or LLM calls automatically.

Phase 6 adds a localhost-only server on `127.0.0.1:8765` and a Matrix-style terminal chat client. Start the server in one terminal:

```bash
python main.py serve
```

Then open the chat console in another terminal:

```bash
python main.py chat
```

Supported chat examples:

```text
show devices
show device 192.168.88.20
scan network
enrich devices
diagnose network
diagnose 192.168.88.20
diagnose management-ports
diagnose connectivity 192.168.88.1
report latest
knowledge list
knowledge search routeros ssh
show knowledge 1
fetch docs vendor=MikroTik model=hEX url=https://help.mikrotik.com/docs/
ask Which devices need attention?
summarize latest scan
plan vlan device=192.168.88.20 vlan=30 name=LAB ports=Gi0/5-Gi0/10
plan cisco description device=192.168.88.20 interface=Gi0/5 description=LAB-PC-01
plan cisco access-port device=192.168.88.20 interface=Gi0/5 vlan=30 description=LAB-PC-01
plan mikrotik address device=192.168.88.1 interface=bridge address=192.168.50.1/24 comment=LAB
plan mikrotik dhcp device=192.168.88.1 name=lab-dhcp interface=bridge network=192.168.50.0/24 gateway=192.168.50.1 pool-name=lab-pool pool-range=192.168.50.100-192.168.50.200 dns=8.8.8.8,1.1.1.1 comment=LAB
plans
show plan 1
review plan 1
approve plan 1
reject plan 1 reason=not-needed
archive plan 1
preflight plan 1
preflight plan 1 refresh=true
execute plan 1
save plan 1
rollback plan 1
exit
```

The server reuses the same safe services as the CLI. It does not add automatic SSH, automatic internet search, multi-user auth, or a web dashboard. State-changing plan endpoints require the same confirmation gates as the CLI, and documentation fetching still requires explicit fetch endpoints.

Phase 7 introduced Cisco VLAN planning. VLAN plans generate proposed Cisco IOS commands, rollback commands, validation findings, risk level, and status. Plans are saved locally in SQLite and always display `PLAN ONLY -- NO COMMANDS EXECUTED` until they pass later lifecycle gates.

Phase 8 adds a formal review and approval lifecycle. Plans can be reviewed, approved, rejected, and archived, with approval history stored in SQLite. Approval requires explicit CLI confirmation and still does not execute commands. Chat mode will not silently approve plans; it tells you to use the CLI confirmation command.

Phase 9 adds preflight validation for approved plans. Preflight checks the saved plan, rollback commands, safety rules, credentials presence, and stored read-only evidence before a plan can be considered ready for any future execution phase. `--refresh` may run only the existing allowlisted read-only collection through saved credentials, then re-check the plan. Preflight always displays `PREFLIGHT ONLY -- NO CONFIGURATION EXECUTED`.

Phase 10 adds controlled execution for Cisco IOS VLAN plans only. Execution is blocked unless the plan is approved, preflight status is `passed`, the device has Cisco IOS credentials, proposed and rollback commands pass the strict VLAN template, and the user types the exact phrase `EXECUTE PLAN <id>`. Dry-run prints the commands and executes nothing. Real execution logs pre-checks, execution output, post-checks, rollback output, and errors in SQLite. It does not run from chat mode, does not save running-config/startup-config, and does not execute routing, firewall, trunk, MikroTik, arbitrary, or LLM-generated commands.

Phase 11 adds post-execution verification, explicit save, and manual rollback for Cisco IOS VLAN plans. `plan verify` runs only read-only show commands. `plan save` requires plan status `executed`, latest verification status `verified`, and the exact phrase `SAVE CONFIG PLAN <id>`, then runs only `write memory`. `plan rollback` requires the exact phrase `ROLLBACK PLAN <id>` and applies only the validated rollback commands. Chat mode refuses save and rollback requests and points to direct CLI confirmation.

Phase 12 upgrades local knowledge into a SQLite FTS-backed RAG foundation. Knowledge documents can be typed as `vendor_note`, `model_note`, `command_reference`, `reset_procedure`, `connection_guide`, `troubleshooting_note`, or `safety_note`. `ask` includes the top relevant local knowledge notes as separate user-added context, not live device evidence. Knowledge is informational only: it is never treated as permission to execute commands and never triggers internet search.

Phase 13 adds explicit internet documentation enrichment for local knowledge. Internet access is allowed only through `knowledge fetch-url` and the placeholder `knowledge fetch-docs` command when `DOC_FETCH_ENABLED=true`. Fetching blocks localhost, private IPs, non-HTTP schemes, and non-official sources unless `DOC_FETCH_ALLOW_NON_OFFICIAL=true`. Fetched documents are summarized if DeepSeek is enabled, otherwise saved as extracted text summaries, then indexed into local knowledge. `ask`, diagnostics, plans, and chat do not browse automatically.

Phase 14 adds MikroTik RouterOS planning. `plan mikrotik-address` creates a local plan to add an IPv4 address to a RouterOS interface and generates precise rollback text. Stored `/interface print` and `/ip address print` outputs are used for validation when available; otherwise the plan warns that read-only evidence is missing.

Phase 15 adds controlled MikroTik address preflight and execution. MikroTik execution is limited to `mikrotik_address` plans, requires approval, `preflight_status=passed`, saved `mikrotik_routeros` credentials, strict command-template validation, and the exact phrase `EXECUTE PLAN <id>`. RouterOS applies changes immediately, so `plan save` refuses for MikroTik plans and manual rollback remains gated by `ROLLBACK PLAN <id>`. No MikroTik firewall, DHCP, route, bridge, VLAN, arbitrary RouterOS, chat-triggered, or LLM-generated execution is supported.

Phase 16 adds lab validation and an offline safety test harness. See `docs/LAB_VALIDATION.md` for a practical Cisco IOSv/IOSvL2 and MikroTik CHR workflow. The `lab` commands inspect stored inventory, credentials, command history, plan status, preflight status, and dry-run readiness without starting SSH sessions or executing changes. Normal `pytest` runs only offline tests; future real-device tests should be marked `integration` and run explicitly with `pytest -m integration`.

Phase 17 adds an interactive deterministic agent mode:

```bash
python main.py agent
```

Agent mode maps natural language to existing safe tools. Low-risk actions such as showing devices, reports, plans, diagnostics from stored data, knowledge search, and lab checklist run directly. Medium-risk actions such as scanning, enrichment, read-only collection, preflight refresh, documentation fetch, and plan creation require yes/no confirmation. High-risk actions such as plan execute, plan save, plan rollback, credential deletion, and knowledge deletion are refused from agent mode and replaced with the exact direct CLI command that requires its own confirmation gate. Agent mode does not run arbitrary SSH, shell, Cisco config, RouterOS, or LLM-generated commands.

Phase 18 hardens agent mode with audit logging and policy dry-run:

```bash
python main.py agent --dry-policy
python main.py agent logs
python main.py agent logs show <id>
```

Every agent input is logged with a generated session ID, parsed intent, tool name, risk level, policy decision, confirmation state, execution state, and result summary. Logs redact likely passwords, API keys, tokens, private keys, and secret strings. Dry-policy mode parses and evaluates policy but executes no tools, which is useful for checking how a request would be classified. Raw SSH, shell, destructive reset/reboot/erase, public-IP scan, credential attack, and exploitation requests are blocked and logged.

Phase 19A adds read-only topology mapping:

```bash
python main.py topology build
python main.py topology show
python main.py topology export --format mermaid
python main.py topology export --format json
python main.py topology explain
```

Topology snapshots are evidence-based. The builder uses stored scan data, gateway information, inventory devices, MAC addresses, device guesses, stored command outputs, Cisco CDP/LLDP output, and MikroTik ARP/interface output. CDP/LLDP links are higher-confidence neighbor evidence. ARP and same-subnet links are labeled as low or medium confidence and are not physical topology proof. If read-only collection is missing, topology confidence is limited; run `python main.py connect collect <ip>` on lab routers/switches with stored credentials to improve evidence.

Phase 22 adds shareable topology exports:

```bash
python main.py topology export-file --format mermaid --output topology.md
python main.py topology export-file --format json --output topology.json
python main.py topology export-file --format html --output topology.html
python main.py topology export-file --format html --output topology-offline.html --offline
python main.py topology report --output network_topology_report.md
```

File export reads an existing topology snapshot and writes Markdown, JSON, or standalone HTML. HTML can include Mermaid from a CDN or stay offline with Mermaid source plus tables. Existing files are not overwritten unless `--force` is provided. The server exposes topology export/report content but does not write files.

Phase 19B adds manual topology correction in the local database only:

```bash
python main.py topology manual-node add --key core-switch --label "Core Switch" --type switch --ip 192.168.88.2
python main.py topology manual-edge add --source gateway_192_168_88_1 --target core-switch --relation manual --label "uplink ether2"
python main.py topology manual-note add --target-type node --target-key core-switch --note "Located in lab rack"
python main.py topology rebuild-with-manual
```

Manual topology data supplements discovered evidence and is marked as manual confirmation, not auto-discovered. Delete commands require direct CLI confirmation. Agent and chat modes do not silently delete manual topology data.

Phase 20 adds Cisco IOS interface planning:

```bash
python main.py plan cisco-description --device 192.168.88.20 --interface Gi0/5 --description "LAB-PC-01"
python main.py plan cisco-access-port --device 192.168.88.20 --interface Gi0/5 --vlan-id 30 --description "LAB-PC-01"
```

These plans generate proposed commands and basic rollback commands for a single interface. Stored `show interfaces status`, `show interfaces trunk`, and `show vlan brief` output is used for validation when available. Interface range input is rejected.

Phase 21 adds controlled preflight, execution, verification, save, and rollback support for `cisco_interface_description` and `cisco_access_port` plans. Execution requires approved status, `preflight_status=passed`, saved `cisco_ios` credentials, strict command-template validation, and the exact phrase `EXECUTE PLAN <id>`. Interface execution does not save configuration automatically. `plan save` still requires a successful verification and the exact phrase `SAVE CONFIG PLAN <id>`. Rollback is basic and may not restore previous interface description or VLAN if previous state was unknown.

Phase 23 adds MikroTik DHCP server planning only:

```bash
python main.py plan mikrotik-dhcp \
  --device 192.168.88.1 \
  --name lab-dhcp \
  --interface bridge \
  --network 192.168.50.0/24 \
  --gateway 192.168.50.1 \
  --pool-name lab-pool \
  --pool-range 192.168.50.100-192.168.50.200 \
  --dns 8.8.8.8,1.1.1.1 \
  --comment "LAB DHCP"
```

This creates a `mikrotik_dhcp_server` change plan with proposed RouterOS DHCP, pool, and network commands plus rollback text. It validates private network CIDR, gateway, pool range, DNS IPs, safe names, safe interface, and safe comment input. Stored `/interface print`, `/ip pool print`, `/ip dhcp-server print`, `/ip dhcp-server network print`, and `/ip address print` output is used for warnings when available. MikroTik DHCP execution, preflight execution, verify, rollback execution, firewall, route, and arbitrary RouterOS commands are not supported in this phase.

Phase 24 adds preflight validation for `mikrotik_dhcp_server` plans only:

```bash
python main.py plan preflight <dhcp-plan-id>
python main.py plan preflight <dhcp-plan-id> --refresh
```

DHCP preflight requires approval, saved `mikrotik_routeros` credentials, strict DHCP command templates, rollback text, and stored or refreshed read-only evidence from `/interface print`, `/ip address print`, `/ip pool print`, `/ip dhcp-server print`, and `/ip dhcp-server network print`. `--refresh` runs only those read-only commands. Preflight can pass, warn, or fail based on interface presence, gateway evidence, existing pool names, existing DHCP server names, and existing DHCP network entries. DHCP execution, verify, save, and rollback remain unsupported.

Phase 25 adds topology-aware planning warnings:

```bash
python main.py topology risk-check --plan-id <plan-id>
```

Planning and preflight can now include warnings from local topology snapshots, manual topology notes, device inventory, known IPs, and interface-name heuristics. This is especially useful for MikroTik DHCP plans: the assistant warns if the pool overlaps known devices, if the target interface looks like WAN/uplink, if gateway evidence is weak, or if manual notes mark the target as infrastructure or “do not modify.” These checks do not run scans, SSH, DeepSeek, or configuration commands.

Phase 26 adds controlled execution for `mikrotik_dhcp_server` plans. Execution is allowed only after approval, `preflight_status=passed`, saved `mikrotik_routeros` credentials, strict DHCP command validation, and the exact phrase `EXECUTE PLAN <id>`. The executor runs read-only pre-checks, applies only the generated pool/DHCP/network commands, runs read-only post-checks, and automatically rolls back if verification fails. `plan verify` and `plan rollback` support DHCP plans with read-only checks and exact rollback confirmation. `plan save` refuses because RouterOS applies DHCP changes immediately. Chat and agent modes still refuse execute/save/rollback and point to direct CLI commands.

Phase 27 adds read-only pre-change backup snapshots before real execution:

```bash
python main.py snapshot list
python main.py snapshot list --device 192.168.88.1
python main.py snapshot list --plan-id 5
python main.py snapshot show <snapshot-id>
python main.py snapshot show <snapshot-id> --full
python main.py snapshot capture --plan-id 5 --type manual
```

Before controlled Cisco or MikroTik execution starts, the assistant captures a `pre_change` snapshot using read-only allowlisted commands. Execution is blocked if this snapshot fails. Successful execution attempts a `post_change` snapshot. Manual and automatic rollbacks capture `pre_rollback` and `post_rollback` snapshots. Cisco snapshots include running config and interface/VLAN evidence; MikroTik snapshots include `/export terse` plus relevant address/DHCP/interface evidence. `/export file`, config commands, save commands, and arbitrary SSH commands are not used for snapshots.

Phase 28 adds snapshot export and deterministic restore guidance:

```bash
python main.py snapshot export <snapshot-id> --format txt --output snapshot.txt
python main.py snapshot export <snapshot-id> --format json --output snapshot.json
python main.py snapshot export <snapshot-id> --format md --output snapshot.md
python main.py snapshot export <snapshot-id> --format md --output snapshot.md --force
python main.py snapshot restore-guidance <snapshot-id>
```

Exports support `txt`, `json`, and `md`. Existing files are not overwritten unless `--force` is provided. Restore guidance is informational only: it explains how to compare current state against the snapshot, shows linked rollback commands when available, warns against blind full-config restore, warns against MikroTik `/import`, and never runs SSH or restore commands.

Phase 29 adds a skipped-by-default real lab integration harness:

```bash
python main.py lab integration-check
python main.py lab integration-check --connect
python main.py lab integration-report
pytest -m integration
RUN_INTEGRATION_TESTS=true pytest -m integration
RUN_INTEGRATION_TESTS=true ALLOW_REAL_CONFIG_TESTS=true pytest -m integration
```

Integration tests target isolated Cisco IOSv/IOSvL2 and MikroTik CHR labs. They do not run by default. Real config tests require `ALLOW_REAL_CONFIG_TESTS=true`, and MikroTik DHCP real execution also requires `ALLOW_REAL_DHCP_TESTS=true`. See `docs/INTEGRATION_TESTING.md`.

Phase 30 packages the project as an installable CLI and adds release-readiness commands:

```bash
pip install -e .
network-assistant version
network-assistant init
network-assistant doctor
network-assistant config show
nat version
nat agent
```

Release documentation:

- `docs/SUPPORTED_OPERATIONS.md`
- `docs/SAFETY_MODEL.md`
- `docs/RELEASE_CHECKLIST.md`

Phase 34 adds the LLM plugin tool factory. Unsupported agent tasks can be turned into pending pure-Python local plugins after user confirmation. Generated plugins are limited to planner, parser, validator, reporter, and diagnostic categories. They are saved under `plugins/pending`, statically validated, and require explicit approval before moving to `plugins/approved`. Approved plugins may run through `nat plugin run`; pending plugins never run. Planner plugins can output proposed commands, rollback commands, and verification commands, but any device execution must still become a governed `ChangePlan`.

Phase 35 adds a tool capability index, operational skill registry, network-only domain guard, deterministic tool/skill retrieval, task chaining, router connection workflow, and cache-friendly planner prompt construction. `scan my network` now scans and returns discovered devices in the agent response. `connect to my router` uses the built-in gateway/read-only SSH workflow instead of plugin generation. Plugin generation is reserved for reusable network planner/parser/validator/reporter/diagnostic tools.

## Future Phases

Future phases can add embedding-based RAG, broader diagnostic workflows, UI, and more device-specific integrations after the local knowledge foundation is stable.
