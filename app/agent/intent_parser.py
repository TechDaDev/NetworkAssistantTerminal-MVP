from __future__ import annotations

import ipaddress
import re
import shlex

from app.agent.agent_models import ParsedIntent
from app.agent.session_memory import SessionMemory


def parse_intent(text: str, memory: SessionMemory | None = None) -> ParsedIntent:
    raw = text.strip()
    normalized = " ".join(raw.split())
    lowered = normalized.lower()
    phrase = lowered.rstrip("?.!")
    memory = memory or SessionMemory()

    if not normalized:
        return ParsedIntent("unknown", raw_text=raw)
    if lowered in {"help", "?"}:
        return ParsedIntent("help", raw_text=raw)
    if phrase in {"what tools do you have", "tools", "list tools", "show tools"}:
        return ParsedIntent("list_tools", raw_text=raw)
    if phrase in {"what skills do you have", "skills", "list skills", "show skills"}:
        return ParsedIntent("list_skills", raw_text=raw)
    if lowered in {"exit", "quit", "q"}:
        return ParsedIntent("exit", raw_text=raw)
    if lowered == "clear":
        return ParsedIntent("clear", raw_text=raw)
    if lowered == "status":
        return ParsedIntent("status", raw_text=raw)

    unsafe_reason = _unsafe_request_reason(lowered)
    if unsafe_reason:
        return ParsedIntent("blocked_request", {"reason": unsafe_reason, "text": normalized}, raw)

    blocked = _blocked_high_risk(lowered, memory)
    if blocked:
        return ParsedIntent(blocked[0], blocked[1], raw)

    if lowered in {"show devices", "list devices", "devices"}:
        return ParsedIntent("show_devices", raw_text=raw)
    if lowered in {"latest report", "show report", "report", "show latest report"}:
        return ParsedIntent("latest_report", raw_text=raw)
    if lowered in {"summarize latest scan", "summarize latest report"}:
        return ParsedIntent("ask", {"question": normalized}, raw)

    if lowered == "nmap check":
        return ParsedIntent("nmap_check", raw_text=raw)
    if lowered in {"nmap scan local", "nmap scan local common ports"}:
        return ParsedIntent("nmap_scan_local", {"profile": "common-ports"}, raw)
    if lowered == "nmap scan local ping":
        return ParsedIntent("nmap_scan_local", {"profile": "ping"}, raw)
    if lowered == "nmap scan local service light":
        return ParsedIntent("nmap_scan_local", {"profile": "service-light"}, raw)
    nmap_device_match = re.fullmatch(r"nmap scan device ([0-9.]+)(?: (ping|common ports|service light))?", lowered)
    if nmap_device_match:
        return ParsedIntent(
            "nmap_scan_device",
            {"target": nmap_device_match.group(1), "profile": _nmap_profile(nmap_device_match.group(2))},
            raw,
        )
    nmap_host_match = re.fullmatch(r"nmap scan ([0-9.]+)(?: (ping|common ports|service light))?", lowered)
    if nmap_host_match:
        return ParsedIntent(
            "nmap_scan_host",
            {"target": nmap_host_match.group(1), "profile": _nmap_profile(nmap_host_match.group(2))},
            raw,
        )

    public_scan = re.fullmatch(r"(?:scan|nmap|scan public ip|run nmap against)\s+([0-9.]+)", lowered)
    if public_scan:
        target = public_scan.group(1)
        try:
            if not ipaddress.ip_address(target).is_private:
                return ParsedIntent(
                    "blocked_request",
                    {
                        "reason": (
                            "Blocked.\n"
                            "Public IP scanning is not allowed by this assistant.\n"
                            "This tool is limited to local/private networks."
                        ),
                        "target_ip": target,
                    },
                    raw,
                )
        except ValueError:
            pass

    if lowered in {"scan network", "scan my network", "scan", "find devices", "discover devices", "what is connected to my network", "show open ports", "check services"}:
        return ParsedIntent("scan_network", raw_text=raw)
    if any(phrase in lowered for phrase in ("scan my network", "find devices", "discover devices", "what is connected to my network")):
        return ParsedIntent("scan_network", raw_text=raw)
    if lowered in {"enrich devices", "enrich"}:
        return ParsedIntent("enrich_devices", raw_text=raw)

    if lowered in {"diagnose network", "network diagnosis"}:
        return ParsedIntent("diagnose_network", raw_text=raw)
    if lowered in {"diagnose management ports", "diagnose management-ports", "show risky ports", "show risky management ports"}:
        return ParsedIntent("diagnose_management_ports", raw_text=raw)
    if lowered == "diagnose gateway":
        return ParsedIntent("diagnose_connectivity", {"target_ip": "gateway"}, raw)
    if lowered.startswith("diagnose connectivity ") or lowered.startswith("ping check "):
        target = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("diagnose_connectivity", {"target_ip": _resolve_device_ref(target, memory)}, raw)
    if lowered in {"diagnose it", "diagnose that device", "diagnose last device", "inspect it", "inspect that device", "inspect last device"}:
        return ParsedIntent("diagnose_device", {"ip": _resolve_device_ref("that device", memory)}, raw)
    if lowered.startswith("inspect ") or lowered.startswith("diagnose device "):
        target = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("diagnose_device", {"ip": _resolve_device_ref(target, memory)}, raw)
    if lowered.startswith("diagnose "):
        target = normalized.split(maxsplit=1)[1]
        if target in {"it", "that device", "last device"} or _looks_like_ip(target):
            return ParsedIntent("diagnose_device", {"ip": _resolve_device_ref(target, memory)}, raw)
    if lowered in {"show that device", "show last device", "show device it", "device it"}:
        return ParsedIntent("show_device", {"ip": _resolve_device_ref("that device", memory)}, raw)
    if lowered.startswith("show device ") or lowered.startswith("device "):
        target = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("show_device", {"ip": _resolve_device_ref(target, memory)}, raw)

    if lowered in {"knowledge list", "list knowledge"}:
        return ParsedIntent("knowledge_list", raw_text=raw)
    if lowered.startswith("knowledge search ") or lowered.startswith("search knowledge "):
        query = normalized.split(maxsplit=2)[2]
        return ParsedIntent("knowledge_search", {"query": query}, raw)
    if lowered.startswith("show knowledge "):
        value = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("knowledge_show", {"knowledge_id": int(value)} if value.isdigit() else {"knowledge_id": value}, raw)

    if lowered in {"plans", "show plans", "list plans", "plan list"}:
        return ParsedIntent("list_plans", raw_text=raw)
    if lowered in {"show that plan", "show last plan", "show plan it"}:
        return ParsedIntent("show_plan", {"plan_id": _resolve_plan_ref("that plan", memory)}, raw)
    if lowered.startswith("show plan "):
        return ParsedIntent("show_plan", {"plan_id": _resolve_plan_ref(normalized.rsplit(" ", 1)[-1], memory)}, raw)
    if lowered.startswith("review plan "):
        return ParsedIntent("review_plan", {"plan_id": _resolve_plan_ref(normalized.rsplit(" ", 1)[-1], memory)}, raw)
    if lowered.startswith(("preflight it", "preflight that plan", "preflight last plan")):
        plan_id = memory.resolve_plan("that plan")
        refresh = "refresh" in lowered
        return ParsedIntent("preflight_plan_refresh" if refresh else "preflight_plan", {"plan_id": plan_id}, raw)
    if lowered.startswith("preflight plan "):
        parts = normalized.split()
        plan_id = _resolve_plan_ref(parts[2] if len(parts) >= 3 else None, memory)
        refresh = any(part.lower() in {"refresh", "refresh=true", "--refresh"} for part in parts[3:])
        return ParsedIntent("preflight_plan_refresh" if refresh else "preflight_plan", {"plan_id": plan_id}, raw)

    if (lowered.startswith("connect collect ") or lowered.startswith("collect ")) and not any(term in lowered for term in ("router info", "gateway info")):
        target = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("connect_collect", {"ip": _resolve_device_ref(target, memory)}, raw)

    if lowered in {
        "connect to my router",
        "connect to router",
        "connect to gateway",
        "login to router",
        "inspect my router",
        "inspect router",
        "inspect gateway",
        "check my router",
        "check router",
        "collect router info",
        "collect gateway info",
        "read router configuration",
        "show router information",
    }:
        return ParsedIntent("router_connect_workflow", raw_text=raw)

    if lowered in {"lab checklist", "show lab checklist"}:
        return ParsedIntent("lab_checklist", raw_text=raw)
    if lowered.startswith("lab validate device "):
        return ParsedIntent("lab_validate_device", {"ip": _resolve_device_ref(normalized.rsplit(" ", 1)[-1], memory)}, raw)
    if lowered.startswith("lab validate plan "):
        return ParsedIntent("lab_validate_plan", {"plan_id": _resolve_plan_ref(normalized.rsplit(" ", 1)[-1], memory)}, raw)

    if lowered in {"workflow scan-and-diagnose", "workflow scan and diagnose", "start scan and diagnose"}:
        return ParsedIntent("workflow_scan_and_diagnose", raw_text=raw)
    if lowered in {"workflow topology-report", "workflow topology report", "start topology report"}:
        return ParsedIntent("workflow_topology_report", raw_text=raw)
    if lowered in {"workflow prepare-cisco-access-port", "prepare cisco access port", "workflow prepare cisco access port"}:
        return ParsedIntent("workflow_prepare_cisco_access_port", _key_values(normalized), raw)
    if lowered.startswith(("workflow prepare-cisco-access-port ", "prepare cisco access port ", "workflow prepare cisco access port ")):
        return ParsedIntent("workflow_prepare_cisco_access_port", _key_values(normalized), raw)
    if lowered in {"workflow prepare-mikrotik-dhcp", "prepare mikrotik dhcp", "workflow prepare mikrotik dhcp"}:
        return ParsedIntent("workflow_prepare_mikrotik_dhcp", _key_values(normalized), raw)
    if lowered.startswith(("workflow prepare-mikrotik-dhcp ", "prepare mikrotik dhcp ", "workflow prepare mikrotik dhcp ")):
        return ParsedIntent("workflow_prepare_mikrotik_dhcp", _key_values(normalized), raw)

    if lowered in {"build topology", "topology build"}:
        return ParsedIntent("build_topology", raw_text=raw)
    if lowered in {"show topology", "topology show"}:
        return ParsedIntent("show_topology", raw_text=raw)
    if lowered in {"export topology json", "topology export json"}:
        return ParsedIntent("export_topology_json", raw_text=raw)
    if lowered in {"export topology mermaid", "topology export mermaid"}:
        return ParsedIntent("export_topology_mermaid", raw_text=raw)
    export_match = re.fullmatch(r"export topology (mermaid|json|html) to (.+)", normalized, flags=re.IGNORECASE)
    if export_match:
        return ParsedIntent(
            "export_topology_file",
            {"format": export_match.group(1).lower(), "output": export_match.group(2).strip()},
            raw,
        )
    report_match = re.fullmatch(r"topology report to (.+)", normalized, flags=re.IGNORECASE)
    if report_match:
        return ParsedIntent("topology_report_file", {"output": report_match.group(1).strip()}, raw)
    if lowered in {"explain topology", "topology explain"}:
        return ParsedIntent("explain_topology", raw_text=raw)
    if lowered.startswith(("topology risk check plan ", "risk check plan ")):
        value = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("topology_risk_check", {"plan_id": _resolve_plan_ref(value, memory)}, raw)
    if lowered in {"list snapshots", "snapshot list", "snapshots"}:
        return ParsedIntent("list_snapshots", raw_text=raw)
    if lowered.startswith("show snapshot "):
        value = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("show_snapshot", {"snapshot_id": int(value)} if value.isdigit() else {"snapshot_id": value}, raw)
    if lowered.startswith(("snapshot restore guidance ", "restore guidance snapshot ")):
        value = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("snapshot_restore_guidance", {"snapshot_id": int(value)} if value.isdigit() else {"snapshot_id": value}, raw)
    snapshot_export_match = re.fullmatch(r"export snapshot (\d+) (?:format=)?(txt|json|md) to (.+)", normalized, flags=re.IGNORECASE)
    if snapshot_export_match:
        return ParsedIntent(
            "export_snapshot_file",
            {
                "snapshot_id": int(snapshot_export_match.group(1)),
                "format": snapshot_export_match.group(2).lower(),
                "output": snapshot_export_match.group(3).strip(),
            },
            raw,
        )
    if lowered.startswith("capture snapshot plan "):
        value = normalized.rsplit(" ", 1)[-1]
        return ParsedIntent("capture_snapshot", {"plan_id": _resolve_plan_ref(value, memory)}, raw)
    if lowered in {"list manual topology", "show manual topology", "manual topology list"}:
        return ParsedIntent("list_manual_topology", raw_text=raw)
    if lowered == "rebuild topology with manual":
        return ParsedIntent("rebuild_topology_with_manual", raw_text=raw)
    if lowered.startswith("add manual topology node "):
        values = _key_values(normalized)
        if {"key", "label", "type"}.issubset(values):
            return ParsedIntent(
                "add_manual_topology_node",
                {
                    "key": values["key"],
                    "label": values["label"],
                    "type": values["type"],
                    "ip": values.get("ip"),
                    "mac": values.get("mac"),
                    "vendor": values.get("vendor"),
                    "notes": values.get("notes"),
                },
                raw,
            )
        return ParsedIntent("unknown", {"text": normalized, "hint": "Use key=<key> label=<label> type=<type>."}, raw)
    if lowered.startswith("add manual topology edge "):
        values = _key_values(normalized)
        if {"source", "target"}.issubset(values):
            return ParsedIntent(
                "add_manual_topology_edge",
                {
                    "source": values["source"],
                    "target": values["target"],
                    "relation": values.get("relation", "manual"),
                    "label": values.get("label"),
                    "confidence": values.get("confidence", "high"),
                    "notes": values.get("notes"),
                },
                raw,
            )
        return ParsedIntent("unknown", {"text": normalized, "hint": "Use source=<key> target=<key>."}, raw)
    if lowered.startswith(("delete manual topology", "remove manual topology")):
        return ParsedIntent("delete_manual_topology", {}, raw)

    if lowered.startswith("ask "):
        return ParsedIntent("ask", {"question": normalized.split(maxsplit=1)[1]}, raw)
    if lowered.startswith("summarize ") or lowered.startswith("explain "):
        return ParsedIntent("ask", {"question": normalized}, raw)

    if "vlan" in lowered and "plan" in lowered:
        values = _key_values(normalized)
        if {"device", "vlan", "name"}.issubset(values):
            return ParsedIntent(
                "create_vlan_plan",
                {
                    "device": values["device"],
                    "vlan": int(values["vlan"]) if values["vlan"].isdigit() else values["vlan"],
                    "name": values["name"],
                    "ports": values.get("ports"),
                },
                raw,
            )

    if "cisco" in lowered and ("access-port" in lowered or "access port" in lowered) and "plan" in lowered:
        values = _key_values(normalized)
        if {"device", "interface", "vlan"}.issubset(values):
            return ParsedIntent(
                "create_cisco_access_port_plan",
                {
                    "device": values["device"],
                    "interface": values["interface"],
                    "vlan": int(values["vlan"]) if values["vlan"].isdigit() else values["vlan"],
                    "description": values.get("description"),
                },
                raw,
            )

    if "cisco" in lowered and "description" in lowered and "plan" in lowered:
        values = _key_values(normalized)
        if {"device", "interface", "description"}.issubset(values):
            return ParsedIntent(
                "create_cisco_description_plan",
                {
                    "device": values["device"],
                    "interface": values["interface"],
                    "description": values["description"],
                },
                raw,
            )

    if "mikrotik" in lowered and "dhcp" in lowered and "plan" in lowered:
        values = _key_values(normalized)
        if {"device", "name", "interface", "network", "gateway", "pool-name", "pool-range"}.issubset(values):
            return ParsedIntent(
                "create_mikrotik_dhcp_plan",
                {
                    "device": values["device"],
                    "name": values["name"],
                    "interface": values["interface"],
                    "network": values["network"],
                    "gateway": values["gateway"],
                    "pool_name": values["pool-name"],
                    "pool_range": values["pool-range"],
                    "dns": values.get("dns"),
                    "comment": values.get("comment"),
                },
                raw,
            )

    if "mikrotik" in lowered and "address" in lowered and "plan" in lowered:
        values = _key_values(normalized)
        if {"device", "interface", "address"}.issubset(values):
            return ParsedIntent(
                "create_mikrotik_address_plan",
                {
                    "device": values["device"],
                    "interface": values["interface"],
                    "address": values["address"],
                    "comment": values.get("comment", ""),
                },
                raw,
            )

    if lowered.startswith("fetch docs "):
        values = _key_values(normalized)
        if "url" in values:
            return ParsedIntent(
                "fetch_docs_url",
                {
                    "url": values["url"],
                    "vendor": values.get("vendor", ""),
                    "model": values.get("model", ""),
                    "doc_type": values.get("doc_type", "vendor_note"),
                    "trusted": values.get("trusted", "true").lower() in {"true", "yes", "1"},
                },
                raw,
            )

    if lowered.startswith(("configure ", "add nat ", "create firewall ", "configure cisco ", "configure mikrotik ", "add firewall ", "create cisco ", "create mikrotik ", "setup failover", "add static route", "add route", "add nat rule")):
        values = _key_values(normalized)
        platform = values.get("platform")
        if platform is None:
            if "mikrotik" in lowered or "routeros" in lowered:
                platform = "mikrotik_routeros"
            elif "cisco" in lowered:
                platform = "cisco_ios"
        return ParsedIntent(
            "custom_plan_goal",
            {"goal": normalized, "target_device_ip": values.get("device") or values.get("target"), "platform": platform},
            raw,
        )

    if lowered.startswith(("generate plugin ", "create plugin ", "make plugin ", "create a reusable tool ", "make a parser ", "create a parser ", "build a planner plugin ", "add a new tool ")):
        return ParsedIntent("generate_plugin_tool", {"goal": normalized}, raw)

    return ParsedIntent("unknown", {"text": normalized}, raw)


def _unsafe_request_reason(lowered: str) -> str | None:
    reasons: list[str] = []
    if lowered.startswith("nmap ") and not lowered.startswith("nmap check") and not lowered.startswith("nmap scan "):
        reasons.append("Raw nmap command execution is not allowed. Use controlled nmap scan routes.")
    if "public ip" in lowered and "nmap" in lowered:
        reasons.append("Public IP scanning with nmap is blocked.")
    if "nmap " in lowered and any(flag in lowered for flag in (" -a", "--script", " -o", " -su", " -ss", " -p-", " --top-ports", " --min-rate", " -t4", " -t5", " -d")):
        reasons.append("Arbitrary nmap flags, scripts, aggressive scans, and UDP/all-port scans are blocked.")
    if any(pattern in lowered for pattern in ("ssh into", "run ssh", "ssh ", "raw ssh", "execute raw command")):
        reasons.append("Raw SSH command execution is not allowed in agent mode.")
    if any(pattern in lowered for pattern in ("run shell", "bash", "terminal command", "sudo ")):
        reasons.append("Arbitrary shell command execution is not allowed in agent mode.")
    if any(pattern in lowered for pattern in ("reset router", "reset-configuration", "/system reset", "reboot device", "reboot router", "erase config", "delete config")):
        reasons.append("Reset, reboot, erase, and delete commands are destructive.")
    if any(pattern in lowered for pattern in ("brute force", "bypass password", "dump credentials", "exploit")):
        reasons.append("Credential attacks and exploitation requests are blocked.")
    if any(pattern in lowered for pattern in ("disable firewall", "open all ports")):
        reasons.append("Firewall-disabling and broad exposure requests are blocked.")
    if reasons:
        reasons.append("Use approved plan/preflight/execution workflows for supported changes.")
        return "Blocked.\n" + "\n".join(f"- {reason}" for reason in reasons)
    return None


def _blocked_high_risk(lowered: str, memory: SessionMemory) -> tuple[str, dict] | None:
    for tool_name, pattern in (
        ("execute_plan", r"^execute plan (\d+|it)$"),
        ("save_plan", r"^save plan (\d+|it)$"),
        ("rollback_plan", r"^rollback plan (\d+|it)$"),
        ("delete_knowledge", r"^(delete|remove) knowledge (\d+)$"),
    ):
        match = re.search(pattern, lowered)
        if match:
            if tool_name == "delete_knowledge":
                return tool_name, {"knowledge_id": int(match.group(2))}
            return tool_name, {"plan_id": memory.resolve_plan(match.group(1))}
    if lowered.startswith("delete credentials") or lowered.startswith("remove credentials"):
        return "delete_credentials", {}
    return None


def _key_values(text: str) -> dict[str, str]:
    try:
        parts = shlex.split(text)
    except ValueError:
        parts = text.split()
    values: dict[str, str] = {}
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            values[key.lower().strip()] = value.strip()
    return values


def _resolve_device_ref(value: str | None, memory: SessionMemory) -> str | None:
    return memory.resolve_device(value)


def _resolve_plan_ref(value: str | None, memory: SessionMemory) -> int | None:
    return memory.resolve_plan(value)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _nmap_profile(value: str | None) -> str:
    if value == "ping":
        return "ping"
    if value == "service light":
        return "service-light"
    return "common-ports"
