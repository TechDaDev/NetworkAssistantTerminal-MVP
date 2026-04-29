from __future__ import annotations

import html
import json
from dataclasses import dataclass
from pathlib import Path

from app.services.topology import TopologySnapshotResult, export_topology_json, export_topology_mermaid, _snapshot_or_latest


SUPPORTED_EXPORT_FORMATS = {"mermaid", "json", "html"}


class TopologyExportError(ValueError):
    pass


@dataclass
class TopologyFileExportResult:
    output_path: Path
    export_format: str
    bytes_written: int
    snapshot_id: int


def render_topology_markdown(snapshot_id: int | None = None) -> str:
    result = _snapshot_or_latest(snapshot_id)
    mermaid = export_topology_mermaid(snapshot_id)
    summary = _summary(result)
    return (
        "# Network Topology\n\n"
        f"Snapshot ID: {result.snapshot.id}\n\n"
        f"Created: {result.snapshot.created_at.isoformat()}\n\n"
        f"Source: {result.snapshot.source}\n\n"
        "```mermaid\n"
        f"{mermaid}\n"
        "```\n\n"
        "## Nodes\n\n"
        "| Node | Type | IP | Vendor | Confidence |\n"
        "| --- | --- | --- | --- | --- |\n"
        + "\n".join(
            f"| {_md(node.label)} | {_md(node.node_type)} | {_md(node.ip_address or '--')} | {_md(node.vendor)} | {_md(node.confidence)} |"
            for node in result.nodes
        )
        + "\n\n## Edges\n\n"
        "| Source | Target | Relation | Confidence | Evidence |\n"
        "| --- | --- | --- | --- | --- |\n"
        + "\n".join(
            f"| {_md(edge.source_node_key)} | {_md(edge.target_node_key)} | {_md(edge.relation_type)} | {_md(edge.confidence)} | {_md(edge.evidence_source)} |"
            for edge in result.edges
        )
        + "\n\n## Confidence Notes\n\n"
        + _confidence_notes(result)
        + "\n\n## Manual Evidence Notes\n\n"
        + _manual_notes(result)
        + "\n\n## Summary\n\n"
        f"- Nodes: {len(result.nodes)}\n"
        f"- Edges: {len(result.edges)}\n"
        f"- Confidence Summary: `{json.dumps(summary.get('edge_confidence', {}), sort_keys=True)}`\n"
    )


def render_topology_json(snapshot_id: int | None = None) -> str:
    data = export_topology_json(snapshot_id)
    summary = data["snapshot"].get("summary", {})
    manual_edges = [edge for edge in data["edges"] if edge.get("evidence_source") == "manual"]
    manual_nodes = [node for node in data["nodes"] if "Manual confirmation" in (node.get("evidence") or "")]
    payload = {
        "snapshot_id": data["snapshot"]["id"],
        "created_at": data["snapshot"]["created_at"],
        "snapshot": data["snapshot"],
        "nodes": data["nodes"],
        "edges": data["edges"],
        "manual_overlays": {
            "node_count": len(manual_nodes),
            "edge_count": len(manual_edges),
            "nodes": manual_nodes,
            "edges": manual_edges,
        },
        "confidence_summary": summary.get("edge_confidence", {}),
        "warnings": summary.get("warnings", []),
    }
    return json.dumps(payload, indent=2, default=str)


def render_topology_html(snapshot_id: int | None = None, *, offline: bool = False) -> str:
    result = _snapshot_or_latest(snapshot_id)
    mermaid = export_topology_mermaid(snapshot_id)
    script = "" if offline else '<script type="module">import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs"; mermaid.initialize({startOnLoad:true});</script>'
    diagram = f"<pre>{html.escape(mermaid)}</pre>" if offline else f'<div class="mermaid">\n{html.escape(mermaid)}\n</div>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Network Topology Snapshot {result.snapshot.id}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; line-height: 1.45; color: #172018; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #b8c7b8; padding: 0.45rem; text-align: left; vertical-align: top; }}
    th {{ background: #e8f5e9; }}
    code, pre {{ background: #f3f7f3; padding: 0.75rem; overflow-x: auto; }}
    .note {{ border-left: 4px solid #2e7d32; padding-left: 1rem; color: #2f4f35; }}
  </style>
  {script}
</head>
<body>
  <h1>Network Topology</h1>
  <p>Snapshot ID: {result.snapshot.id}<br>Created: {html.escape(result.snapshot.created_at.isoformat())}<br>Source: {html.escape(result.snapshot.source)}</p>
  <div class="note">Topology is evidence-based. Same-subnet and ARP links are not physical cabling proof. Manual links are user-confirmed local annotations.</div>
  <h2>Diagram</h2>
  {diagram}
  <h2>Nodes</h2>
  {_html_nodes_table(result)}
  <h2>Edges</h2>
  {_html_edges_table(result)}
  <h2>Evidence Notes</h2>
  <pre>{html.escape(_confidence_notes(result) + "\n\n" + _manual_notes(result))}</pre>
</body>
</html>
"""


def render_topology_report(snapshot_id: int | None = None) -> str:
    result = _snapshot_or_latest(snapshot_id)
    explanation = _report_missing_evidence(result)
    high = [edge for edge in result.edges if edge.confidence == "high"]
    low = [edge for edge in result.edges if edge.confidence == "low"]
    manual = [edge for edge in result.edges if edge.evidence_source == "manual"]
    return (
        "# Network Topology Report\n\n"
        "## Executive Summary\n\n"
        f"Snapshot {result.snapshot.id} contains {len(result.nodes)} node(s) and {len(result.edges)} edge(s). "
        "Links are labeled by confidence and evidence source.\n\n"
        "## Snapshot Metadata\n\n"
        f"- Snapshot ID: {result.snapshot.id}\n"
        f"- Created: {result.snapshot.created_at.isoformat()}\n"
        f"- Source: {result.snapshot.source}\n\n"
        "## Topology Diagram\n\n"
        "```mermaid\n"
        f"{export_topology_mermaid(snapshot_id)}\n"
        "```\n\n"
        "## Known Devices\n\n"
        + _nodes_markdown(result)
        + "\n\n## Links and Edges\n\n"
        + _edges_markdown(result)
        + "\n\n## High-Confidence Evidence\n\n"
        + _edge_list(high)
        + "\n\n## Low-Confidence Inferred Links\n\n"
        + _edge_list(low)
        + "\n\n## Manual Corrections\n\n"
        + _edge_list(manual)
        + "\n\n## Missing Evidence\n\n"
        + explanation
        + "\n\n## Recommended Next Commands\n\n"
        "- `python main.py scan`\n"
        "- `python main.py enrich`\n"
        "- `python main.py connect collect <ip>`\n"
        "- `python main.py topology rebuild-with-manual`\n"
    )


def write_topology_export_file(
    *,
    export_format: str,
    output_path: str | Path,
    snapshot_id: int | None = None,
    offline: bool = False,
    force: bool = False,
) -> TopologyFileExportResult:
    normalized = export_format.lower()
    if normalized not in SUPPORTED_EXPORT_FORMATS:
        raise TopologyExportError("Unsupported topology export format. Use mermaid, json, or html.")
    path = Path(output_path).expanduser()
    if path.exists() and not force:
        raise TopologyExportError(f"Output file already exists: {path}. Use --force to overwrite.")
    path.parent.mkdir(parents=True, exist_ok=True)
    if normalized == "mermaid":
        content = render_topology_markdown(snapshot_id)
    elif normalized == "json":
        content = render_topology_json(snapshot_id)
    else:
        content = render_topology_html(snapshot_id, offline=offline)
    path.write_text(content, encoding="utf-8")
    snapshot = _snapshot_or_latest(snapshot_id).snapshot
    return TopologyFileExportResult(path, normalized, len(content.encode("utf-8")), snapshot.id)


def write_topology_report_file(
    *,
    output_path: str | Path,
    snapshot_id: int | None = None,
    force: bool = False,
) -> TopologyFileExportResult:
    path = Path(output_path).expanduser()
    if path.exists() and not force:
        raise TopologyExportError(f"Output file already exists: {path}. Use --force to overwrite.")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_topology_report(snapshot_id)
    path.write_text(content, encoding="utf-8")
    snapshot = _snapshot_or_latest(snapshot_id).snapshot
    return TopologyFileExportResult(path, "report", len(content.encode("utf-8")), snapshot.id)


def _summary(result: TopologySnapshotResult) -> dict:
    try:
        return json.loads(result.snapshot.summary_json or "{}")
    except json.JSONDecodeError:
        return {}


def _nodes_markdown(result: TopologySnapshotResult) -> str:
    return (
        "| Node | Type | IP | Vendor | Confidence |\n| --- | --- | --- | --- | --- |\n"
        + "\n".join(
            f"| {_md(node.label)} | {_md(node.node_type)} | {_md(node.ip_address or '--')} | {_md(node.vendor)} | {_md(node.confidence)} |"
            for node in result.nodes
        )
    )


def _edges_markdown(result: TopologySnapshotResult) -> str:
    return (
        "| Source | Target | Relation | Confidence | Evidence |\n| --- | --- | --- | --- | --- |\n"
        + "\n".join(
            f"| {_md(edge.source_node_key)} | {_md(edge.target_node_key)} | {_md(edge.relation_type)} | {_md(edge.confidence)} | {_md(edge.evidence_source)} |"
            for edge in result.edges
        )
    )


def _confidence_notes(result: TopologySnapshotResult) -> str:
    notes = [
        "- High confidence usually comes from default gateway, CDP/LLDP, or manual confirmation.",
        "- Medium confidence may come from matching inventory/ARP evidence.",
        "- Low confidence links are inferred and should not be treated as physical cabling proof.",
    ]
    summary = _summary(result)
    warnings = summary.get("warnings", [])
    notes.extend(f"- Warning: {warning}" for warning in warnings)
    return "\n".join(notes)


def _manual_notes(result: TopologySnapshotResult) -> str:
    manual_edges = [edge for edge in result.edges if edge.evidence_source == "manual"]
    manual_nodes = [node for node in result.nodes if "Manual confirmation" in (node.evidence or "")]
    if not manual_edges and not manual_nodes:
        return "- No manual topology overlays are present."
    lines = [f"- Manual node: {node.node_key} ({node.label})" for node in manual_nodes]
    lines.extend(f"- Manual edge: {edge.source_node_key} -> {edge.target_node_key} ({edge.confidence})" for edge in manual_edges)
    return "\n".join(lines)


def _edge_list(edges) -> str:
    if not edges:
        return "- None."
    return "\n".join(f"- {edge.source_node_key} -> {edge.target_node_key} ({edge.relation_type}, {edge.confidence}, {edge.evidence_source})" for edge in edges)


def _report_missing_evidence(result: TopologySnapshotResult) -> str:
    lines = []
    if not any(edge.relation_type in {"cdp_neighbor", "lldp_neighbor"} for edge in result.edges):
        lines.append("- No CDP/LLDP neighbor evidence is present.")
    if not any(edge.relation_type == "arp_neighbor" for edge in result.edges):
        lines.append("- No MikroTik ARP neighbor evidence is present.")
    if not lines:
        lines.append("- Core topology evidence sources are present, but low-confidence links should still be verified.")
    return "\n".join(lines)


def _html_nodes_table(result: TopologySnapshotResult) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(node.node_key)}</td>"
        f"<td>{html.escape(node.label)}</td>"
        f"<td>{html.escape(node.node_type)}</td>"
        f"<td>{html.escape(node.ip_address or '--')}</td>"
        f"<td>{html.escape(node.vendor)}</td>"
        f"<td>{html.escape(node.confidence)}</td>"
        "</tr>"
        for node in result.nodes
    )
    return "<table><thead><tr><th>Key</th><th>Label</th><th>Type</th><th>IP</th><th>Vendor</th><th>Confidence</th></tr></thead><tbody>" + rows + "</tbody></table>"


def _html_edges_table(result: TopologySnapshotResult) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(edge.source_node_key)}</td>"
        f"<td>{html.escape(edge.target_node_key)}</td>"
        f"<td>{html.escape(edge.relation_type)}</td>"
        f"<td>{html.escape(edge.confidence)}</td>"
        f"<td>{html.escape(edge.evidence_source)}</td>"
        "</tr>"
        for edge in result.edges
    )
    return "<table><thead><tr><th>Source</th><th>Target</th><th>Relation</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>" + rows + "</tbody></table>"


def _md(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
