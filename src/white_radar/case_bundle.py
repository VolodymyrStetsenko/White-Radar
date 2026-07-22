from __future__ import annotations

import csv
import dataclasses
import hashlib
import html
import io
import json
from pathlib import Path
from typing import Any

from white_radar.investigation import InvestigationCase

BUNDLE_FILES = (
    "case.json",
    "report.md",
    "calls.csv",
    "events.csv",
    "transfers.csv",
    "state_changes.csv",
    "storage_changes.csv",
    "entities.csv",
    "relationships.csv",
    "timeline.csv",
    "graph.graphml",
    "graph.html",
)


@dataclasses.dataclass(frozen=True, slots=True)
class BundleResult:
    directory: Path
    files: tuple[Path, ...]
    manifest: Path

    def to_dict(self) -> dict[str, object]:
        return {
            "directory": str(self.directory),
            "files": [str(item) for item in self.files],
            "manifest": str(self.manifest),
        }


def _plain(value: object, *, limit: int = 2_000) -> str:
    return " ".join(str(value).split()).replace("`", "'")[:limit]


def render_investigation_report(case: InvestigationCase) -> str:
    root_signature = (
        case.root_call.signature
        if case.root_call and case.root_call.signature
        else (case.root_call.selector if case.root_call else "unresolved")
    )
    transaction_fee = (
        f"{case.transaction_fee_wei} wei" if case.transaction_fee_wei is not None else "unavailable"
    )
    lines = [
        f"# White Radar investigation {case.case_id}",
        "",
        "## Executive summary",
        "",
        (
            f"Transaction `{case.transaction_hash}` executed on **{case.chain}** at block "
            f"`{case.block_number}` with status **{case.transaction_status.upper()}**. "
            f"The reconstruction contains {len(case.calls)} call frames, "
            f"{len(case.events)} emitted events, {len(case.transfers)} asset transfers, "
            f"and {len(case.entities)} entities."
        ),
        "",
        "This report describes observed execution and asset-flow evidence. Findings are factual "
        "investigation leads and do not by themselves classify intent or exploitability.",
        "",
        "## Transaction",
        "",
        f"- Network: **{_plain(case.chain)}** (`{case.chain_id}`)",
        f"- Block: `{case.block_number}`",
        f"- Block hash: `{_plain(case.block_hash or 'unavailable')}`",
        f"- Block timestamp: `{_plain(case.block_timestamp or 'unavailable')}`",
        f"- Status: **{case.transaction_status.upper()}**",
        f"- Transaction fee: `{transaction_fee}`",
        f"- Root function: `{_plain(root_signature)}`",
        f"- Exact call trace available: **{'yes' if case.trace_available else 'no'}**",
        f"- Explorer: [{case.transaction_hash}]({case.explorer_url}/tx/{case.transaction_hash})",
    ]
    if case.proxy_snapshot:
        lines.extend(
            [
                "",
                "## Proxy execution context",
                "",
                f"- Proxy: `{case.proxy_snapshot.address}`",
                (
                    "- Effective implementation: `"
                    + _plain(case.proxy_snapshot.effective_implementation or "unresolved")
                    + "`"
                ),
                f"- Admin: `{_plain(case.proxy_snapshot.admin or 'not observed')}`",
                f"- Beacon: `{_plain(case.proxy_snapshot.beacon or 'not observed')}`",
                (
                    "- Implementation runtime SHA-256: `"
                    + _plain(case.proxy_snapshot.implementation_code_sha256 or "unavailable")
                    + "`"
                ),
            ]
        )
    lines.extend(["", "## Evidence findings", ""])
    if case.findings:
        for finding in case.findings:
            refs = ", ".join(f"`{_plain(item)}`" for item in finding.evidence_refs)
            lines.append(
                f"- **{_plain(finding.code)}** — {_plain(finding.summary)} Evidence: {refs}"
            )
    else:
        lines.append(
            "- No derived findings were produced beyond the source transaction and receipt."
        )
    if case.warnings:
        lines.extend(["", "## Source limitations", ""])
        lines.extend(f"- {_plain(item)}" for item in case.warnings)

    lines.extend(["", "## Emitted-event evidence", ""])
    if case.events:
        verified = sum(item.decode_confidence == "verified" for item in case.events)
        lines.extend(
            [
                f"- Receipt logs retained: {len(case.events)}",
                f"- Events decoded from verified ABIs: {verified}",
                "- Full topic, payload-hash, ABI-source, and argument inventory: `events.csv`",
                "",
                "| Log | Emitter | Event | Confidence | Evidence |",
                "|---:|---|---|---|---|",
            ]
        )
        for event in case.events[:100]:
            identity = event.event_signature or event.topic0 or "anonymous/unresolved"
            lines.append(
                "| {} | `{}` | `{}` | `{}` | `{}` |".format(
                    event.log_index,
                    _plain(event.address or "unknown"),
                    _plain(identity),
                    _plain(event.decode_confidence or "unresolved"),
                    event.evidence_ref,
                )
            )
        if len(case.events) > 100:
            lines.append(
                "\nThe table is capped at 100 rows; `events.csv` contains all "
                f"{len(case.events)} rows."
            )
    else:
        lines.append("- The transaction receipt contains no retained event logs.")

    lines.extend(["", "## Pre/post state-change evidence", ""])
    if case.state_diff:
        lines.extend(
            [
                f"- Changed accounts: {len(case.state_diff.accounts)}",
                f"- Changed storage slots: {case.state_diff.storage_change_count}",
                f"- Evidence source: `{_plain(case.state_diff.source)}`",
                f"- Bounded/truncated: **{'yes' if case.state_diff.truncated else 'no'}**",
                "- Account changes: `state_changes.csv`",
                "- Storage-slot changes: `storage_changes.csv`",
            ]
        )
    else:
        lines.append("- The configured RPC endpoint did not provide state-diff evidence.")

    lines.extend(["", "## Asset-flow summary", ""])
    if case.transfers:
        counts: dict[str, int] = {}
        for transfer in case.transfers:
            counts[transfer.asset_type] = counts.get(transfer.asset_type, 0) + 1
        lines.extend(f"- `{name}`: {count}" for name, count in sorted(counts.items()))
        lines.extend(
            [
                "",
                "| Type | Asset | From | To | Amount | Token ID | Evidence |",
                "|---|---|---|---|---:|---|---|",
            ]
        )
        for transfer in case.transfers[:100]:
            asset = transfer.asset_symbol or transfer.asset_address or "native"
            amount = transfer.amount_display or transfer.amount
            lines.append(
                "| {} | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                    transfer.asset_type,
                    _plain(asset),
                    transfer.sender,
                    transfer.recipient,
                    amount,
                    _plain(transfer.token_id or ""),
                    transfer.evidence_ref,
                )
            )
        if len(case.transfers) > 100:
            lines.append(
                "\nThe table is capped at 100 rows; `transfers.csv` contains all "
                f"{len(case.transfers)} rows."
            )
    else:
        lines.append(
            "- No native or standard ERC-20/ERC-721/ERC-1155 transfers were reconstructed."
        )

    lines.extend(["", "## Execution summary", ""])
    if case.calls:
        call_types: dict[str, int] = {}
        for frame in case.calls:
            call_types[frame.call_type] = call_types.get(frame.call_type, 0) + 1
        reverted_frames = sum(bool(frame.error or frame.revert_reason) for frame in case.calls)
        lines.extend(f"- `{name}`: {count}" for name, count in sorted(call_types.items()))
        lines.extend(
            [
                f"- Maximum observed depth: {max(frame.depth for frame in case.calls)}",
                f"- Reverted frames: {reverted_frames}",
                "- Full frame inventory: `calls.csv`",
            ]
        )
    else:
        lines.append(
            "- Call tracing was not available; root transaction and receipt evidence remain "
            "in `case.json`."
        )

    lines.extend(
        [
            "",
            "## Entity and relationship graph",
            "",
            f"- Entities: {len(case.entities)}",
            f"- Relationships: {len(case.relationships)}",
            "- Interactive graph: `graph.html`",
            "- HTML rendering limit: 250 nodes and 1,000 relationships",
            "- Portable graph: `graph.graphml`",
            "- Tabular exports: `entities.csv` and `relationships.csv`",
            "",
            "## Evidence integrity",
            "",
            "`manifest.json` records the SHA-256 and byte size of every bundle artifact. "
            "`case.json` is the canonical machine-readable case record.",
            "",
            "Generated by White Radar Incident Investigator.",
        ]
    )
    return "\n".join(lines) + "\n"


def _csv_text(fieldnames: tuple[str, ...], rows: list[dict[str, object]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def _graphml(case: InvestigationCase) -> str:
    nodes = []
    for entity in case.entities:
        label = entity.label or entity.address
        nodes.append(
            '<node id="{}"><data key="label">{}</data><data key="kind">{}</data>'
            '<data key="roles">{}</data></node>'.format(
                html.escape(entity.address, quote=True),
                html.escape(label),
                html.escape(entity.kind),
                html.escape(",".join(entity.roles)),
            )
        )
    edges = []
    for relation in case.relationships:
        edge_id = html.escape(relation.relationship_id, quote=True)
        source = html.escape(relation.source, quote=True)
        target = html.escape(relation.target, quote=True)
        relation_name = html.escape(relation.relation)
        evidence = html.escape(relation.evidence_ref)
        edges.append(
            f'<edge id="{edge_id}" source="{source}" target="{target}">'
            f'<data key="relation">{relation_name}</data>'
            f'<data key="evidence">{evidence}</data></edge>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n'
        '<key id="label" for="node" attr.name="label" attr.type="string"/>\n'
        '<key id="kind" for="node" attr.name="kind" attr.type="string"/>\n'
        '<key id="roles" for="node" attr.name="roles" attr.type="string"/>\n'
        '<key id="relation" for="edge" attr.name="relation" attr.type="string"/>\n'
        '<key id="evidence" for="edge" attr.name="evidence" attr.type="string"/>\n'
        '<graph id="white-radar-case" edgedefault="directed">\n'
        + "\n".join(nodes + edges)
        + "\n</graph>\n</graphml>\n"
    )


GRAPH_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>White Radar investigation graph</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, system-ui, sans-serif; }
    body { margin: 0; background: #07111f; color: #e9f2ff; }
    header { padding: 18px 22px; border-bottom: 1px solid #26364d; }
    h1 { margin: 0 0 6px; font-size: 20px; }
    #meta { color: #9eb1c8; }
    svg { width: 100vw; height: calc(100vh - 82px); display: block; }
    line { stroke: #526983; stroke-opacity: .65; }
    .edge-label { fill: #94a8bf; font-size: 9px; }
    circle { stroke: #d8e8ff; stroke-width: 1.2px; }
    .node-label { fill: #f3f8ff; font-size: 10px; pointer-events: none; }
    .contract { fill: #ffb347; } .account { fill: #5ab0ff; }
    .system { fill: #e46cff; } .unknown { fill: #9aa7b6; }
  </style>
</head>
<body>
<header><h1>White Radar investigation graph</h1><div id="meta"></div></header>
<svg id="graph" role="img" aria-label="Transaction entity relationship graph"></svg>
<script>
const data = __DATA__;
const svg = document.getElementById('graph');
const ns = 'http://www.w3.org/2000/svg';
const width = Math.max(900, window.innerWidth);
const height = Math.max(600, window.innerHeight - 82);
svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
document.getElementById('meta').textContent =
  `${data.case_id} · ${data.nodes.length} nodes · ${data.edges.length} edges`;
const radius = Math.min(width, height) * .38;
const cx = width / 2, cy = height / 2;
const positions = new Map(data.nodes.map((node, i) => [node.address, {
  x: cx + Math.cos((Math.PI * 2 * i / Math.max(1, data.nodes.length)) - Math.PI / 2) * radius,
  y: cy + Math.sin((Math.PI * 2 * i / Math.max(1, data.nodes.length)) - Math.PI / 2) * radius
}]));
for (const edge of data.edges) {
  const a = positions.get(edge.source), b = positions.get(edge.target);
  if (!a || !b) continue;
  const line = document.createElementNS(ns, 'line');
  for (const [k,v] of Object.entries({x1:a.x,y1:a.y,x2:b.x,y2:b.y})) {
    line.setAttribute(k,v);
  }
  const title = document.createElementNS(ns, 'title');
  title.textContent = `${edge.relation} · ${edge.evidence_ref}`;
  line.appendChild(title);
  svg.appendChild(line);
}
for (const node of data.nodes) {
  const p = positions.get(node.address);
  const group = document.createElementNS(ns, 'g');
  const circle = document.createElementNS(ns, 'circle');
  circle.setAttribute('cx',p.x);
  circle.setAttribute('cy',p.y);
  circle.setAttribute('r', node.roles.includes('transaction_target') ? 11 : 7);
  circle.setAttribute('class',node.kind);
  const title = document.createElementNS(ns, 'title');
  title.textContent =
    `${node.label || node.address}\n${node.kind}\n${node.roles.join(', ')}`;
  circle.appendChild(title);
  group.appendChild(circle);
  const label = document.createElementNS(ns, 'text');
  label.setAttribute('x',p.x + 12);
  label.setAttribute('y',p.y + 3);
  label.setAttribute('class','node-label');
  label.textContent = node.label || node.address.slice(0,10) + '…';
  group.appendChild(label);
  svg.appendChild(group);
}
</script>
</body>
</html>
"""


def _graph_html(case: InvestigationCase) -> str:
    selected_nodes = case.entities[:250]
    addresses = {item.address for item in selected_nodes}
    selected_edges = [
        item.to_dict()
        for item in case.relationships
        if item.source in addresses and item.target in addresses
    ][:1_000]
    data = {
        "case_id": case.case_id,
        "nodes": [item.to_dict() for item in selected_nodes],
        "edges": selected_edges,
    }
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).replace("<", "\\u003c")
    return GRAPH_TEMPLATE.replace("__DATA__", encoded)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_case_bundle(
    case: InvestigationCase,
    destination: Path,
    *,
    overwrite: bool = False,
) -> BundleResult:
    root = destination.expanduser().resolve()
    if root.exists() and not root.is_dir():
        raise ValueError(f"Case bundle destination is not a directory: {root}")
    existing = [root / name for name in (*BUNDLE_FILES, "manifest.json") if (root / name).exists()]
    symlinks = [
        root / name for name in (*BUNDLE_FILES, "manifest.json") if (root / name).is_symlink()
    ]
    if symlinks:
        raise ValueError("Case bundle files cannot be symbolic links")
    if existing and not overwrite:
        raise FileExistsError(
            "Case bundle files already exist; select a new directory or pass --overwrite"
        )
    root.mkdir(parents=True, exist_ok=True)

    state_rows: list[dict[str, object]] = []
    storage_rows: list[dict[str, object]] = []
    if case.state_diff:
        for account in case.state_diff.accounts:
            account_data = account.to_dict()
            account_data.pop("storage_changes", None)
            state_rows.append(account_data)
            storage_rows.extend(
                {
                    "address": account.address,
                    **storage.to_dict(),
                }
                for storage in account.storage_changes
            )

    artifacts: dict[str, str] = {
        "case.json": json.dumps(case.to_dict(), indent=2, sort_keys=True) + "\n",
        "report.md": render_investigation_report(case),
        "calls.csv": _csv_text(
            (
                "path",
                "depth",
                "call_type",
                "sender",
                "recipient",
                "value_wei",
                "gas",
                "gas_used",
                "selector",
                "function_signature",
                "abi_source",
                "decode_confidence",
                "decoded_arguments",
                "calldata",
                "calldata_bytes",
                "calldata_sha256",
                "calldata_truncated",
                "error",
                "revert_reason",
            ),
            [
                {
                    **item.to_dict(),
                    "decoded_arguments": json.dumps(
                        item.decoded_arguments, sort_keys=True, separators=(",", ":")
                    ),
                }
                for item in case.calls
            ],
        ),
        "events.csv": _csv_text(
            (
                "log_index",
                "address",
                "topic0",
                "event_signature",
                "event_name",
                "arguments",
                "abi_source",
                "abi_sha256",
                "decode_confidence",
                "topics",
                "data",
                "data_bytes",
                "data_sha256",
                "data_truncated",
                "evidence_ref",
            ),
            [
                {
                    **item.to_dict(),
                    "arguments": json.dumps(
                        item.arguments, sort_keys=True, separators=(",", ":")
                    ),
                    "topics": json.dumps(item.topics, separators=(",", ":")),
                }
                for item in case.events
            ],
        ),
        "transfers.csv": _csv_text(
            (
                "transfer_id",
                "asset_type",
                "asset_address",
                "asset_name",
                "asset_symbol",
                "asset_decimals",
                "sender",
                "recipient",
                "amount",
                "amount_display",
                "token_id",
                "operator",
                "source",
                "evidence_ref",
            ),
            [item.to_dict() for item in case.transfers],
        ),
        "state_changes.csv": _csv_text(
            (
                "address",
                "change_type",
                "balance_before_wei",
                "balance_after_wei",
                "nonce_before",
                "nonce_after",
                "code_before_bytes",
                "code_after_bytes",
                "code_before_sha256",
                "code_after_sha256",
            ),
            state_rows,
        ),
        "storage_changes.csv": _csv_text(
            ("address", "slot", "before", "after"),
            storage_rows,
        ),
        "entities.csv": _csv_text(
            (
                "address",
                "kind",
                "label",
                "roles",
                "code_observed",
                "code_bytes",
                "runtime_code_sha256",
            ),
            [
                {
                    **item.to_dict(),
                    "roles": ",".join(item.roles),
                }
                for item in case.entities
            ],
        ),
        "relationships.csv": _csv_text(
            (
                "relationship_id",
                "source",
                "target",
                "relation",
                "evidence_ref",
                "asset_address",
                "amount",
                "asset_type",
                "asset_symbol",
                "amount_display",
            ),
            [item.to_dict() for item in case.relationships],
        ),
        "timeline.csv": _csv_text(
            ("entry_id", "phase", "order", "event_type", "summary", "evidence_ref"),
            [item.to_dict() for item in case.timeline],
        ),
        "graph.graphml": _graphml(case),
        "graph.html": _graph_html(case),
    }
    written: list[Path] = []
    for name in BUNDLE_FILES:
        path = root / name
        path.write_text(artifacts[name], encoding="utf-8", newline="")
        written.append(path)

    manifest_payload: dict[str, Any] = {
        "schema_version": 2,
        "case_id": case.case_id,
        "transaction_hash": case.transaction_hash,
        "chain_id": case.chain_id,
        "generated_at": case.generated_at,
        "files": [
            {
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in written
        ],
    }
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return BundleResult(root, tuple(written), manifest)
