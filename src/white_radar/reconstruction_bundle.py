from __future__ import annotations

# Embedded HTML/CSS/JavaScript is kept self-contained for portable evidence bundles.
# ruff: noqa: E501
import csv
import hashlib
import html
import io
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from white_radar.case_bundle import BundleResult
from white_radar.reconstruction import AttackReconstruction, ReconstructionEdge

RECONSTRUCTION_BUNDLE_FILES = (
    "case.json",
    "report.md",
    "transactions.csv",
    "calls.csv",
    "transfers.csv",
    "entities.csv",
    "relationships.csv",
    "timeline.csv",
    "graph.graphml",
    "graph.html",
)


def _plain(value: object, *, limit: int = 2_000) -> str:
    return " ".join(str(value).split()).replace("`", "'")[:limit]


def _short(value: str, length: int = 14) -> str:
    return value if len(value) <= length + 3 else value[:length] + "…"


def _asset_label(edge: ReconstructionEdge) -> str:
    if edge.asset_type == "native":
        return "native"
    return edge.asset_symbol or edge.asset_address or edge.asset_type or "unresolved"


def _amount_label(edge: ReconstructionEdge) -> str:
    amount = edge.amount_display or edge.raw_amount or "unavailable"
    symbol = edge.asset_symbol or ""
    return f"{amount} {symbol}".strip()


def render_reconstruction_report(reconstruction: AttackReconstruction) -> str:
    coverage = reconstruction.coverage
    contexts = reconstruction.contexts
    phases = Counter(item.phase for item in contexts)
    calls = sum(len(item.calls) for item in reconstruction.transactions)
    transfers = sum(len(item.transfers) for item in reconstruction.transactions)
    traced = sum(item.trace_available for item in contexts)
    flow_edges = [item for item in reconstruction.edges if item.asset_type is not None]
    lines = [
        f"# White Radar incident reconstruction {reconstruction.reconstruction_id}",
        "",
        "## Executive summary",
        "",
        (
            f"Seed transaction `{reconstruction.seed_transaction_hash}` was expanded into "
            f"**{len(contexts)} reconstructed transactions**, **{len(reconstruction.entities)} "
            f"entities**, **{calls} call frames**, and **{transfers} observed asset transfers** "
            f"on **{reconstruction.chain}**."
        ),
        "",
        (
            "The result is an evidence-backed, bounded candidate incident chain. It reconstructs "
            "relationships found inside the configured block, hop, address, and transaction limits; "
            "it does not claim that the earliest or final incident transaction has been proven."
        ),
        "",
        "## Investigation scope and coverage",
        "",
        f"- Chain: **{_plain(reconstruction.chain)}** (`{reconstruction.chain_id}`)",
        f"- Seed block: `{reconstruction.seed_block_number}`",
        (
            f"- Requested block window: `{coverage.requested_start_block}` through "
            f"`{coverage.requested_end_block}`"
        ),
        f"- Observed chain head: `{coverage.observed_chain_head}`",
        f"- Boundary classification: **{_plain(coverage.boundary_status)}**",
        f"- Addresses queried: `{coverage.addresses_queried}`",
        f"- History records considered: `{coverage.history_records_considered}`",
        f"- Candidate transactions: `{coverage.transaction_candidates}`",
        f"- Transactions reconstructed: `{coverage.transactions_reconstructed}`",
        f"- Transaction reconstruction failures: `{coverage.transaction_failures}`",
        f"- Trace coverage: `{traced}/{len(contexts)}` transactions",
        (
            "- History sources: "
            + (", ".join(f"`{_plain(item)}`" for item in coverage.history_sources) or "unavailable")
        ),
        "",
        "### Boundary controls",
        "",
        f"- Backward blocks: `{reconstruction.limits.backward_blocks}`",
        f"- Forward blocks: `{reconstruction.limits.forward_blocks}`",
        f"- Maximum relationship hops: `{reconstruction.limits.max_hops}`",
        f"- Maximum transactions: `{reconstruction.limits.max_transactions}`",
        f"- Maximum frontier addresses: `{reconstruction.limits.max_frontier_addresses}`",
        (
            "- Maximum history records per address: "
            f"`{reconstruction.limits.history_records_per_address}`"
        ),
        "",
        "## Candidate incident phases",
        "",
        f"- Pre-seed transactions: `{phases['pre_seed']}`",
        f"- Same-block related transactions: `{phases['same_block']}`",
        f"- Seed transactions: `{phases['seed']}`",
        f"- Post-seed transactions: `{phases['post_seed']}`",
        "",
        "## Chronological transaction inventory",
        "",
        "| Phase | Block | Tx index | Transaction | From | To | Function / selector | Status | Hop | Why included |",
        "|---|---:|---:|---|---|---|---|---|---:|---|",
    ]
    for item in contexts[:250]:
        function = item.function_signature or item.selector
        if item.function_confidence:
            function = f"{function} [{item.function_confidence}]"
        reasons = "; ".join(_plain(value, limit=180) for value in item.discovery_reasons)
        tx_link = f"[{_short(item.transaction_hash)}]({reconstruction.explorer_url}/tx/{item.transaction_hash})"
        lines.append(
            "| {} | {} | {} | {} | `{}` | `{}` | `{}` | {} | {} | {} |".format(
                item.phase,
                item.block_number,
                item.transaction_index if item.transaction_index is not None else "",
                tx_link,
                _short(item.sender or "creation"),
                _short(item.recipient or "creation"),
                _plain(function),
                item.status,
                item.hop,
                reasons,
            )
        )
    if len(contexts) > 250:
        lines.append(
            f"\nThe table is capped at 250 rows; `transactions.csv` contains all {len(contexts)} rows."
        )

    lines.extend(
        [
            "",
            "## Asset-flow ledger",
            "",
            "| Block | Transaction | Type | Asset | From | To | Amount | Evidence |",
            "|---:|---|---|---|---|---|---:|---|",
        ]
    )
    if flow_edges:
        for edge in flow_edges[:300]:
            lines.append(
                "| {} | [{}]({}/tx/{}) | {} | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                    edge.block_number,
                    _short(edge.transaction_hash),
                    reconstruction.explorer_url,
                    edge.transaction_hash,
                    edge.asset_type or "",
                    _plain(_asset_label(edge)),
                    edge.source,
                    edge.target,
                    _plain(_amount_label(edge)),
                    edge.evidence_ref,
                )
            )
        if len(flow_edges) > 300:
            lines.append(
                f"\nThe table is capped at 300 rows; `transfers.csv` contains all {len(flow_edges)} rows."
            )
    else:
        lines.append("|  |  |  |  |  |  |  | No standard asset flow reconstructed |")

    selector_transactions: dict[str, set[str]] = defaultdict(set)
    selector_sources: dict[str, set[str]] = defaultdict(set)
    selector_confidences: dict[str, set[str]] = defaultdict(set)
    for case in reconstruction.transactions:
        for frame in case.calls:
            label = frame.function_signature or frame.selector
            selector_transactions[label].add(case.transaction_hash)
            if frame.abi_source:
                selector_sources[label].add(frame.abi_source)
            if frame.decode_confidence:
                selector_confidences[label].add(frame.decode_confidence)
    lines.extend(
        [
            "",
            "## Function and selector inventory",
            "",
            "| Function / selector | Transactions | Confidence | ABI sources |",
            "|---|---:|---|---|",
        ]
    )
    if selector_transactions:
        for selector, tx_hashes in sorted(
            selector_transactions.items(), key=lambda item: (-len(item[1]), item[0])
        ):
            sources = "; ".join(sorted(selector_sources[selector])) or "unresolved"
            confidence = "; ".join(sorted(selector_confidences[selector])) or "unresolved"
            lines.append(
                f"| `{_plain(selector)}` | {len(tx_hashes)} | "
                f"{_plain(confidence)} | {_plain(sources, limit=300)} |"
            )
    else:
        lines.append("| `unavailable` | 0 | unavailable | Call tracing unavailable |")

    proxy_cases = [item for item in reconstruction.transactions if item.proxy_snapshot]
    lines.extend(["", "## Proxy and contract execution context", ""])
    if proxy_cases:
        lines.extend(
            [
                "| Transaction | Proxy | Implementation | Admin | Beacon |",
                "|---|---|---|---|---|",
            ]
        )
        for case in proxy_cases:
            snapshot = case.proxy_snapshot
            assert snapshot is not None
            lines.append(
                "| `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                    _short(case.transaction_hash),
                    snapshot.address,
                    snapshot.effective_implementation or "unresolved",
                    snapshot.admin or "not observed",
                    snapshot.beacon or "not observed",
                )
            )
    else:
        lines.append(
            "- No proxy implementation was resolved from the configured sources at the relevant blocks."
        )

    lines.extend(
        [
            "",
            "## Entity inventory",
            "",
            "| Entity | Kind | Label | Roles | Transactions | Blocks | Code bytes | Runtime hashes |",
            "|---|---|---|---|---:|---|---|---|",
        ]
    )
    for entity in reconstruction.entities[:300]:
        lines.append(
            "| `{}` | {} | {} | {} | {} | {}-{} | {} | {} |".format(
                entity.address,
                entity.kind,
                _plain(entity.label or ""),
                _plain(", ".join(entity.roles), limit=300),
                len(entity.transaction_hashes),
                entity.first_block,
                entity.last_block,
                (
                    ""
                    if entity.code_bytes_min is None
                    else str(entity.code_bytes_min)
                    if entity.code_bytes_min == entity.code_bytes_max
                    else f"{entity.code_bytes_min}-{entity.code_bytes_max}"
                ),
                _plain(", ".join(value[:16] for value in entity.runtime_code_sha256s)),
            )
        )
    if len(reconstruction.entities) > 300:
        lines.append(
            f"\nThe table is capped at 300 rows; `entities.csv` contains all {len(reconstruction.entities)} rows."
        )

    lines.extend(["", "## Evidence gaps and limitations", ""])
    lines.extend(f"- {_plain(item)}" for item in reconstruction.warnings)
    lines.extend(
        [
            "",
            "## Evidence artifacts",
            "",
            "- `case.json`: canonical machine-readable reconstruction, including every bounded transaction case.",
            "- `transactions.csv`: chronological candidate transaction inventory and discovery reasons.",
            "- `calls.csv`: cross-transaction call-frame inventory with selectors and verified ABI labels.",
            "- `transfers.csv`: raw and normalized native/token transfer ledger.",
            "- `entities.csv`: address roles and observed participation range.",
            "- `relationships.csv`: evidence-backed graph edges.",
            "- `timeline.csv`: ordered execution and asset-flow events across transactions.",
            "- `graph.html`: interactive investigation graph with search, filtering, zoom, and details.",
            "- `graph.graphml`: portable graph for external analysis tools.",
            "- `manifest.json`: byte sizes and SHA-256 digests for every artifact.",
            "",
            "## Interpretation model",
            "",
            "Observed transaction, receipt, trace, log, block, ABI, and proxy data are evidence. "
            "Discovery reasons and candidate boundaries are derived links. Attribution, intent, "
            "authorization, and final incident conclusions require analyst validation and are not "
            "silently inferred from address proximity.",
            "",
            "Generated by White Radar Incident Reconstruction Engine.",
        ]
    )
    return "\n".join(lines) + "\n"


def _csv_text(fieldnames: tuple[str, ...], rows: list[dict[str, object]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def _graph_nodes(reconstruction: AttackReconstruction) -> list[dict[str, object]]:
    nodes: list[dict[str, object]] = []
    for entity in reconstruction.entities:
        nodes.append(
            {
                "id": entity.address,
                "label": entity.label or _short(entity.address),
                "full_label": entity.label or entity.address,
                "kind": entity.kind,
                "roles": list(entity.roles),
                "transactions": list(entity.transaction_hashes),
                "first_block": entity.first_block,
                "last_block": entity.last_block,
                "code_observed": entity.code_observed,
                "code_bytes_min": entity.code_bytes_min,
                "code_bytes_max": entity.code_bytes_max,
                "runtime_code_sha256s": list(entity.runtime_code_sha256s),
            }
        )
    for context in reconstruction.contexts:
        nodes.append(
            {
                "id": f"tx:{context.transaction_hash}",
                "label": f"tx {_short(context.transaction_hash, 10)}",
                "full_label": context.transaction_hash,
                "kind": "transaction",
                "roles": [context.phase, f"hop:{context.hop}", context.status],
                "transactions": [context.transaction_hash],
                "first_block": context.block_number,
                "last_block": context.block_number,
                "function": context.function_signature or context.selector,
                "function_source": context.function_source,
                "function_confidence": context.function_confidence,
                "decoded_arguments": context.decoded_arguments,
                "score": context.relevance_score,
            }
        )
    return nodes


def _graph_edges(reconstruction: AttackReconstruction) -> list[dict[str, object]]:
    edges: list[dict[str, object]] = []
    for context in reconstruction.contexts:
        tx_node = f"tx:{context.transaction_hash}"
        if context.sender:
            edges.append(
                {
                    "id": f"initiated:{context.transaction_hash}",
                    "source": context.sender,
                    "target": tx_node,
                    "relation": "INITIATED",
                    "transaction_hash": context.transaction_hash,
                    "block_number": context.block_number,
                    "amount": None,
                    "asset": None,
                    "evidence_ref": f"{context.transaction_hash}:transaction",
                }
            )
        if context.recipient:
            edges.append(
                {
                    "id": f"targeted:{context.transaction_hash}",
                    "source": tx_node,
                    "target": context.recipient,
                    "relation": "TARGETED",
                    "transaction_hash": context.transaction_hash,
                    "block_number": context.block_number,
                    "amount": None,
                    "asset": None,
                    "evidence_ref": f"{context.transaction_hash}:transaction",
                }
            )
    for edge in reconstruction.edges:
        edges.append(
            {
                "id": edge.edge_id,
                "source": edge.source,
                "target": edge.target,
                "relation": edge.relation,
                "transaction_hash": edge.transaction_hash,
                "block_number": edge.block_number,
                "amount": _amount_label(edge) if edge.raw_amount is not None else None,
                "asset": _asset_label(edge) if edge.asset_type else None,
                "evidence_ref": edge.evidence_ref,
            }
        )
    return edges


def _graphml(reconstruction: AttackReconstruction) -> str:
    nodes = []
    for node in _graph_nodes(reconstruction):
        roles = node["roles"]
        role_text = ",".join(str(item) for item in roles) if isinstance(roles, list) else str(roles)
        nodes.append(
            '<node id="{}"><data key="label">{}</data><data key="kind">{}</data>'
            '<data key="roles">{}</data><data key="block">{}</data></node>'.format(
                html.escape(str(node["id"]), quote=True),
                html.escape(str(node["full_label"])),
                html.escape(str(node["kind"])),
                html.escape(role_text),
                html.escape(str(node["first_block"])),
            )
        )
    edges = []
    for edge in _graph_edges(reconstruction):
        edges.append(
            '<edge id="{}" source="{}" target="{}"><data key="relation">{}</data>'
            '<data key="evidence">{}</data><data key="amount">{}</data>'
            '<data key="transaction">{}</data></edge>'.format(
                html.escape(str(edge["id"]), quote=True),
                html.escape(str(edge["source"]), quote=True),
                html.escape(str(edge["target"]), quote=True),
                html.escape(str(edge["relation"])),
                html.escape(str(edge["evidence_ref"])),
                html.escape(str(edge["amount"] or "")),
                html.escape(str(edge["transaction_hash"])),
            )
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n'
        '<key id="label" for="node" attr.name="label" attr.type="string"/>\n'
        '<key id="kind" for="node" attr.name="kind" attr.type="string"/>\n'
        '<key id="roles" for="node" attr.name="roles" attr.type="string"/>\n'
        '<key id="block" for="node" attr.name="block" attr.type="string"/>\n'
        '<key id="relation" for="edge" attr.name="relation" attr.type="string"/>\n'
        '<key id="evidence" for="edge" attr.name="evidence" attr.type="string"/>\n'
        '<key id="amount" for="edge" attr.name="amount" attr.type="string"/>\n'
        '<key id="transaction" for="edge" attr.name="transaction" attr.type="string"/>\n'
        '<graph id="white-radar-reconstruction" edgedefault="directed">\n'
        + "\n".join(nodes + edges)
        + "\n</graph>\n</graphml>\n"
    )


GRAPH_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>White Radar incident reconstruction graph</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; background: #06101d; color: #eaf2ff; overflow: hidden; }
    header { height: 116px; padding: 15px 20px; border-bottom: 1px solid #273a54;
      background: linear-gradient(115deg,#0a1b2c,#111830); }
    h1 { margin: 0 0 8px; font-size: 22px; }
    #meta { color: #a9bdd5; margin-bottom: 11px; }
    #toolbar { display: flex; gap: 8px; flex-wrap: wrap; }
    input, select, button { border: 1px solid #38506d; border-radius: 7px; background: #0b192a;
      color: #eef6ff; padding: 7px 10px; }
    input { width: min(420px,45vw); }
    button { cursor: pointer; } button:hover { background: #17304a; }
    main { display: grid; grid-template-columns: minmax(0,1fr) 350px; height: calc(100vh - 116px); }
    #canvas { position: relative; min-width: 0; }
    svg { width: 100%; height: 100%; display: block; background: radial-gradient(circle at 50% 50%,#0b1d30,#06101d 72%); }
    #details { border-left: 1px solid #273a54; padding: 16px; overflow: auto; background: #081523; }
    #details h2 { margin: 0 0 12px; font-size: 17px; }
    .detail-row { margin: 0 0 12px; }
    .detail-key { color: #8fa8c3; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
    .detail-value { margin-top: 3px; word-break: break-all; line-height: 1.35; }
    #legend { position: absolute; left: 14px; bottom: 14px; display: grid; gap: 5px;
      background: #071625e8; border: 1px solid #30465f; border-radius: 8px; padding: 9px 11px;
      color: #b8c9dc; font-size: 12px; }
    .legend-dot { width: 9px; height: 9px; display: inline-block; border-radius: 50%; margin-right: 6px; }
    .edge { stroke: #58718e; stroke-opacity: .52; fill: none; }
    .edge.asset { stroke: #4fd1a5; stroke-opacity: .82; stroke-width: 2.2; }
    .edge.transaction-link { stroke: #8b9bb1; stroke-dasharray: 4 3; }
    .edge.hidden, .node.hidden, .node-label.hidden { display: none; }
    .edge-label { fill: #9fb4ca; font-size: 9px; paint-order: stroke; stroke: #06101d; stroke-width: 3px; }
    .node { stroke: #dcecff; stroke-width: 1.2; cursor: pointer; }
    .node.account { fill: #48a8ff; } .node.contract { fill: #ffb44a; }
    .node.system { fill: #d879ff; } .node.transaction { fill: #55d7aa; }
    .node.unknown { fill: #9aa8b8; }
    .node.seed { stroke: #fff07a; stroke-width: 3; }
    .node.match { stroke: #ff6f91; stroke-width: 4; }
    .node-label { fill: #f4f8ff; font-size: 10px; pointer-events: none; paint-order: stroke;
      stroke: #06101d; stroke-width: 3px; }
    @media (max-width: 850px) { main { grid-template-columns: 1fr; } #details { display: none; } }
  </style>
</head>
<body>
<header>
  <h1>White Radar incident reconstruction graph</h1>
  <div id="meta"></div>
  <div id="toolbar">
    <input id="search" placeholder="Search address, transaction, label, selector…" aria-label="Search graph">
    <select id="kind"><option value="all">All node types</option><option value="transaction">Transactions</option>
      <option value="account">Accounts</option><option value="contract">Contracts</option><option value="system">System</option></select>
    <select id="relation"><option value="all">All relationships</option></select>
    <button id="fit">Fit graph</button>
  </div>
</header>
<main>
  <section id="canvas">
    <svg id="graph" role="img" aria-label="Cross-transaction incident graph">
      <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#7f97b3"/></marker></defs>
      <g id="viewport"><g id="edges"></g><g id="edge-labels"></g><g id="nodes"></g><g id="node-labels"></g></g>
    </svg>
    <div id="legend"><div><span class="legend-dot" style="background:#55d7aa"></span>Transaction</div>
      <div><span class="legend-dot" style="background:#48a8ff"></span>Account</div>
      <div><span class="legend-dot" style="background:#ffb44a"></span>Contract</div>
      <div><span class="legend-dot" style="background:#d879ff"></span>System</div>
      <div><span class="legend-dot" style="background:#4fd1a5"></span>Asset flow</div></div>
  </section>
  <aside id="details"><h2>Investigation details</h2><p>Select a node or relationship.</p></aside>
</main>
<script>
const data = __DATA__;
const svg = document.getElementById('graph'), viewport = document.getElementById('viewport');
const edgeLayer = document.getElementById('edges'), edgeLabelLayer = document.getElementById('edge-labels');
const nodeLayer = document.getElementById('nodes'), nodeLabelLayer = document.getElementById('node-labels');
const details = document.getElementById('details'), ns = 'http://www.w3.org/2000/svg';
const width = Math.max(900, svg.clientWidth), height = Math.max(620, svg.clientHeight);
svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
document.getElementById('meta').textContent = `${data.id} · ${data.nodes.length} nodes · ${data.edges.length} relationships · bounded evidence graph`;
const hash = s => [...s].reduce((a,c)=>((a*31+c.charCodeAt(0))>>>0),2166136261);
const nodes = data.nodes.map((node,i)=>({...node,x:70+(hash(node.id)%Math.max(100,width-140)),y:70+((hash(node.id+'y')+i*37)%Math.max(100,height-140)),vx:0,vy:0}));
const byId = new Map(nodes.map(n=>[n.id,n]));
const edges = data.edges.filter(e=>byId.has(e.source)&&byId.has(e.target)).map(e=>({...e,a:byId.get(e.source),b:byId.get(e.target)}));
const relationSelect = document.getElementById('relation');
[...new Set(edges.map(e=>e.relation))].sort().forEach(value=>{const option=document.createElement('option');option.value=value;option.textContent=value;relationSelect.appendChild(option);});
const edgeElements = edges.map(edge=>{const line=document.createElementNS(ns,'line');line.setAttribute('marker-end','url(#arrow)');line.classList.add('edge');if(edge.asset)line.classList.add('asset');if(['INITIATED','TARGETED'].includes(edge.relation))line.classList.add('transaction-link');line.addEventListener('click',()=>show(edge,'Relationship'));edgeLayer.appendChild(line);return line;});
const labelElements = edges.map(edge=>{const text=document.createElementNS(ns,'text');text.classList.add('edge-label');text.textContent=edge.amount?`${edge.relation} · ${edge.amount}`:edge.relation;text.addEventListener('click',()=>show(edge,'Relationship'));edgeLabelLayer.appendChild(text);return text;});
const nodeElements = nodes.map(node=>{const circle=document.createElementNS(ns,'circle');circle.setAttribute('r',node.kind==='transaction'?10:node.roles.includes('transaction_target')?9:7);circle.classList.add('node',node.kind||'unknown');if(node.id===`tx:${data.seed}`)circle.classList.add('seed');circle.addEventListener('click',()=>show(node,'Node'));nodeLayer.appendChild(circle);return circle;});
const nodeLabels = nodes.map(node=>{const text=document.createElementNS(ns,'text');text.classList.add('node-label');text.textContent=node.label;text.addEventListener('click',()=>show(node,'Node'));nodeLabelLayer.appendChild(text);return text;});
function escapeText(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function show(value,title){const rows=Object.entries(value).filter(([key])=>!['a','b','x','y','vx','vy'].includes(key)).map(([key,item])=>`<div class="detail-row"><div class="detail-key">${escapeText(key.replaceAll('_',' '))}</div><div class="detail-value">${escapeText(Array.isArray(item)?item.join(', '):item)}</div></div>`).join('');details.innerHTML=`<h2>${escapeText(title)}</h2>${rows}`;}
function update(){edges.forEach((edge,i)=>{const el=edgeElements[i],label=labelElements[i];el.setAttribute('x1',edge.a.x);el.setAttribute('y1',edge.a.y);el.setAttribute('x2',edge.b.x);el.setAttribute('y2',edge.b.y);label.setAttribute('x',(edge.a.x+edge.b.x)/2);label.setAttribute('y',(edge.a.y+edge.b.y)/2);});nodes.forEach((node,i)=>{nodeElements[i].setAttribute('cx',node.x);nodeElements[i].setAttribute('cy',node.y);nodeLabels[i].setAttribute('x',node.x+12);nodeLabels[i].setAttribute('y',node.y+4);});}
let ticks=0;function simulate(){if(ticks++>220)return;for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){const a=nodes[i],b=nodes[j],dx=a.x-b.x,dy=a.y-b.y,d2=Math.max(80,dx*dx+dy*dy),force=1900/d2;a.vx+=dx*force/Math.sqrt(d2);a.vy+=dy*force/Math.sqrt(d2);b.vx-=dx*force/Math.sqrt(d2);b.vy-=dy*force/Math.sqrt(d2);}for(const edge of edges){const dx=edge.b.x-edge.a.x,dy=edge.b.y-edge.a.y,d=Math.max(1,Math.hypot(dx,dy)),force=(d-130)*.0025;edge.a.vx+=dx/d*force;edge.a.vy+=dy/d*force;edge.b.vx-=dx/d*force;edge.b.vy-=dy/d*force;}for(const node of nodes){node.vx+=(width/2-node.x)*.0007;node.vy+=(height/2-node.y)*.0007;node.vx*=.84;node.vy*=.84;node.x=Math.max(24,Math.min(width-24,node.x+node.vx));node.y=Math.max(24,Math.min(height-24,node.y+node.vy));}update();requestAnimationFrame(simulate);}simulate();
let scale=1,panX=0,panY=0;function transform(){viewport.setAttribute('transform',`translate(${panX} ${panY}) scale(${scale})`);}svg.addEventListener('wheel',event=>{event.preventDefault();scale=Math.max(.2,Math.min(5,scale*(event.deltaY<0?1.12:.89)));transform();},{passive:false});let panning=false,lastX=0,lastY=0;svg.addEventListener('pointerdown',event=>{panning=true;lastX=event.clientX;lastY=event.clientY;svg.setPointerCapture(event.pointerId);});svg.addEventListener('pointermove',event=>{if(!panning)return;panX+=event.clientX-lastX;panY+=event.clientY-lastY;lastX=event.clientX;lastY=event.clientY;transform();});svg.addEventListener('pointerup',()=>panning=false);document.getElementById('fit').addEventListener('click',()=>{scale=1;panX=0;panY=0;transform();});
function applyFilters(){const query=document.getElementById('search').value.toLowerCase(),kind=document.getElementById('kind').value,relation=relationSelect.value;const visible=new Set();nodes.forEach((node,i)=>{const hay=JSON.stringify(node).toLowerCase(),ok=(!query||hay.includes(query))&&(kind==='all'||node.kind===kind);nodeElements[i].classList.toggle('hidden',!ok);nodeLabels[i].classList.toggle('hidden',!ok);nodeElements[i].classList.toggle('match',Boolean(query)&&ok);if(ok)visible.add(node.id);});edges.forEach((edge,i)=>{const ok=visible.has(edge.source)&&visible.has(edge.target)&&(relation==='all'||edge.relation===relation);edgeElements[i].classList.toggle('hidden',!ok);labelElements[i].classList.toggle('hidden',!ok||edges.length>120);});}
document.getElementById('search').addEventListener('input',applyFilters);document.getElementById('kind').addEventListener('change',applyFilters);relationSelect.addEventListener('change',applyFilters);applyFilters();
</script>
</body>
</html>
"""


def _graph_html(reconstruction: AttackReconstruction) -> str:
    nodes = _graph_nodes(reconstruction)[:250]
    selected_ids = {str(item["id"]) for item in nodes}
    edges = [
        item
        for item in _graph_edges(reconstruction)
        if str(item["source"]) in selected_ids and str(item["target"]) in selected_ids
    ][:1_000]
    data = {
        "id": reconstruction.reconstruction_id,
        "seed": reconstruction.seed_transaction_hash,
        "nodes": nodes,
        "edges": edges,
    }
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).replace("<", "\\u003c")
    return GRAPH_TEMPLATE.replace("__DATA__", encoded)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_reconstruction_bundle(
    reconstruction: AttackReconstruction,
    destination: Path,
    *,
    overwrite: bool = False,
) -> BundleResult:
    root = destination.expanduser().resolve()
    if root.exists() and not root.is_dir():
        raise ValueError(f"Case bundle destination is not a directory: {root}")
    paths = [root / name for name in (*RECONSTRUCTION_BUNDLE_FILES, "manifest.json")]
    if any(path.is_symlink() for path in paths):
        raise ValueError("Case bundle files cannot be symbolic links")
    if any(path.exists() for path in paths) and not overwrite:
        raise FileExistsError(
            "Case bundle files already exist; select a new directory or pass --overwrite"
        )
    root.mkdir(parents=True, exist_ok=True)
    context_by_hash = {item.transaction_hash: item for item in reconstruction.contexts}
    transaction_rows = [
        {
            **item.to_dict(),
            "discovery_reasons": ";".join(item.discovery_reasons),
            "decoded_arguments": json.dumps(
                item.decoded_arguments, sort_keys=True, separators=(",", ":")
            ),
        }
        for item in reconstruction.contexts
    ]
    call_rows: list[dict[str, object]] = []
    transfer_rows: list[dict[str, object]] = []
    for case in reconstruction.transactions:
        context = context_by_hash[case.transaction_hash]
        for call in case.calls:
            call_data = call.to_dict()
            call_data["decoded_arguments"] = json.dumps(
                call.decoded_arguments, sort_keys=True, separators=(",", ":")
            )
            call_rows.append(
                {
                    "transaction_hash": case.transaction_hash,
                    "block_number": case.block_number,
                    "transaction_phase": context.phase,
                    "hop": context.hop,
                    **call_data,
                }
            )
        for transfer in case.transfers:
            transfer_rows.append(
                {
                    "transaction_hash": case.transaction_hash,
                    "block_number": case.block_number,
                    "transaction_phase": context.phase,
                    "hop": context.hop,
                    **transfer.to_dict(),
                }
            )
    entity_rows = [
        {
            **item.to_dict(),
            "roles": ",".join(item.roles),
            "transaction_hashes": ",".join(item.transaction_hashes),
            "transaction_count": len(item.transaction_hashes),
            "runtime_code_sha256s": ",".join(item.runtime_code_sha256s),
        }
        for item in reconstruction.entities
    ]
    relationship_rows = [item.to_dict() for item in reconstruction.edges]
    timeline_rows = [item.to_dict() for item in reconstruction.timeline]
    artifacts: dict[str, str] = {
        "case.json": json.dumps(reconstruction.to_dict(), indent=2, sort_keys=True) + "\n",
        "report.md": render_reconstruction_report(reconstruction),
        "transactions.csv": _csv_text(
            (
                "transaction_hash",
                "block_number",
                "transaction_index",
                "block_timestamp",
                "phase",
                "hop",
                "relevance_score",
                "discovery_reasons",
                "status",
                "sender",
                "recipient",
                "selector",
                "function_signature",
                "function_confidence",
                "function_source",
                "decoded_arguments",
                "call_count",
                "transfer_count",
                "trace_available",
            ),
            transaction_rows,
        ),
        "calls.csv": _csv_text(
            (
                "transaction_hash",
                "block_number",
                "transaction_phase",
                "hop",
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
            call_rows,
        ),
        "transfers.csv": _csv_text(
            (
                "transaction_hash",
                "block_number",
                "transaction_phase",
                "hop",
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
            transfer_rows,
        ),
        "entities.csv": _csv_text(
            (
                "address",
                "kind",
                "label",
                "roles",
                "transaction_hashes",
                "transaction_count",
                "first_block",
                "last_block",
                "code_observed",
                "code_bytes_min",
                "code_bytes_max",
                "runtime_code_sha256s",
            ),
            entity_rows,
        ),
        "relationships.csv": _csv_text(
            (
                "edge_id",
                "transaction_hash",
                "block_number",
                "hop",
                "source",
                "target",
                "relation",
                "asset_type",
                "asset_address",
                "asset_symbol",
                "raw_amount",
                "amount_display",
                "evidence_ref",
            ),
            relationship_rows,
        ),
        "timeline.csv": _csv_text(
            (
                "entry_id",
                "transaction_hash",
                "block_number",
                "block_timestamp",
                "transaction_phase",
                "transaction_index",
                "event_phase",
                "event_order",
                "event_type",
                "summary",
                "evidence_ref",
            ),
            timeline_rows,
        ),
        "graph.graphml": _graphml(reconstruction),
        "graph.html": _graph_html(reconstruction),
    }
    written: list[Path] = []
    for name in RECONSTRUCTION_BUNDLE_FILES:
        path = root / name
        path.write_text(artifacts[name], encoding="utf-8", newline="")
        written.append(path)
    manifest_payload: dict[str, Any] = {
        "schema_version": 2,
        "reconstruction_id": reconstruction.reconstruction_id,
        "seed_transaction_hash": reconstruction.seed_transaction_hash,
        "chain_id": reconstruction.chain_id,
        "generated_at": reconstruction.generated_at,
        "coverage": reconstruction.coverage.to_dict(),
        "files": [
            {"path": path.name, "bytes": path.stat().st_size, "sha256": _sha256(path)}
            for path in written
        ],
    }
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return BundleResult(root, tuple(written), manifest)
