from __future__ import annotations

import collections
import html
from typing import Any

from white_radar.models import ChainConfig, IncidentRecord, RadarEvent


def _plain(value: object, *, limit: int = 500) -> str:
    text = " ".join(str(value).split())
    return text.replace("`", "'")[:limit]


def render_incident_report(
    event: RadarEvent,
    chain: ChainConfig,
    *,
    graph: dict[str, list[dict[str, Any]]] | None = None,
    incident: IncidentRecord | None = None,
) -> str:
    """Render a reproducible Markdown incident-analysis report."""

    lines = [
        f"# White Radar case {_plain(event.event_id)}",
        "",
        "> Status: security signal awaiting evidence-based disposition.",
        "",
        "## Executive summary",
        "",
        _plain(event.summary),
        "",
        "## Classification",
        "",
        f"- Event type: `{_plain(event.event_type)}`",
        f"- Priority: **{event.score}/100 ({event.severity.value.upper()})**",
        f"- Evidence confidence: **{event.confidence:.0%}**",
        f"- Observed at: `{_plain(event.observed_at)}`",
        f"- Network: **{_plain(chain.display_name)}** (`{chain.chain_id}`)",
    ]
    if event.block_number is not None:
        lines.append(f"- Block: `{event.block_number}`")
    if event.subject_address:
        lines.append(f"- Subject: `{_plain(event.subject_address)}`")
    if event.deployer_address:
        lines.append(f"- Deployer or sender: `{_plain(event.deployer_address)}`")
    if event.tx_hash:
        lines.append(f"- Transaction: `{_plain(event.tx_hash)}`")
    if incident:
        lines.extend(
            [
                "",
                "## Incident workflow",
                "",
                f"- Incident ID: `{_plain(incident.incident_id)}`",
                f"- Status: **{incident.status.value.upper()}**",
                f"- Acknowledgement deadline: `{_plain(incident.due_at)}`",
                f"- Owner: `{_plain(incident.owner or 'unassigned')}`",
            ]
        )

    lines.extend(["", "## Why this case surfaced", ""])
    lines.extend(f"- {_plain(reason)}" for reason in event.reasons)
    lines.extend(
        [
            "",
            "## Recommended response",
            "",
            _plain(event.recommended_action, limit=1500),
            "",
            "## Evidence",
            "",
        ]
    )
    if event.evidence:
        lines.extend(
            f"- [{_plain(label)}]({_plain(url, limit=1000)})"
            for label, url in sorted(event.evidence.items())
        )
    else:
        lines.append("- No external evidence links were recorded.")

    metadata = event.metadata
    lines.extend(["", "## Technical context", ""])
    context_fields = (
        "protocol",
        "role",
        "contract_name",
        "verification_source",
        "bytecode_size",
        "normalized_bytecode_sha256",
        "creation_type",
        "trace_depth",
        "is_proxy",
        "implementation",
        "admin",
        "beacon",
        "selector",
        "function_signature",
        "decoded_arguments",
        "abi_sha256",
        "native_value_wei",
        "calldata_size_bytes",
        "simulation",
        "invariant",
        "proxy_snapshot",
        "changes",
    )
    emitted = False
    for field in context_fields:
        value = metadata.get(field)
        if value is None or value == "" or value == []:
            continue
        lines.append(f"- `{field}`: `{_plain(value, limit=1000)}`")
        emitted = True
    if not emitted:
        lines.append("- No additional technical context was recorded.")

    similar = metadata.get("similar_contracts") or []
    if isinstance(similar, list) and similar:
        lines.extend(["", "## Bytecode similarity", ""])
        for item in similar[:8]:
            if not isinstance(item, dict):
                continue
            lines.append(
                "- `{}` — similarity {:.1%}{}".format(
                    _plain(item.get("address", "unknown")),
                    float(item.get("similarity", 0.0)),
                    " (exact normalized match)" if item.get("exact_normalized_match") else "",
                )
            )

    if graph and graph.get("nodes"):
        lines.extend(["", "## Identity neighborhood", ""])
        lines.append(f"- Nodes: {len(graph['nodes'])}")
        lines.append(f"- Evidence-backed relationships: {len(graph.get('edges', []))}")
        node_labels = {
            str(node.get("node_id")): _plain(
                node.get("label") or node.get("value") or node.get("node_id", "?"),
                limit=200,
            )
            for node in graph["nodes"]
        }
        for edge in graph.get("edges", [])[:20]:
            lines.append(
                "- `{}` — **{}** → `{}`".format(
                    node_labels.get(
                        str(edge.get("source_node_id")),
                        _plain(edge.get("source_node_id", "?")),
                    ),
                    _plain(edge.get("relation", "RELATED_TO")),
                    node_labels.get(
                        str(edge.get("target_node_id")),
                        _plain(edge.get("target_node_id", "?")),
                    ),
                )
            )

    lines.extend(
        [
            "",
            "## Incident response checklist",
            "",
            "- [ ] Validate the signal against an independent RPC source.",
            "- [ ] Correlate governance, deployment, and protocol change records.",
            "- [ ] Preserve the pinned block, transaction, policy digest, and relevant hashes.",
            "- [ ] Assign an incident owner and acknowledgement deadline.",
            "- [ ] Route confirmed findings through the configured response contact.",
            "- [ ] Record the final disposition and recovery evidence.",
            "",
            "Generated by White Radar.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_digest(
    events: list[RadarEvent],
    chains: dict[str, ChainConfig],
    *,
    hours: int,
    incidents: list[IncidentRecord] | None = None,
    overdue_incident_ids: set[str] | None = None,
) -> str:
    """Render a compact Telegram HTML digest without claiming exploitability."""

    severity = collections.Counter(event.severity.value for event in events)
    event_types = collections.Counter(event.event_type for event in events)
    chain_counts = collections.Counter(event.chain for event in events)
    lines = [
        "<b>WHITE RADAR DIGEST</b>",
        f"Window: last {max(1, hours)}h",
        f"Cases: <b>{len(events)}</b>",
        "",
        "<b>Severity</b>",
        (
            f"Critical {severity['critical']} · High {severity['high']} · "
            f"Medium {severity['medium']} · Low {severity['low']} · "
            f"Info {severity['informational']}"
        ),
    ]
    if incidents is not None:
        open_statuses = {"new", "acknowledged", "investigating", "monitoring"}
        open_cases = [item for item in incidents if item.status.value in open_statuses]
        overdue = overdue_incident_ids or set()
        lines.extend(
            [
                "",
                "<b>Incident workflow</b>",
                f"Open {len(open_cases)} · Overdue {len(overdue)}",
            ]
        )
    if chain_counts:
        lines.extend(["", "<b>Networks</b>"])
        for name, count in chain_counts.most_common():
            display = chains[name].display_name if name in chains else name
            lines.append(f"• {html.escape(display)}: {count}")
    if event_types:
        lines.extend(["", "<b>Signals</b>"])
        for name, count in event_types.most_common():
            lines.append(f"• {html.escape(name)}: {count}")
    if events:
        lines.extend(["", "<b>Highest priority cases</b>"])
        top = sorted(events, key=lambda event: (event.score, event.observed_at), reverse=True)[:8]
        for event in top:
            subject = event.subject_address or event.tx_hash or "no subject"
            escaped_title = html.escape(event.title)
            escaped_subject = html.escape(subject)
            escaped_case_id = html.escape(event.event_id)
            lines.append(
                f"• <b>{event.score}/100</b> {escaped_title} · "
                f"<code>{escaped_subject}</code> · case <code>{escaped_case_id}</code>"
            )
    else:
        lines.extend(["", "No cases were recorded in this window."])
    lines.extend(["", "Priority reflects configured evidence and analysis signals."])
    return "\n".join(lines)[:4000]
