from __future__ import annotations

import html
import json
import os
from dataclasses import dataclass

from white_radar.config import TelegramConfig
from white_radar.http import HttpError, request_json
from white_radar.models import ChainConfig, RadarEvent, Severity

SEVERITY_ICON = {
    Severity.INFORMATIONAL: "⚪",
    Severity.LOW: "🔵",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🟠",
    Severity.CRITICAL: "🔴",
}


def short_address(value: str | None) -> str:
    if not value:
        return "unknown"
    return f"{value[:8]}…{value[-6:]}"


def _safe(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_event(event: RadarEvent, chain: ChainConfig) -> str:
    icon = SEVERITY_ICON[event.severity]
    lines = [
        "<b>WHITE RADAR</b>",
        f"{icon} <b>{_safe(event.title)}</b>",
        f"Priority: <b>{event.score}/100</b> · {_safe(event.severity.value.upper())}",
        f"Confidence: {event.confidence:.0%}",
        "",
        f"<b>Network:</b> {_safe(chain.display_name)} ({chain.chain_id})",
    ]
    if event.block_number is not None:
        lines.append(f"<b>Block:</b> {event.block_number:,}")
    if event.subject_address:
        lines.append(f"<b>Contract:</b> <code>{_safe(event.subject_address)}</code>")
    if event.deployer_address:
        lines.append(f"<b>Deployer:</b> <code>{_safe(event.deployer_address)}</code>")

    metadata = event.metadata
    name = metadata.get("contract_name")
    if name:
        lines.append(f"<b>Name:</b> {_safe(name)}")
    verification = metadata.get("verification_source") or "not verified"
    lines.append(f"<b>Verification:</b> {_safe(verification)}")
    bytecode_size = metadata.get("bytecode_size")
    if bytecode_size is not None:
        lines.append(f"<b>Runtime:</b> {int(bytecode_size):,} bytes")
    cluster_size = metadata.get("deployer_cluster_size")
    if cluster_size:
        lines.append(f"<b>Deployer cluster:</b> {int(cluster_size)} contracts / 24h")
    if metadata.get("is_proxy"):
        lines.append("<b>Architecture:</b> EIP-1967 proxy")
        if metadata.get("implementation"):
            lines.append(f"<b>Implementation:</b> <code>{_safe(metadata['implementation'])}</code>")

    lines.extend(["", "<b>Why this surfaced</b>"])
    lines.extend(f"• {_safe(reason)}" for reason in event.reasons[:5])

    related = metadata.get("related_contracts") or []
    if related:
        lines.extend(["", "<b>Related contracts from the same deployer</b>"])
        for item in related[:5]:
            if isinstance(item, dict):
                label = item.get("contract_name") or short_address(str(item.get("address", "")))
                lines.append(f"• {_safe(label)} · block {_safe(item.get('block_number', '?'))}")

    lines.extend(
        [
            "",
            "<b>Recommended action</b>",
            _safe(event.recommended_action),
            "",
            f"Case ID: <code>{_safe(event.event_id)}</code>",
        ]
    )
    return "\n".join(lines)[:4000]


def event_buttons(event: RadarEvent, chain: ChainConfig) -> list[list[dict[str, str]]]:
    buttons: list[dict[str, str]] = []
    if event.tx_hash:
        buttons.append({"text": "Transaction", "url": f"{chain.explorer_url}/tx/{event.tx_hash}"})
    if event.subject_address:
        buttons.append(
            {"text": "Contract", "url": f"{chain.explorer_url}/address/{event.subject_address}"}
        )
    bounty = event.metadata.get("bounty_url")
    if isinstance(bounty, str) and bounty.startswith("https://"):
        buttons.append({"text": "Authorized scope", "url": bounty})
    return [buttons] if buttons else []


@dataclass(slots=True)
class TelegramNotifier:
    config: TelegramConfig
    dry_run: bool
    timeout: int
    retries: int

    def should_send(self, event: RadarEvent, chain: ChainConfig) -> bool:
        return (
            self.config.enabled
            and event.score >= self.config.minimum_score
            and (self.config.send_testnet_alerts or not chain.is_testnet)
        )

    def send(self, event: RadarEvent, chain: ChainConfig) -> bool:
        if not self.should_send(event, chain):
            return False
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat_id:
            raise RuntimeError("Telegram is enabled but TELEGRAM_BOT_TOKEN/CHAT_ID is missing")
        if self.dry_run:
            return False
        payload: dict[str, object] = {
            "chat_id": chat_id,
            "text": render_event(event, chain),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        buttons = event_buttons(event, chain)
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": buttons}
        try:
            response = request_json(
                "POST",
                f"https://api.telegram.org/bot{token}/sendMessage",
                timeout=self.timeout,
                retries=self.retries,
                payload=payload,
            )
        except HttpError as exc:
            raise RuntimeError(f"Telegram delivery failed: {exc}") from exc
        if not isinstance(response, dict) or not response.get("ok"):
            raise RuntimeError(f"Telegram rejected the alert: {json.dumps(response)[:300]}")
        return True
