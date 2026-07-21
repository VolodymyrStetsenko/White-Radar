from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def severity_for_score(score: int) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 50:
        return Severity.MEDIUM
    if score >= 30:
        return Severity.LOW
    return Severity.INFORMATIONAL


def stable_event_id(*parts: object) -> str:
    material = "|".join(str(part).lower() for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


@dataclasses.dataclass(frozen=True, slots=True)
class ChainConfig:
    name: str
    display_name: str
    chain_id: int
    enabled: bool
    is_testnet: bool
    rpc_http_env: str
    rpc_ws_env: str
    explorer_url: str
    confirmations: int = 3
    initial_lookback_blocks: int = 3
    max_blocks_per_cycle: int = 12
    monitor_global_upgrades: bool = False
    pending_subscription: str = "auto"
    trace_internal_creations: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class ContractWatch:
    chain_id: int
    address: str
    protocol: str
    role: str = "contract"
    bounty_url: str = ""
    contact_uri: str = ""
    critical_selectors: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class DeployerWatch:
    chain_id: int
    address: str
    label: str


@dataclasses.dataclass(frozen=True, slots=True)
class ContractMetadata:
    verified: bool = False
    verification_source: str | None = None
    contract_name: str | None = None
    is_proxy: bool = False
    implementation: str | None = None
    admin: str | None = None
    beacon: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class RadarEvent:
    event_id: str
    observed_at: str
    event_type: str
    title: str
    summary: str
    chain: str
    chain_id: int
    score: int
    severity: Severity
    confidence: float
    reasons: tuple[str, ...]
    recommended_action: str
    subject_address: str | None = None
    deployer_address: str | None = None
    tx_hash: str | None = None
    block_number: int | None = None
    evidence: dict[str, str] = dataclasses.field(default_factory=dict)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = dataclasses.asdict(self)
        value["severity"] = self.severity.value
        return value

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RadarEvent:
        return cls(
            event_id=str(value["event_id"]),
            observed_at=str(value["observed_at"]),
            event_type=str(value["event_type"]),
            title=str(value["title"]),
            summary=str(value["summary"]),
            chain=str(value["chain"]),
            chain_id=int(value["chain_id"]),
            score=int(value["score"]),
            severity=Severity(str(value["severity"])),
            confidence=float(value["confidence"]),
            reasons=tuple(str(item) for item in value.get("reasons", [])),
            recommended_action=str(value["recommended_action"]),
            subject_address=value.get("subject_address"),
            deployer_address=value.get("deployer_address"),
            tx_hash=value.get("tx_hash"),
            block_number=value.get("block_number"),
            evidence=dict(value.get("evidence", {})),
            metadata=dict(value.get("metadata", {})),
        )
