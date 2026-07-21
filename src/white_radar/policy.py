from __future__ import annotations

import dataclasses
import hashlib
import re
import tomllib
from pathlib import Path
from typing import Any

from white_radar.config import ConfigurationError

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
SELECTOR_RE = re.compile(r"^0x[a-fA-F0-9]{8}$")
MAX_POLICY_BYTES = 1_048_576
MAX_CALLDATA_BYTES = 8_192
INVARIANT_DECODERS = frozenset({"uint256", "int256", "address", "bool", "bytes32"})
INVARIANT_OPERATORS = frozenset({"eq", "ne", "gt", "gte", "lt", "lte", "zero", "nonzero"})


@dataclasses.dataclass(frozen=True, slots=True)
class ProtocolInvariant:
    name: str
    target: str
    call_data: str
    decode_as: str
    operator: str
    expected: str | int | bool | None
    score: int
    alert_on_error: bool


@dataclasses.dataclass(frozen=True, slots=True)
class ProtocolPolicy:
    chain_id: int
    address: str
    protocol: str
    authorized_senders: frozenset[str]
    allowed_selectors: frozenset[str]
    critical_selectors: frozenset[str]
    max_native_value_wei: int | None
    incident_sla_minutes: int | None
    selector_labels: tuple[tuple[str, str], ...] = ()
    invariants: tuple[ProtocolInvariant, ...] = ()

    def selector_label(self, selector: str) -> str | None:
        normalized = selector.lower()
        return next((label for key, label in self.selector_labels if key == normalized), None)


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyFinding:
    code: str
    score_delta: int
    reason: str

    def to_dict(self) -> dict[str, str | int]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyAssessment:
    baseline_match: bool
    findings: tuple[PolicyFinding, ...]

    @property
    def score_delta(self) -> int:
        return sum(item.score_delta for item in self.findings)


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyBook:
    policies: tuple[ProtocolPolicy, ...]
    source_sha256: str | None = None

    @classmethod
    def empty(cls) -> PolicyBook:
        return cls(())

    def contract(self, chain_id: int, address: str | None) -> ProtocolPolicy | None:
        if not address:
            return None
        normalized = address.lower()
        return next(
            (
                policy
                for policy in self.policies
                if policy.chain_id == chain_id and policy.address == normalized
            ),
            None,
        )

    def for_chain(self, chain_id: int) -> tuple[ProtocolPolicy, ...]:
        return tuple(policy for policy in self.policies if policy.chain_id == chain_id)


def _address(value: object, field: str) -> str:
    normalized = str(value).lower()
    if not ADDRESS_RE.fullmatch(normalized):
        raise ConfigurationError(f"Invalid {field}: {value}")
    return normalized


def _selectors(values: object, field: str) -> frozenset[str]:
    if not isinstance(values, list):
        raise ConfigurationError(f"{field} must be a TOML array")
    normalized = frozenset(str(value).lower() for value in values)
    if any(not SELECTOR_RE.fullmatch(value) for value in normalized):
        raise ConfigurationError(f"Invalid selector in {field}")
    return normalized


def _call_data(value: object) -> str:
    normalized = str(value).lower()
    if not normalized.startswith("0x") or len(normalized) % 2:
        raise ConfigurationError("Invariant call_data must be even-length hexadecimal data")
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise ConfigurationError("Invariant call_data is not valid hexadecimal data") from exc
    if len(raw) < 4 or len(raw) > MAX_CALLDATA_BYTES:
        raise ConfigurationError(f"Invariant call_data must contain 4-{MAX_CALLDATA_BYTES} bytes")
    return normalized


def _invariants(values: object, *, default_target: str) -> tuple[ProtocolInvariant, ...]:
    if not isinstance(values, list):
        raise ConfigurationError("invariants must be a TOML array of tables")
    invariants: list[ProtocolInvariant] = []
    names: set[str] = set()
    for item in values:
        if not isinstance(item, dict):
            raise ConfigurationError("Each invariant must be a TOML table")
        name = str(item.get("name") or "").strip()
        if not name or len(name) > 100:
            raise ConfigurationError("Invariant name must contain 1-100 characters")
        if name in names:
            raise ConfigurationError(f"Duplicate invariant name: {name}")
        names.add(name)
        decode_as = str(item.get("decode_as", "uint256")).lower()
        operator = str(item.get("operator", "eq")).lower()
        if decode_as not in INVARIANT_DECODERS:
            raise ConfigurationError(f"Unsupported invariant decoder: {decode_as}")
        if operator not in INVARIANT_OPERATORS:
            raise ConfigurationError(f"Unsupported invariant operator: {operator}")
        expected = item.get("expected")
        if operator not in {"zero", "nonzero"} and expected is None:
            raise ConfigurationError(f"Invariant {name} requires expected")
        invariants.append(
            ProtocolInvariant(
                name=name,
                target=_address(item.get("target", default_target), "invariant target"),
                call_data=_call_data(item.get("call_data", "")),
                decode_as=decode_as,
                operator=operator,
                expected=expected,
                score=max(0, min(100, int(item.get("score", 85)))),
                alert_on_error=bool(item.get("alert_on_error", True)),
            )
        )
    return tuple(invariants)


def load_policy_book(path: Path) -> PolicyBook:
    """Load a bounded, deterministic protocol policy pack.

    Missing files are treated as an empty policy book so confirmed monitoring can run before a
    protocol baseline has been configured.
    """

    if not path.exists():
        return PolicyBook.empty()
    if path.stat().st_size > MAX_POLICY_BYTES:
        raise ConfigurationError(
            f"Policy file exceeds the {MAX_POLICY_BYTES}-byte input limit: {path}"
        )
    raw = path.read_bytes()
    try:
        data: dict[str, Any] = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"Invalid TOML in {path}: {exc}") from exc
    if int(data.get("schema_version", 1)) not in {1, 2}:
        raise ConfigurationError("Unsupported policy schema_version")

    configured_policies = data.get("protocols", [])
    if not isinstance(configured_policies, list):
        raise ConfigurationError("protocols must be a TOML array of tables")
    policies: list[ProtocolPolicy] = []
    seen: set[tuple[int, str]] = set()
    for item in configured_policies:
        if not isinstance(item, dict):
            raise ConfigurationError("Each protocol policy must be a TOML table")
        chain_id = int(item["chain_id"])
        address = _address(item["address"], "policy contract address")
        identity = (chain_id, address)
        if identity in seen:
            raise ConfigurationError(f"Duplicate protocol policy: {chain_id}:{address}")
        seen.add(identity)

        maximum = item.get("max_native_value_wei")
        max_native_value_wei = int(maximum) if maximum is not None else None
        if max_native_value_wei is not None and max_native_value_wei < 0:
            raise ConfigurationError("max_native_value_wei cannot be negative")
        configured_sla = item.get("incident_sla_minutes")
        incident_sla_minutes = int(configured_sla) if configured_sla is not None else None
        if incident_sla_minutes is not None and incident_sla_minutes < 1:
            raise ConfigurationError("incident_sla_minutes must be positive")

        authorized = item.get("authorized_senders", [])
        if not isinstance(authorized, list):
            raise ConfigurationError("authorized_senders must be a TOML array")
        protocol = str(item["protocol"]).strip()
        if not protocol:
            raise ConfigurationError("Policy protocol cannot be empty")
        configured_labels = item.get("selector_labels", {})
        if not isinstance(configured_labels, dict):
            raise ConfigurationError("selector_labels must be a TOML table")
        selector_labels = tuple(
            sorted(
                (
                    next(iter(_selectors([selector], "selector_labels"))),
                    str(label).strip(),
                )
                for selector, label in configured_labels.items()
            )
        )
        if any(not label for _, label in selector_labels):
            raise ConfigurationError("selector_labels values cannot be empty")
        policies.append(
            ProtocolPolicy(
                chain_id=chain_id,
                address=address,
                protocol=protocol,
                authorized_senders=frozenset(
                    _address(value, "configured sender") for value in authorized
                ),
                allowed_selectors=_selectors(
                    item.get("allowed_selectors", []), "allowed_selectors"
                ),
                critical_selectors=_selectors(
                    item.get("critical_selectors", []), "critical_selectors"
                ),
                max_native_value_wei=max_native_value_wei,
                incident_sla_minutes=incident_sla_minutes,
                selector_labels=selector_labels,
                invariants=_invariants(item.get("invariants", []), default_target=address),
            )
        )
    return PolicyBook(tuple(policies), hashlib.sha256(raw).hexdigest())


def assess_pending(
    policy: ProtocolPolicy,
    *,
    sender: str | None,
    selector: str,
    native_value_wei: int,
) -> PolicyAssessment:
    """Compare pending metadata with an operator-approved baseline.

    Findings are explainable triage signals. They do not establish intent or exploitability.
    """

    findings: list[PolicyFinding] = []
    normalized_sender = (sender or "").lower()
    if policy.authorized_senders and normalized_sender not in policy.authorized_senders:
        findings.append(
            PolicyFinding(
                "sender_outside_baseline",
                15,
                "The sender is outside the protocol-supplied sender baseline.",
            )
        )
    if policy.allowed_selectors and selector not in policy.allowed_selectors:
        findings.append(
            PolicyFinding(
                "selector_outside_baseline",
                10,
                "The selector is outside the protocol-supplied call baseline.",
            )
        )
    if selector in policy.critical_selectors:
        findings.append(
            PolicyFinding(
                "critical_selector",
                0,
                "The selector is marked critical in the protocol policy.",
            )
        )
    if policy.max_native_value_wei is not None and native_value_wei > policy.max_native_value_wei:
        findings.append(
            PolicyFinding(
                "native_value_above_baseline",
                15,
                "The native value exceeds the protocol-supplied baseline.",
            )
        )
    baseline_match = not any(finding.score_delta > 0 for finding in findings)
    return PolicyAssessment(baseline_match, tuple(findings))
