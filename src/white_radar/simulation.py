from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any

from white_radar.rpc import JsonRpcClient, RpcError, hex_to_int

CALL_FIELDS = (
    "from",
    "to",
    "gas",
    "gasPrice",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "value",
    "type",
    "accessList",
)
MAX_TRACE_FRAMES = 512
MAX_TOUCHED_ADDRESSES = 64


@dataclasses.dataclass(frozen=True, slots=True)
class TraceSummary:
    call_count: int = 0
    max_depth: int = 0
    delegatecall_count: int = 0
    staticcall_count: int = 0
    create_count: int = 0
    selfdestruct_count: int = 0
    value_call_count: int = 0
    reverted_call_count: int = 0
    truncated: bool = False
    touched_addresses: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class SimulationFinding:
    code: str
    category: str
    score_delta: int
    summary: str

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class SimulationResult:
    status: str
    block_number: int
    block_hash: str | None
    transaction_fingerprint: str
    return_data_size: int = 0
    return_data_sha256: str | None = None
    error_class: str | None = None
    trace: TraceSummary | None = None
    findings: tuple[SimulationFinding, ...] = ()

    @property
    def score_delta(self) -> int:
        return sum(item.score_delta for item in self.findings)

    def to_dict(self) -> dict[str, object]:
        result = dataclasses.asdict(self)
        result["score_delta"] = self.score_delta
        return result


def build_call_object(transaction: dict[str, object]) -> dict[str, object]:
    """Build the bounded JSON-RPC call object used for state-pinned simulation."""

    result = {
        field: transaction[field] for field in CALL_FIELDS if transaction.get(field) is not None
    }
    calldata = str(transaction.get("input") or transaction.get("data") or "0x")
    if not calldata.startswith("0x") or len(calldata) % 2:
        raise ValueError("Transaction calldata must be even-length hexadecimal data")
    try:
        bytes.fromhex(calldata[2:])
    except ValueError as exc:
        raise ValueError("Transaction calldata is not valid hexadecimal data") from exc
    result["data"] = calldata
    return result


def transaction_fingerprint(transaction: dict[str, object]) -> str:
    call = build_call_object(transaction)
    calldata = str(call.pop("data"))
    call["data_sha256"] = hashlib.sha256(bytes.fromhex(calldata[2:])).hexdigest()
    for field in ("nonce", "chainId"):
        if transaction.get(field) is not None:
            call[field] = transaction[field]
    material = json.dumps(call, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def summarize_call_trace(trace: dict[str, Any]) -> TraceSummary:
    counts = {
        "call_count": 0,
        "max_depth": 0,
        "delegatecall_count": 0,
        "staticcall_count": 0,
        "create_count": 0,
        "selfdestruct_count": 0,
        "value_call_count": 0,
        "reverted_call_count": 0,
    }
    touched: set[str] = set()
    stack: list[tuple[object, int]] = [(trace, 0)]
    truncated = False
    while stack:
        frame, depth = stack.pop()
        if not isinstance(frame, dict):
            continue
        if counts["call_count"] >= MAX_TRACE_FRAMES:
            truncated = True
            break
        counts["call_count"] += 1
        counts["max_depth"] = max(counts["max_depth"], depth)
        call_type = str(frame.get("type") or "CALL").upper()
        if call_type == "DELEGATECALL":
            counts["delegatecall_count"] += 1
        elif call_type == "STATICCALL":
            counts["staticcall_count"] += 1
        elif call_type in {"CREATE", "CREATE2"}:
            counts["create_count"] += 1
        elif call_type == "SELFDESTRUCT":
            counts["selfdestruct_count"] += 1
        if hex_to_int(str(frame.get("value") or "0x0")) > 0:
            counts["value_call_count"] += 1
        if frame.get("error") or frame.get("revertReason"):
            counts["reverted_call_count"] += 1
        destination = str(frame.get("to") or "").lower()
        if destination.startswith("0x") and len(destination) == 42:
            touched.add(destination)
        children = frame.get("calls") or []
        if isinstance(children, list):
            stack.extend((child, depth + 1) for child in reversed(children))
    return TraceSummary(
        **counts,
        truncated=truncated or len(touched) > MAX_TOUCHED_ADDRESSES,
        touched_addresses=tuple(sorted(touched)[:MAX_TOUCHED_ADDRESSES]),
    )


def assess_trace(summary: TraceSummary) -> tuple[SimulationFinding, ...]:
    findings: list[SimulationFinding] = []
    if summary.selfdestruct_count:
        findings.append(
            SimulationFinding(
                "destructive_execution_path",
                "runtime_control",
                15,
                "The simulated call graph contains a SELFDESTRUCT execution frame.",
            )
        )
    if summary.create_count:
        findings.append(
            SimulationFinding(
                "dynamic_contract_creation",
                "runtime_control",
                8,
                "The simulated call graph creates one or more contracts.",
            )
        )
    if summary.delegatecall_count:
        findings.append(
            SimulationFinding(
                "delegated_execution_path",
                "upgradeability_and_dispatch",
                5,
                "The simulated call graph enters delegated execution.",
            )
        )
    if summary.value_call_count >= 2:
        findings.append(
            SimulationFinding(
                "multi_hop_native_value_flow",
                "asset_flow",
                7,
                "The simulated call graph contains multiple value-bearing execution frames.",
            )
        )
    if summary.max_depth >= 8:
        findings.append(
            SimulationFinding(
                "deep_execution_graph",
                "business_logic",
                5,
                "The simulated call graph reaches a depth of eight or more frames.",
            )
        )
    return tuple(findings)


def simulate_transaction(
    rpc: JsonRpcClient,
    transaction: dict[str, object],
    *,
    block_number: int | None = None,
    include_trace: bool = False,
) -> SimulationResult:
    """Execute an RPC-side, state-pinned call without submitting a transaction."""

    selected_block = rpc.block_number() if block_number is None else max(0, block_number)
    block = rpc.block(selected_block, full_transactions=False) or {}
    block_hash = str(block.get("hash") or "") or None
    call = build_call_object(transaction)
    status = "succeeded"
    error_class: str | None = None
    return_size = 0
    return_sha256: str | None = None
    try:
        raw_result = rpc.eth_call(call, hex(selected_block))
        encoded = raw_result.removeprefix("0x")
        if len(encoded) % 2 == 0:
            return_data = bytes.fromhex(encoded)
            return_size = len(return_data)
            return_sha256 = hashlib.sha256(return_data).hexdigest()
    except (RpcError, ValueError) as exc:
        status = "reverted" if isinstance(exc, RpcError) else "unavailable"
        error_class = type(exc).__name__

    trace_summary: TraceSummary | None = None
    if include_trace:
        try:
            raw_trace = rpc.trace_call(call, hex(selected_block))
            if raw_trace:
                trace_summary = summarize_call_trace(raw_trace)
        except RpcError:
            if error_class is None:
                error_class = "TraceUnavailable"
    findings = assess_trace(trace_summary) if trace_summary else ()
    return SimulationResult(
        status=status,
        block_number=selected_block,
        block_hash=block_hash,
        transaction_fingerprint=transaction_fingerprint(transaction),
        return_data_size=return_size,
        return_data_sha256=return_sha256,
        error_class=error_class,
        trace=trace_summary,
        findings=findings,
    )
