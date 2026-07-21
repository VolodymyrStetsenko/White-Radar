from __future__ import annotations

import dataclasses
from typing import Any

from white_radar.policy import ProtocolInvariant, ProtocolPolicy
from white_radar.rpc import JsonRpcClient, RpcError


@dataclasses.dataclass(frozen=True, slots=True)
class InvariantCheck:
    name: str
    target: str
    status: str
    observed: str | int | bool | None
    expected: str | int | bool | None
    operator: str
    score: int
    block_number: int
    block_hash: str | None
    error_class: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def decode_return_data(data: str, decode_as: str) -> str | int | bool:
    if not data.startswith("0x"):
        raise ValueError("Invariant return data must be hexadecimal")
    try:
        raw = bytes.fromhex(data[2:])
    except ValueError as exc:
        raise ValueError("Invariant return data is not valid hexadecimal") from exc
    if len(raw) < 32:
        raise ValueError("Invariant return data is shorter than one ABI word")
    word = raw[:32]
    if decode_as == "address":
        return "0x" + word[-20:].hex()
    if decode_as == "bool":
        value = int.from_bytes(word, "big")
        if value not in {0, 1}:
            raise ValueError("Invariant bool return value is not canonical")
        return bool(value)
    if decode_as == "int256":
        return int.from_bytes(word, "big", signed=True)
    if decode_as == "uint256":
        return int.from_bytes(word, "big")
    if decode_as == "bytes32":
        return "0x" + word.hex()
    raise ValueError(f"Unsupported invariant decoder: {decode_as}")


def normalize_expected(value: object, decode_as: str) -> str | int | bool | None:
    if value is None:
        return None
    if decode_as == "address":
        text = str(value).lower()
        if not text.startswith("0x") or len(text) != 42:
            raise ValueError("Invariant expected address is invalid")
        int(text[2:], 16)
        return text
    if decode_as == "bool":
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
        raise ValueError("Invariant expected bool is invalid")
    if decode_as in {"uint256", "int256"}:
        if isinstance(value, int):
            return value
        return int(str(value), 0)
    if decode_as == "bytes32":
        text = str(value).lower()
        if not text.startswith("0x") or len(text) != 66:
            raise ValueError("Invariant expected bytes32 is invalid")
        int(text[2:], 16)
        return text
    raise ValueError(f"Unsupported invariant decoder: {decode_as}")


def compare_values(
    observed: str | int | bool,
    expected: str | int | bool | None,
    operator: str,
) -> bool:
    zero_values = (0, "0x" + "0" * 40, "0x" + "0" * 64)
    if operator == "zero":
        return observed in zero_values
    if operator == "nonzero":
        return observed not in zero_values
    if expected is None:
        raise ValueError(f"Invariant operator {operator} requires an expected value")
    if operator == "eq":
        return observed == expected
    if operator == "ne":
        return observed != expected
    if not isinstance(observed, int) or isinstance(observed, bool):
        raise ValueError(f"Invariant operator {operator} requires an integer decoder")
    if not isinstance(expected, int) or isinstance(expected, bool):
        raise ValueError(f"Invariant operator {operator} requires an integer expected value")
    comparisons = {
        "gt": observed > expected,
        "gte": observed >= expected,
        "lt": observed < expected,
        "lte": observed <= expected,
    }
    if operator not in comparisons:
        raise ValueError(f"Unsupported invariant operator: {operator}")
    return comparisons[operator]


def check_invariant(
    rpc: JsonRpcClient,
    invariant: ProtocolInvariant,
    *,
    block_number: int,
    block_hash: str | None,
) -> InvariantCheck:
    expected: str | int | bool | None = None
    try:
        expected = normalize_expected(invariant.expected, invariant.decode_as)
        raw = rpc.eth_call(
            {"to": invariant.target, "data": invariant.call_data},
            hex(block_number),
        )
        observed = decode_return_data(raw, invariant.decode_as)
        matched = compare_values(observed, expected, invariant.operator)
        return InvariantCheck(
            name=invariant.name,
            target=invariant.target,
            status="ok" if matched else "violated",
            observed=observed,
            expected=expected,
            operator=invariant.operator,
            score=invariant.score,
            block_number=block_number,
            block_hash=block_hash,
        )
    except (RpcError, ValueError) as exc:
        return InvariantCheck(
            name=invariant.name,
            target=invariant.target,
            status="error" if invariant.alert_on_error else "unavailable",
            observed=None,
            expected=expected,
            operator=invariant.operator,
            score=invariant.score,
            block_number=block_number,
            block_hash=block_hash,
            error_class=type(exc).__name__,
        )


def check_policy_invariants(
    rpc: JsonRpcClient,
    policy: ProtocolPolicy,
    *,
    block_number: int,
    block_hash: str | None,
) -> tuple[InvariantCheck, ...]:
    return tuple(
        check_invariant(
            rpc,
            invariant,
            block_number=block_number,
            block_hash=block_hash,
        )
        for invariant in policy.invariants
    )
