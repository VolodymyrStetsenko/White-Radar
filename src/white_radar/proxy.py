from __future__ import annotations

import dataclasses
from typing import Any

from white_radar.enrichment import EIP1967_SLOTS, storage_word_to_address
from white_radar.fingerprint import fingerprint_bytecode
from white_radar.rpc import JsonRpcClient, RpcError

BEACON_IMPLEMENTATION_SELECTOR = "0x5c60da1b"
PROXIABLE_UUID_SELECTOR = "0x52d1902d"


@dataclasses.dataclass(frozen=True, slots=True)
class ProxyFinding:
    code: str
    score_delta: int
    summary: str

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class ProxySnapshot:
    address: str
    block_number: int
    block_hash: str | None
    implementation: str | None
    admin: str | None
    beacon: str | None
    beacon_implementation: str | None
    effective_implementation: str | None
    implementation_code_sha256: str | None
    implementation_code_size: int
    uups_compatible: bool | None
    findings: tuple[ProxyFinding, ...]

    @property
    def score_delta(self) -> int:
        return sum(item.score_delta for item in self.findings)

    def to_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        result["score_delta"] = self.score_delta
        return result


def _returned_address(value: str) -> str | None:
    if not value.startswith("0x"):
        return None
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError:
        return None
    if len(raw) < 32 or int.from_bytes(raw[:32], "big") == 0:
        return None
    return "0x" + raw[:32][-20:].hex()


def inspect_proxy(
    rpc: JsonRpcClient,
    address: str,
    *,
    block_number: int | None = None,
) -> ProxySnapshot:
    selected_block = rpc.block_number() if block_number is None else max(0, block_number)
    block = rpc.block(selected_block, full_transactions=False) or {}
    block_hash = str(block.get("hash") or "") or None
    block_ref = hex(selected_block)
    slots = {
        name: storage_word_to_address(rpc.storage_at(address, slot, block_ref))
        for name, slot in EIP1967_SLOTS.items()
    }
    beacon_implementation: str | None = None
    if slots["beacon"]:
        try:
            beacon_implementation = _returned_address(
                rpc.eth_call(
                    {"to": slots["beacon"], "data": BEACON_IMPLEMENTATION_SELECTOR},
                    block_ref,
                )
            )
        except RpcError:
            beacon_implementation = None
    effective = slots["implementation"] or beacon_implementation
    code_hash: str | None = None
    code_size = 0
    uups_compatible: bool | None = None
    if effective:
        fingerprint = fingerprint_bytecode(rpc.code(effective, block_ref))
        code_hash = fingerprint.normalized_sha256
        code_size = fingerprint.bytecode_size
        try:
            uuid_value = rpc.eth_call(
                {"to": effective, "data": PROXIABLE_UUID_SELECTOR},
                block_ref,
            )
            uups_compatible = uuid_value.lower() == EIP1967_SLOTS["implementation"].lower()
        except RpcError:
            uups_compatible = None

    findings: list[ProxyFinding] = []
    if (slots["implementation"] or slots["beacon"]) and not effective:
        findings.append(
            ProxyFinding(
                "unresolved_proxy_implementation",
                15,
                "Proxy control state is present but the effective implementation is unresolved.",
            )
        )
    if effective and code_size == 0:
        findings.append(
            ProxyFinding(
                "implementation_without_runtime_code",
                25,
                "The effective implementation address has no runtime bytecode at the pinned block.",
            )
        )
    if slots["implementation"] and slots["beacon"]:
        findings.append(
            ProxyFinding(
                "multiple_proxy_control_planes",
                10,
                "Both implementation and beacon control slots are populated.",
            )
        )
    return ProxySnapshot(
        address=address.lower(),
        block_number=selected_block,
        block_hash=block_hash,
        implementation=slots["implementation"],
        admin=slots["admin"],
        beacon=slots["beacon"],
        beacon_implementation=beacon_implementation,
        effective_implementation=effective,
        implementation_code_sha256=code_hash,
        implementation_code_size=code_size,
        uups_compatible=uups_compatible,
        findings=tuple(findings),
    )
