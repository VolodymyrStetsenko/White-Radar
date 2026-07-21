from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from typing import TYPE_CHECKING, Any

from white_radar.http import HttpError, request_json

if TYPE_CHECKING:
    from white_radar.storage import RadarStore

MAX_ABI_BYTES = 2_000_000
MAX_ABI_ENTRIES = 2_000
ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
MASK_64 = (1 << 64) - 1


def _rotate_left(value: int, amount: int) -> int:
    if amount == 0:
        return value & MASK_64
    return ((value << amount) | (value >> (64 - amount))) & MASK_64


def _keccak_f1600(state: list[int]) -> None:
    for constant in ROUND_CONSTANTS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        for x in range(5):
            delta = columns[(x - 1) % 5] ^ _rotate_left(columns[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= delta

        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                target_x = y
                target_y = (2 * x + 3 * y) % 5
                rotated[target_x + 5 * target_y] = _rotate_left(
                    state[x + 5 * y], ROTATION_OFFSETS[x][y]
                )
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ (
                    (~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]
                )
        state[0] ^= constant


def keccak_256(data: bytes) -> bytes:
    """Return Ethereum Keccak-256 without introducing a cryptographic dependency."""

    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - len(padded) % rate) % rate))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for index in range(rate // 8):
            state[index] ^= int.from_bytes(block[index * 8 : index * 8 + 8], "little")
        _keccak_f1600(state)
    output = bytearray()
    while len(output) < 32:
        for index in range(rate // 8):
            output.extend(state[index].to_bytes(8, "little"))
        if len(output) < 32:
            _keccak_f1600(state)
    return bytes(output[:32])


def canonical_abi_type(parameter: dict[str, Any]) -> str:
    type_name = str(parameter.get("type") or "")
    if not type_name.startswith("tuple"):
        return type_name
    suffix = type_name.removeprefix("tuple")
    components = parameter.get("components") or []
    if not isinstance(components, list):
        return type_name
    return "(" + ",".join(canonical_abi_type(item) for item in components) + ")" + suffix


def function_signature(item: dict[str, Any]) -> str | None:
    if item.get("type") != "function" or not item.get("name"):
        return None
    inputs = item.get("inputs") or []
    if not isinstance(inputs, list):
        return None
    return f"{item['name']}({','.join(canonical_abi_type(value) for value in inputs)})"


def selector_for_signature(signature: str) -> str:
    return "0x" + keccak_256(signature.encode("utf-8"))[:4].hex()


def build_selector_catalog(abi: list[dict[str, Any]]) -> dict[str, str]:
    collisions: dict[str, set[str]] = {}
    for item in abi[:MAX_ABI_ENTRIES]:
        signature = function_signature(item)
        if signature:
            collisions.setdefault(selector_for_signature(signature), set()).add(signature)
    return {
        selector: " | ".join(sorted(signatures))
        for selector, signatures in sorted(collisions.items())
    }


def _decode_word(type_name: str, word: bytes) -> object:
    if type_name == "address":
        return "0x" + word[-20:].hex()
    if type_name == "bool":
        return bool(int.from_bytes(word, "big"))
    if type_name.startswith("uint"):
        return int.from_bytes(word, "big")
    if type_name.startswith("int"):
        return int.from_bytes(word, "big", signed=bool(word[0] & 0x80))
    if type_name.startswith("bytes") and type_name != "bytes":
        try:
            length = int(type_name[5:])
        except ValueError:
            length = 32
        return "0x" + word[: max(0, min(32, length))].hex()
    return "0x" + word.hex()


def decode_static_arguments(
    abi_item: dict[str, Any], calldata: str, *, limit: int = 16
) -> dict[str, object]:
    inputs = abi_item.get("inputs") or []
    if not isinstance(inputs, list) or not calldata.startswith("0x"):
        return {}
    try:
        raw = bytes.fromhex(calldata[10:])
    except ValueError:
        return {}
    decoded: dict[str, object] = {}
    for index, item in enumerate(inputs[: max(0, limit)]):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or f"arg{index}")
        type_name = canonical_abi_type(item)
        if index * 32 + 32 > len(raw):
            break
        if type_name in {"string", "bytes"} or "[" in type_name or type_name.startswith("("):
            decoded[name] = "<dynamic>"
            continue
        decoded[name] = _decode_word(type_name, raw[index * 32 : index * 32 + 32])
    return decoded


@dataclasses.dataclass(frozen=True, slots=True)
class DecodedCall:
    selector: str
    signature: str | None
    arguments: dict[str, object]
    source: str | None
    abi_sha256: str | None


class AbiResolver:
    def __init__(self, store: RadarStore, *, timeout: int, retries: int) -> None:
        self._store = store
        self._timeout = timeout
        self._retries = retries
        self._memory: dict[tuple[int, str], tuple[list[dict[str, Any]], str, str]] = {}
        self._unavailable: set[tuple[int, str]] = set()

    def _fetch_etherscan(self, chain_id: int, address: str) -> list[dict[str, Any]] | None:
        key = os.getenv("ETHERSCAN_API_KEY", "").strip()
        if not key:
            return None
        try:
            response = request_json(
                "GET",
                "https://api.etherscan.io/v2/api",
                timeout=self._timeout,
                retries=self._retries,
                params={
                    "chainid": chain_id,
                    "module": "contract",
                    "action": "getabi",
                    "address": address,
                    "apikey": key,
                },
            )
        except HttpError:
            return None
        if not isinstance(response, dict) or not isinstance(response.get("result"), str):
            return None
        raw = str(response["result"])
        if len(raw.encode("utf-8")) > MAX_ABI_BYTES:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, list) or len(parsed) > MAX_ABI_ENTRIES:
            return None
        return [item for item in parsed if isinstance(item, dict)]

    def catalog(
        self, chain_id: int, address: str, *, refresh: bool = False
    ) -> tuple[dict[str, str], str | None, str | None]:
        identity = (chain_id, address.lower())
        if not refresh:
            cached = self._store.get_abi_catalog(chain_id, address)
            if cached:
                return cached["selectors"], str(cached["source"]), str(cached["abi_sha256"])
            if identity in self._unavailable:
                return {}, None, None
        abi = self._fetch_etherscan(chain_id, address)
        if abi is None:
            self._unavailable.add(identity)
            return {}, None, None
        canonical = json.dumps(abi, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        selectors = build_selector_catalog(abi)
        self._memory[identity] = (abi, "Etherscan", digest)
        self._store.upsert_abi_catalog(
            chain_id=chain_id,
            address=address,
            source="Etherscan",
            abi_sha256=digest,
            selectors=selectors,
        )
        return selectors, "Etherscan", digest

    def resolve(
        self,
        chain_id: int,
        address: str,
        calldata: str,
        *,
        fallback_signature: str | None = None,
    ) -> DecodedCall:
        selector = calldata[:10].lower() if len(calldata) >= 10 else "0x"
        selectors, source, digest = self.catalog(chain_id, address)
        signature = selectors.get(selector) or fallback_signature
        arguments: dict[str, object] = {}
        in_memory = self._memory.get((chain_id, address.lower()))
        if signature and in_memory and " | " not in signature:
            item = next(
                (entry for entry in in_memory[0] if function_signature(entry) == signature),
                None,
            )
            if item:
                arguments = decode_static_arguments(item, calldata)
        return DecodedCall(selector, signature, arguments, source, digest)
