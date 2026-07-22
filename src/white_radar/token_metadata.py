from __future__ import annotations

import contextlib
import dataclasses
from typing import Any

from white_radar.investigation import InvestigationCase, _build_relationships
from white_radar.rpc import JsonRpcClient, RpcError

NAME_SELECTOR = "0x06fdde03"
SYMBOL_SELECTOR = "0x95d89b41"
DECIMALS_SELECTOR = "0x313ce567"
MAX_TEXT_BYTES = 256


@dataclasses.dataclass(frozen=True, slots=True)
class TokenMetadata:
    address: str
    name: str | None
    symbol: str | None
    decimals: int | None
    block_number: int

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


def _response_bytes(value: str) -> bytes:
    if not value.startswith("0x") or len(value) % 2:
        return b""
    try:
        return bytes.fromhex(value[2:])
    except ValueError:
        return b""


def _clean_text(value: bytes) -> str | None:
    text = value[:MAX_TEXT_BYTES].rstrip(b"\x00").decode("utf-8", errors="replace").strip()
    cleaned = " ".join(text.split())
    return cleaned[:128] or None


def _decode_abi_text(value: str) -> str | None:
    raw = _response_bytes(value)
    if not raw:
        return None
    if len(raw) == 32:
        return _clean_text(raw)
    if len(raw) < 64:
        return None
    offset = int.from_bytes(raw[:32], "big")
    if offset % 32 or offset + 32 > len(raw):
        return None
    length = int.from_bytes(raw[offset : offset + 32], "big")
    start = offset + 32
    if length > MAX_TEXT_BYTES or start + length > len(raw):
        return None
    return _clean_text(raw[start : start + length])


def _decode_uint(value: str) -> int | None:
    raw = _response_bytes(value)
    if len(raw) < 32:
        return None
    return int.from_bytes(raw[:32], "big")


def format_token_amount(raw_amount: str, decimals: int | None) -> str | None:
    if decimals is None or decimals < 0 or decimals > 255:
        return None
    try:
        amount = int(raw_amount)
    except ValueError:
        return None
    if decimals == 0:
        return str(amount)
    scale = 10**decimals
    whole, fraction = divmod(amount, scale)
    if fraction == 0:
        return str(whole)
    fraction_text = f"{fraction:0{decimals}d}".rstrip("0")
    return f"{whole}.{fraction_text}"


class TokenMetadataResolver:
    """Resolve bounded token display metadata at a pinned historical block."""

    def __init__(self, rpc: JsonRpcClient, *, max_contracts: int = 64) -> None:
        self._rpc = rpc
        self._max_contracts = max(0, min(512, max_contracts))
        self._cache: dict[tuple[str, int], TokenMetadata] = {}
        self._attempted: set[tuple[str, int]] = set()

    def resolve(self, address: str, block_number: int) -> TokenMetadata | None:
        key = (address.lower(), block_number)
        if key in self._cache:
            return self._cache[key]
        if key in self._attempted or len(self._attempted) >= self._max_contracts:
            return None
        self._attempted.add(key)
        block = hex(block_number)

        def call(selector: str) -> str:
            return self._rpc.eth_call({"to": address, "data": selector}, block)

        name: str | None = None
        symbol: str | None = None
        decimals: int | None = None
        with contextlib.suppress(RpcError, AttributeError, ValueError):
            name = _decode_abi_text(call(NAME_SELECTOR))
        with contextlib.suppress(RpcError, AttributeError, ValueError):
            symbol = _decode_abi_text(call(SYMBOL_SELECTOR))
        with contextlib.suppress(RpcError, AttributeError, ValueError):
            candidate = _decode_uint(call(DECIMALS_SELECTOR))
            decimals = candidate if candidate is not None and 0 <= candidate <= 255 else None
        if name is None and symbol is None and decimals is None:
            return None
        metadata = TokenMetadata(address.lower(), name, symbol, decimals, block_number)
        self._cache[key] = metadata
        return metadata

    def enrich_case(self, case: InvestigationCase) -> InvestigationCase:
        enriched = []
        for transfer in case.transfers:
            if transfer.asset_type != "erc20" or not transfer.asset_address:
                enriched.append(transfer)
                continue
            metadata = self.resolve(transfer.asset_address, case.block_number)
            if metadata is None:
                enriched.append(transfer)
                continue
            enriched.append(
                dataclasses.replace(
                    transfer,
                    asset_name=metadata.name,
                    asset_symbol=metadata.symbol,
                    asset_decimals=metadata.decimals,
                    amount_display=format_token_amount(transfer.amount, metadata.decimals),
                )
            )
        transfers = tuple(enriched)
        return dataclasses.replace(
            case,
            transfers=transfers,
            relationships=_build_relationships(case.calls, transfers),
        )


def token_metadata_to_dict(value: TokenMetadata | None) -> dict[str, Any] | None:
    return value.to_dict() if value else None
