from __future__ import annotations

import dataclasses
import os
from collections.abc import Iterable
from typing import Any, ClassVar, Protocol

from white_radar.http import HttpError, request_json
from white_radar.investigation import (
    ADDRESS_RE,
    TRANSFER_BATCH_TOPIC,
    TRANSFER_SINGLE_TOPIC,
    TRANSFER_TOPIC,
)
from white_radar.rpc import JsonRpcClient, RpcError, hex_to_int

MAX_HISTORY_PAGE = 1_000
DEFAULT_LOG_CHUNK_BLOCKS = 1_000
ZERO_ADDRESS = "0x" + "00" * 20


class HistorySourceError(RuntimeError):
    """A bounded transaction-history source could not answer a query."""


@dataclasses.dataclass(frozen=True, slots=True)
class HistoryRecord:
    transaction_hash: str
    block_number: int
    transaction_index: int | None
    timestamp: int | None
    sender: str | None
    recipient: str | None
    record_type: str
    value: str | None
    asset_address: str | None
    token_id: str | None
    source: str

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


class HistorySource(Protocol):
    @property
    def warnings(self) -> tuple[str, ...]: ...

    def records_for_address(
        self,
        *,
        chain_id: int,
        address: str,
        start_block: int,
        end_block: int,
        anchor_block: int,
        limit: int,
    ) -> tuple[HistoryRecord, ...]: ...


def _address(value: object) -> str | None:
    normalized = str(value or "").lower()
    return normalized if ADDRESS_RE.fullmatch(normalized) else None


def _hash(value: object) -> str | None:
    normalized = str(value or "").lower()
    if len(normalized) != 66 or not normalized.startswith("0x"):
        return None
    try:
        int(normalized[2:], 16)
    except ValueError:
        return None
    return normalized


def _integer(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _topic_address(value: object) -> str | None:
    raw = str(value or "").removeprefix("0x")
    if len(raw) != 64:
        return None
    return _address("0x" + raw[-40:])


def _topic_for_address(address: str) -> str:
    return "0x" + "00" * 12 + address.lower().removeprefix("0x")


def _bounded_unique(
    records: Iterable[HistoryRecord], limit: int, *, anchor_block: int | None = None
) -> tuple[HistoryRecord, ...]:
    selected: list[HistoryRecord] = []
    seen: set[tuple[object, ...]] = set()
    for record in sorted(
        records,
        key=lambda item: (
            abs(item.block_number - anchor_block) if anchor_block is not None else 0,
            item.block_number,
            item.transaction_index if item.transaction_index is not None else 2**31,
            item.transaction_hash,
            item.record_type,
        ),
    ):
        identity = (
            record.transaction_hash,
            record.record_type,
            record.sender,
            record.recipient,
            record.asset_address,
            record.value,
            record.token_id,
        )
        if identity in seen:
            continue
        seen.add(identity)
        selected.append(record)
        if len(selected) >= max(0, limit):
            break
    return tuple(selected)


def _bounded_window(
    start_block: int, end_block: int, anchor_block: int, max_blocks: int
) -> tuple[int, int, bool]:
    if end_block < start_block:
        return start_block, start_block - 1, False
    requested = end_block - start_block + 1
    if requested <= max_blocks:
        return start_block, end_block, False
    anchor = min(end_block, max(start_block, anchor_block))
    left_budget = (max_blocks - 1) // 2
    selected_start = max(start_block, anchor - left_budget)
    selected_end = min(end_block, selected_start + max_blocks - 1)
    selected_start = max(start_block, selected_end - max_blocks + 1)
    return selected_start, selected_end, True


class EtherscanHistorySource:
    """Bounded Etherscan API V2 address history with source-specific provenance."""

    ACTION_TYPES: ClassVar[dict[str, str]] = {
        "txlist": "normal",
        "txlistinternal": "internal",
        "tokentx": "erc20",
        "tokennfttx": "erc721",
        "token1155tx": "erc1155",
    }

    def __init__(self, *, timeout: int = 20, retries: int = 3, api_key: str | None = None) -> None:
        configured_key = api_key if api_key is not None else os.getenv("ETHERSCAN_API_KEY", "")
        self._api_key = configured_key.strip()
        self._timeout = timeout
        self._retries = retries
        self._warnings: list[str] = []
        self._cache: dict[tuple[int, str, int, int, int], tuple[HistoryRecord, ...]] = {}

    @property
    def warnings(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self._warnings))

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def _request(
        self,
        *,
        chain_id: int,
        action: str,
        address: str,
        start_block: int,
        end_block: int,
        limit: int,
        sort: str,
    ) -> list[dict[str, Any]]:
        if not self._api_key:
            raise HistorySourceError("Etherscan history is not configured")
        try:
            response = request_json(
                "GET",
                "https://api.etherscan.io/v2/api",
                timeout=self._timeout,
                retries=self._retries,
                params={
                    "chainid": chain_id,
                    "module": "account",
                    "action": action,
                    "address": address,
                    "startblock": start_block,
                    "endblock": end_block,
                    "page": 1,
                    "offset": min(MAX_HISTORY_PAGE, max(1, limit)),
                    "sort": sort,
                    "apikey": self._api_key,
                },
            )
        except HttpError as exc:
            raise HistorySourceError(f"Etherscan {action} request failed") from exc
        if not isinstance(response, dict):
            raise HistorySourceError(f"Etherscan {action} returned malformed data")
        result = response.get("result")
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
        message = str(response.get("message") or result or "unknown response")
        if "No transactions found" in message:
            return []
        raise HistorySourceError(f"Etherscan {action} unavailable: {message[:160]}")

    def _convert(self, action: str, item: dict[str, Any]) -> HistoryRecord | None:
        tx_hash = _hash(item.get("hash"))
        block_number = _integer(item.get("blockNumber"))
        if tx_hash is None or block_number is None:
            return None
        record_type = self.ACTION_TYPES[action]
        asset_address = _address(item.get("contractAddress")) if record_type != "normal" else None
        return HistoryRecord(
            transaction_hash=tx_hash,
            block_number=block_number,
            transaction_index=_integer(item.get("transactionIndex")),
            timestamp=_integer(item.get("timeStamp")),
            sender=_address(item.get("from")),
            recipient=_address(item.get("to")),
            record_type=record_type,
            value=str(item.get("value")) if item.get("value") is not None else None,
            asset_address=asset_address,
            token_id=(str(item.get("tokenID")) if item.get("tokenID") is not None else None),
            source=f"etherscan_v2:{action}",
        )

    def records_for_address(
        self,
        *,
        chain_id: int,
        address: str,
        start_block: int,
        end_block: int,
        anchor_block: int,
        limit: int,
    ) -> tuple[HistoryRecord, ...]:
        bounded_limit = min(MAX_HISTORY_PAGE, max(1, limit))
        key = (chain_id, address.lower(), start_block, end_block, bounded_limit)
        if key in self._cache:
            return self._cache[key]
        records: list[HistoryRecord] = []
        errors = 0
        per_direction = max(5, (bounded_limit + 1) // 2)
        for action in self.ACTION_TYPES:
            action_succeeded = False
            ranges = (
                (start_block, min(anchor_block, end_block), "desc"),
                (max(anchor_block, start_block), end_block, "asc"),
            )
            for range_start, range_end, sort in ranges:
                if range_start > range_end:
                    continue
                try:
                    items = self._request(
                        chain_id=chain_id,
                        action=action,
                        address=address,
                        start_block=range_start,
                        end_block=range_end,
                        limit=per_direction,
                        sort=sort,
                    )
                except HistorySourceError as exc:
                    self._warnings.append(str(exc))
                    continue
                action_succeeded = True
                records.extend(
                    converted
                    for item in items
                    if (converted := self._convert(action, item)) is not None
                )
            if not action_succeeded:
                errors += 1
        if errors == len(self.ACTION_TYPES):
            raise HistorySourceError("All Etherscan history endpoints failed for the address")
        result = _bounded_unique(records, bounded_limit, anchor_block=anchor_block)
        self._cache[key] = result
        return result


class RpcWindowHistorySource:
    """Portable fallback using bounded block scans and standard transfer-event logs."""

    def __init__(
        self,
        rpc: JsonRpcClient,
        *,
        max_blocks: int = 768,
        max_transactions: int = 150_000,
        log_chunk_blocks: int = DEFAULT_LOG_CHUNK_BLOCKS,
    ) -> None:
        self._rpc = rpc
        self._max_blocks = max(1, min(10_000, max_blocks))
        self._max_transactions = max(1, min(1_000_000, max_transactions))
        self._log_chunk_blocks = max(1, min(10_000, log_chunk_blocks))
        self._warnings: list[str] = []
        self._normal_cache: dict[tuple[int, int], tuple[HistoryRecord, ...]] = {}
        self._address_cache: dict[tuple[str, int, int, int], tuple[HistoryRecord, ...]] = {}

    @property
    def warnings(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self._warnings))

    def _normal_records(self, start_block: int, end_block: int) -> tuple[HistoryRecord, ...]:
        key = (start_block, end_block)
        if key in self._normal_cache:
            return self._normal_cache[key]
        records: list[HistoryRecord] = []
        for block_number in range(start_block, end_block + 1):
            try:
                block = self._rpc.block(block_number, full_transactions=True)
            except (RpcError, AttributeError):
                self._warnings.append(
                    f"RPC block {block_number} was unavailable during history scan."
                )
                continue
            if not block:
                continue
            timestamp = hex_to_int(str(block.get("timestamp") or "0x0"))
            transactions = block.get("transactions") or []
            if not isinstance(transactions, list):
                continue
            for ordinal, item in enumerate(transactions):
                if not isinstance(item, dict):
                    continue
                tx_hash = _hash(item.get("hash"))
                if tx_hash is None:
                    continue
                records.append(
                    HistoryRecord(
                        transaction_hash=tx_hash,
                        block_number=block_number,
                        transaction_index=(
                            hex_to_int(str(item.get("transactionIndex")))
                            if item.get("transactionIndex") is not None
                            else ordinal
                        ),
                        timestamp=timestamp,
                        sender=_address(item.get("from")),
                        recipient=_address(item.get("to")),
                        record_type="normal",
                        value=str(hex_to_int(str(item.get("value") or "0x0"))),
                        asset_address=None,
                        token_id=None,
                        source="ethereum_json_rpc:block_scan",
                    )
                )
                if len(records) >= self._max_transactions:
                    self._warnings.append(
                        f"RPC history transaction inventory was capped at {self._max_transactions}."
                    )
                    self._normal_cache[key] = tuple(records)
                    return self._normal_cache[key]
        self._normal_cache[key] = tuple(records)
        return self._normal_cache[key]

    def _log_records(
        self, address: str, start_block: int, end_block: int
    ) -> tuple[HistoryRecord, ...]:
        padded = _topic_for_address(address)
        filters = (
            ("erc20_or_erc721", [TRANSFER_TOPIC, padded]),
            ("erc20_or_erc721", [TRANSFER_TOPIC, None, padded]),
            ("erc1155", [TRANSFER_SINGLE_TOPIC, None, padded]),
            ("erc1155", [TRANSFER_SINGLE_TOPIC, None, None, padded]),
            ("erc1155", [TRANSFER_BATCH_TOPIC, None, padded]),
            ("erc1155", [TRANSFER_BATCH_TOPIC, None, None, padded]),
        )
        records: list[HistoryRecord] = []
        for record_type, topics in filters:
            for chunk_start in range(start_block, end_block + 1, self._log_chunk_blocks):
                chunk_end = min(end_block, chunk_start + self._log_chunk_blocks - 1)
                try:
                    logs = self._rpc.logs(
                        from_block=chunk_start,
                        to_block=chunk_end,
                        topics=list(topics),
                    )
                except (RpcError, AttributeError):
                    self._warnings.append(
                        "Standard transfer-log history was partially unavailable from the RPC "
                        f"endpoint for blocks {chunk_start}-{chunk_end}."
                    )
                    continue
                for log in logs:
                    self._append_log_record(records, record_type, log)
                    if len(records) >= self._max_transactions:
                        self._warnings.append(
                            f"RPC transfer-log inventory was capped at {self._max_transactions}."
                        )
                        return _bounded_unique(records, self._max_transactions)
        return _bounded_unique(records, self._max_transactions)

    @staticmethod
    def _append_log_record(
        records: list[HistoryRecord], record_type: str, log: dict[str, Any]
    ) -> None:
        tx_hash = _hash(log.get("transactionHash"))
        block_number = (
            hex_to_int(str(log.get("blockNumber")))
            if log.get("blockNumber") is not None
            else None
        )
        log_topics = log.get("topics") or []
        if tx_hash is None or block_number is None or not isinstance(log_topics, list):
            return
        topic0 = str(log_topics[0]).lower() if log_topics else ""
        if topic0 == TRANSFER_TOPIC:
            sender = _topic_address(log_topics[1]) if len(log_topics) > 1 else None
            recipient = _topic_address(log_topics[2]) if len(log_topics) > 2 else None
            resolved_type = "erc721" if len(log_topics) >= 4 else "erc20"
            token_id = str(hex_to_int(str(log_topics[3]))) if len(log_topics) >= 4 else None
            raw_data = str(log.get("data") or "0x").removeprefix("0x")
            value = (
                str(int(raw_data[:64], 16))
                if len(raw_data) >= 64 and resolved_type == "erc20"
                else "1" if resolved_type == "erc721" else None
            )
        else:
            sender = _topic_address(log_topics[2]) if len(log_topics) > 2 else None
            recipient = _topic_address(log_topics[3]) if len(log_topics) > 3 else None
            resolved_type = record_type
            value = None
            token_id = None
        records.append(
            HistoryRecord(
                transaction_hash=tx_hash,
                block_number=block_number,
                transaction_index=(
                    hex_to_int(str(log.get("transactionIndex")))
                    if log.get("transactionIndex") is not None
                    else None
                ),
                timestamp=None,
                sender=sender,
                recipient=recipient,
                record_type=resolved_type,
                value=value,
                asset_address=_address(log.get("address")),
                token_id=token_id,
                source="ethereum_json_rpc:eth_getLogs",
            )
        )

    def records_for_address(
        self,
        *,
        chain_id: int,
        address: str,
        start_block: int,
        end_block: int,
        anchor_block: int,
        limit: int,
    ) -> tuple[HistoryRecord, ...]:
        del chain_id
        selected_start, selected_end, capped = _bounded_window(
            start_block, end_block, anchor_block, self._max_blocks
        )
        if capped:
            self._warnings.append(
                f"RPC history was centered on the seed and capped at {self._max_blocks} blocks; "
                "use indexed history for wider coverage."
            )
        key = (address.lower(), selected_start, selected_end, max(1, limit))
        if key in self._address_cache:
            return self._address_cache[key]
        normal = (
            item
            for item in self._normal_records(selected_start, selected_end)
            if item.sender == address.lower() or item.recipient == address.lower()
        )
        logs = self._log_records(address.lower(), selected_start, selected_end)
        result = _bounded_unique(
            (*normal, *logs), max(1, limit), anchor_block=anchor_block
        )
        self._address_cache[key] = result
        return result


class CompositeHistorySource:
    """Use an indexed source first and preserve portable RPC fallback behavior."""

    def __init__(self, primary: HistorySource | None, fallback: HistorySource) -> None:
        self._primary = primary
        self._fallback = fallback
        self._warnings: list[str] = []

    @property
    def warnings(self) -> tuple[str, ...]:
        values = [*self._warnings]
        if self._primary:
            values.extend(self._primary.warnings)
        values.extend(self._fallback.warnings)
        return tuple(dict.fromkeys(values))

    def records_for_address(
        self,
        *,
        chain_id: int,
        address: str,
        start_block: int,
        end_block: int,
        anchor_block: int,
        limit: int,
    ) -> tuple[HistoryRecord, ...]:
        if self._primary:
            try:
                return self._primary.records_for_address(
                    chain_id=chain_id,
                    address=address,
                    start_block=start_block,
                    end_block=end_block,
                    anchor_block=anchor_block,
                    limit=limit,
                )
            except HistorySourceError as exc:
                self._warnings.append(
                    f"Indexed history failed for {address}; RPC fallback was used ({exc})."
                )
        return self._fallback.records_for_address(
            chain_id=chain_id,
            address=address,
            start_block=start_block,
            end_block=end_block,
            anchor_block=anchor_block,
            limit=limit,
        )
