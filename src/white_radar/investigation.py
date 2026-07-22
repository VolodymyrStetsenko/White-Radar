from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from white_radar.abi import AbiResolver, DecodedCall, keccak_256
from white_radar.models import ChainConfig, utc_now
from white_radar.proxy import ProxySnapshot, inspect_proxy
from white_radar.rpc import JsonRpcClient, RpcError, hex_to_int
from white_radar.simulation import SimulationResult, simulate_transaction
from white_radar.state_diff import StateDiff, parse_state_diff

if TYPE_CHECKING:
    from white_radar.config import Watchlist

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TRANSACTION_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
ZERO_ADDRESS = "0x" + "00" * 20
MAX_CALL_FRAMES = 2_000
MAX_RECEIPT_LOGS = 5_000
MAX_TRANSFERS = 20_000
MAX_ENTITIES = 1_000
MAX_CODE_LOOKUPS = 128
MAX_ABI_DESTINATIONS = 32
MAX_ABI_EVENT_ADDRESSES = 32
MAX_ERC1155_BATCH_ITEMS = 256
MAX_CALLDATA_BYTES = 16_384
MAX_EVENT_DATA_BYTES = 16_384
VALUE_TRANSFER_CALL_TYPES = frozenset({"CALL", "CREATE", "CREATE2", "SELFDESTRUCT"})

TRANSFER_TOPIC = "0x" + keccak_256(b"Transfer(address,address,uint256)").hex()
TRANSFER_SINGLE_TOPIC = (
    "0x" + keccak_256(b"TransferSingle(address,address,address,uint256,uint256)").hex()
)
TRANSFER_BATCH_TOPIC = (
    "0x" + keccak_256(b"TransferBatch(address,address,address,uint256[],uint256[])").hex()
)


def validate_transaction_hash(value: str) -> str:
    normalized = value.lower()
    if not TRANSACTION_HASH_RE.fullmatch(normalized):
        raise ValueError("Transaction hash must be a 32-byte 0x-prefixed hexadecimal value")
    return normalized


def _address(value: object) -> str | None:
    normalized = str(value or "").lower()
    return normalized if ADDRESS_RE.fullmatch(normalized) else None


def _topic_address(value: object) -> str | None:
    raw = str(value or "").removeprefix("0x")
    if len(raw) != 64:
        return None
    try:
        int(raw, 16)
    except ValueError:
        return None
    return _address("0x" + raw[-40:])


def _hex_data(value: object) -> bytes | None:
    raw = str(value or "0x")
    if not raw.startswith("0x") or len(raw) % 2:
        return None
    try:
        return bytes.fromhex(raw[2:])
    except ValueError:
        return None


def _word(raw: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 32 > len(raw):
        return None
    return int.from_bytes(raw[offset : offset + 32], "big")


def _decode_dynamic_uint_array(raw: bytes, head_offset: int) -> list[int] | None:
    relative = _word(raw, head_offset)
    if relative is None or relative % 32 or relative + 32 > len(raw):
        return None
    length = _word(raw, relative)
    if length is None or length > MAX_ERC1155_BATCH_ITEMS:
        return None
    start = relative + 32
    end = start + length * 32
    if end > len(raw):
        return None
    return [int.from_bytes(raw[index : index + 32], "big") for index in range(start, end, 32)]


def _block_timestamp(block: dict[str, Any]) -> str | None:
    timestamp = block.get("timestamp")
    if timestamp is None:
        return None
    try:
        return dt.datetime.fromtimestamp(hex_to_int(str(timestamp)), tz=dt.UTC).isoformat(
            timespec="seconds"
        )
    except (ValueError, OverflowError, OSError):
        return None


def _quantity(value: object, field: str) -> int:
    if value is None:
        raise RuntimeError(f"The confirmed transaction is missing {field}")
    try:
        return hex_to_int(str(value))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"The confirmed transaction contains an invalid {field}") from exc


def _optional_quantity(value: object) -> int | None:
    if value is None:
        return None
    try:
        return hex_to_int(str(value))
    except (TypeError, ValueError):
        return None


def _calldata_selector(value: object) -> str:
    calldata = str(value or "0x").lower()
    return calldata[:10] if len(calldata) >= 10 else "0x"


@dataclasses.dataclass(frozen=True, slots=True)
class CallFrame:
    path: str
    depth: int
    call_type: str
    sender: str | None
    recipient: str | None
    value_wei: int
    gas: int
    gas_used: int
    selector: str
    function_signature: str | None
    abi_source: str | None
    error: str | None
    revert_reason: str | None
    decode_confidence: str | None = None
    decoded_arguments: dict[str, object] = dataclasses.field(default_factory=dict)
    calldata: str = "0x"
    calldata_bytes: int = 0
    calldata_sha256: str | None = None
    calldata_truncated: bool = False

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class EventRecord:
    log_index: int
    address: str | None
    topic0: str | None
    event_signature: str | None
    event_name: str | None
    arguments: dict[str, object]
    abi_source: str | None
    abi_sha256: str | None
    decode_confidence: str | None
    topics: tuple[str, ...]
    data: str
    data_bytes: int
    data_sha256: str | None
    data_truncated: bool
    evidence_ref: str

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class AssetTransfer:
    transfer_id: str
    asset_type: str
    asset_address: str | None
    sender: str
    recipient: str
    amount: str
    token_id: str | None
    operator: str | None
    source: str
    evidence_ref: str
    asset_name: str | None = None
    asset_symbol: str | None = None
    asset_decimals: int | None = None
    amount_display: str | None = None

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class Entity:
    address: str
    kind: str
    label: str | None
    roles: tuple[str, ...]
    code_observed: bool | None
    code_bytes: int | None = None
    runtime_code_sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class Relationship:
    relationship_id: str
    source: str
    target: str
    relation: str
    evidence_ref: str
    asset_address: str | None = None
    amount: str | None = None
    asset_type: str | None = None
    asset_symbol: str | None = None
    amount_display: str | None = None

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class TimelineEntry:
    entry_id: str
    phase: str
    order: int
    event_type: str
    summary: str
    evidence_ref: str

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class InvestigationFinding:
    code: str
    category: str
    summary: str
    evidence_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class InvestigationCase:
    schema_version: int
    case_id: str
    generated_at: str
    chain: str
    chain_id: int
    explorer_url: str
    transaction_hash: str
    block_number: int
    block_hash: str | None
    block_timestamp: str | None
    transaction_status: str
    transaction_fee_wei: str | None
    trace_available: bool
    trace_truncated: bool
    source_transaction: dict[str, Any]
    source_receipt: dict[str, Any]
    root_call: DecodedCall | None
    calls: tuple[CallFrame, ...]
    events: tuple[EventRecord, ...]
    transfers: tuple[AssetTransfer, ...]
    entities: tuple[Entity, ...]
    relationships: tuple[Relationship, ...]
    timeline: tuple[TimelineEntry, ...]
    findings: tuple[InvestigationFinding, ...]
    warnings: tuple[str, ...]
    proxy_snapshot: ProxySnapshot | None
    historical_replay: SimulationResult | None
    state_diff: StateDiff | None

    def to_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        if self.root_call:
            result["root_call"] = dataclasses.asdict(self.root_call)
        return result


def _flatten_trace(
    trace: dict[str, Any],
    *,
    resolver: AbiResolver | None,
    chain_id: int,
    proxy_implementation: str | None,
) -> tuple[tuple[CallFrame, ...], bool]:
    frames: list[CallFrame] = []
    stack: list[tuple[object, int, str]] = [(trace, 0, "0")]
    abi_addresses: set[str] = set()
    truncated = False
    while stack:
        raw_frame, depth, path = stack.pop()
        if not isinstance(raw_frame, dict):
            continue
        if len(frames) >= MAX_CALL_FRAMES:
            truncated = True
            break
        sender = _address(raw_frame.get("from"))
        recipient = _address(raw_frame.get("to"))
        calldata = str(raw_frame.get("input") or "0x")
        raw_calldata = _hex_data(calldata)
        calldata_bytes = len(raw_calldata) if raw_calldata is not None else 0
        calldata_sha256 = (
            hashlib.sha256(raw_calldata).hexdigest() if raw_calldata is not None else None
        )
        calldata_truncated = calldata_bytes > MAX_CALLDATA_BYTES
        bounded_calldata = (
            "0x" + raw_calldata[:MAX_CALLDATA_BYTES].hex()
            if raw_calldata is not None
            else "0x"
        )
        decoded: DecodedCall | None = None
        if (
            resolver
            and recipient
            and (recipient in abi_addresses or len(abi_addresses) < MAX_ABI_DESTINATIONS)
        ):
            abi_addresses.add(recipient)
            decoded = resolver.resolve(chain_id, recipient, calldata)
            if (
                not decoded.signature
                and path == "0"
                and proxy_implementation
                and proxy_implementation != recipient
            ):
                implementation_call = resolver.resolve(chain_id, proxy_implementation, calldata)
                if implementation_call.signature:
                    decoded = dataclasses.replace(
                        implementation_call,
                        source=(implementation_call.source or "verified ABI")
                        + " via proxy implementation",
                    )
        call_type = str(raw_frame.get("type") or "CALL").upper()
        error = str(raw_frame.get("error") or "") or None
        revert_reason = str(raw_frame.get("revertReason") or "") or None
        frames.append(
            CallFrame(
                path=path,
                depth=depth,
                call_type=call_type,
                sender=sender,
                recipient=recipient,
                value_wei=hex_to_int(str(raw_frame.get("value") or "0x0")),
                gas=hex_to_int(str(raw_frame.get("gas") or "0x0")),
                gas_used=hex_to_int(str(raw_frame.get("gasUsed") or "0x0")),
                selector=decoded.selector if decoded else _calldata_selector(calldata),
                function_signature=decoded.signature if decoded else None,
                abi_source=decoded.source if decoded else None,
                error=error,
                revert_reason=revert_reason,
                decode_confidence=decoded.confidence if decoded else None,
                decoded_arguments=dict(decoded.arguments) if decoded else {},
                calldata=bounded_calldata,
                calldata_bytes=calldata_bytes,
                calldata_sha256=calldata_sha256,
                calldata_truncated=calldata_truncated,
            )
        )
        children = raw_frame.get("calls") or []
        if isinstance(children, list):
            stack.extend(
                (child, depth + 1, f"{path}.{index}")
                for index, child in reversed(list(enumerate(children)))
            )
    return tuple(frames), truncated


def _transfers_from_logs(
    logs: Iterable[dict[str, Any]], warnings: list[str] | None = None
) -> list[AssetTransfer]:
    transfers: list[AssetTransfer] = []
    notices = warnings if warnings is not None else []
    for ordinal, log in enumerate(logs):
        if len(transfers) >= MAX_TRANSFERS:
            notices.append(f"Asset transfers were capped at {MAX_TRANSFERS} records.")
            break
        topics = log.get("topics") or []
        if not isinstance(topics, list) or not topics:
            continue
        topic0 = str(topics[0]).lower()
        token = _address(log.get("address"))
        log_index = hex_to_int(str(log.get("logIndex") or hex(ordinal)))
        evidence_ref = f"log:{log_index}"
        raw = _hex_data(log.get("data"))
        if topic0 == TRANSFER_TOPIC and token and raw is not None:
            sender = _topic_address(topics[1]) if len(topics) > 1 else None
            recipient = _topic_address(topics[2]) if len(topics) > 2 else None
            if not sender or not recipient:
                continue
            if len(topics) >= 4:
                erc721_token_id = str(hex_to_int(str(topics[3])))
                transfers.append(
                    AssetTransfer(
                        transfer_id=f"transfer:{log_index}:0",
                        asset_type="erc721",
                        asset_address=token,
                        sender=sender,
                        recipient=recipient,
                        amount="1",
                        token_id=erc721_token_id,
                        operator=None,
                        source="receipt_log",
                        evidence_ref=evidence_ref,
                    )
                )
            elif len(raw) >= 32:
                transfers.append(
                    AssetTransfer(
                        transfer_id=f"transfer:{log_index}:0",
                        asset_type="erc20",
                        asset_address=token,
                        sender=sender,
                        recipient=recipient,
                        amount=str(int.from_bytes(raw[:32], "big")),
                        token_id=None,
                        operator=None,
                        source="receipt_log",
                        evidence_ref=evidence_ref,
                    )
                )
        elif topic0 == TRANSFER_SINGLE_TOPIC and token and raw is not None and len(topics) >= 4:
            operator = _topic_address(topics[1])
            sender = _topic_address(topics[2])
            recipient = _topic_address(topics[3])
            erc1155_token_id = _word(raw, 0)
            erc1155_amount = _word(raw, 32)
            if sender and recipient and erc1155_token_id is not None and erc1155_amount is not None:
                transfers.append(
                    AssetTransfer(
                        transfer_id=f"transfer:{log_index}:0",
                        asset_type="erc1155",
                        asset_address=token,
                        sender=sender,
                        recipient=recipient,
                        amount=str(erc1155_amount),
                        token_id=str(erc1155_token_id),
                        operator=operator,
                        source="receipt_log",
                        evidence_ref=evidence_ref,
                    )
                )
            elif sender and recipient:
                notices.append(f"ERC-1155 TransferSingle log {log_index} could not be decoded.")
        elif topic0 == TRANSFER_BATCH_TOPIC and token and raw is not None and len(topics) >= 4:
            operator = _topic_address(topics[1])
            sender = _topic_address(topics[2])
            recipient = _topic_address(topics[3])
            token_ids = _decode_dynamic_uint_array(raw, 0)
            amounts = _decode_dynamic_uint_array(raw, 32)
            if sender and recipient and token_ids is not None and amounts is not None:
                if len(token_ids) != len(amounts):
                    notices.append(
                        f"ERC-1155 TransferBatch log {log_index} contains unequal array lengths."
                    )
                    continue
                remaining = MAX_TRANSFERS - len(transfers)
                selected = list(zip(token_ids, amounts, strict=True))[:remaining]
                for index, (batch_token_id, batch_amount) in enumerate(selected):
                    transfers.append(
                        AssetTransfer(
                            transfer_id=f"transfer:{log_index}:{index}",
                            asset_type="erc1155",
                            asset_address=token,
                            sender=sender,
                            recipient=recipient,
                            amount=str(batch_amount),
                            token_id=str(batch_token_id),
                            operator=operator,
                            source="receipt_log",
                            evidence_ref=evidence_ref,
                        )
                    )
                if len(selected) < len(token_ids):
                    notices.append(f"Asset transfers were capped at {MAX_TRANSFERS} records.")
                    break
            elif sender and recipient:
                notices.append(f"ERC-1155 TransferBatch log {log_index} could not be decoded.")
    return transfers


def _events_from_logs(
    logs: Iterable[dict[str, Any]],
    *,
    resolver: AbiResolver | None,
    chain_id: int,
    warnings: list[str],
) -> tuple[EventRecord, ...]:
    events: list[EventRecord] = []
    abi_addresses: set[str] = set()
    abi_limit_reached = False
    for ordinal, log in enumerate(logs):
        try:
            log_index = hex_to_int(str(log.get("logIndex") or hex(ordinal)))
        except ValueError:
            log_index = ordinal
        address = _address(log.get("address"))
        raw_topics = log.get("topics") or []
        topics = (
            tuple(
                str(topic).lower()
                for topic in raw_topics
                if isinstance(topic, str) and topic.startswith("0x")
            )
            if isinstance(raw_topics, list)
            else ()
        )
        raw_data = _hex_data(log.get("data"))
        data_bytes = len(raw_data) if raw_data is not None else 0
        data_sha256 = hashlib.sha256(raw_data).hexdigest() if raw_data is not None else None
        data_truncated = data_bytes > MAX_EVENT_DATA_BYTES
        bounded_data = (
            "0x" + raw_data[:MAX_EVENT_DATA_BYTES].hex()
            if raw_data is not None
            else "0x"
        )
        decoded = None
        if resolver and address and topics:
            if address in abi_addresses or len(abi_addresses) < MAX_ABI_EVENT_ADDRESSES:
                abi_addresses.add(address)
                try:
                    decoded = resolver.resolve_event(chain_id, address, list(topics), bounded_data)
                except (AttributeError, ValueError):
                    decoded = None
            else:
                abi_limit_reached = True
        events.append(
            EventRecord(
                log_index=log_index,
                address=address,
                topic0=topics[0] if topics else None,
                event_signature=decoded.signature if decoded else None,
                event_name=decoded.name if decoded else None,
                arguments=dict(decoded.arguments) if decoded else {},
                abi_source=decoded.source if decoded else None,
                abi_sha256=decoded.abi_sha256 if decoded else None,
                decode_confidence=decoded.confidence if decoded else None,
                topics=topics,
                data=bounded_data,
                data_bytes=data_bytes,
                data_sha256=data_sha256,
                data_truncated=data_truncated,
                evidence_ref=f"log:{log_index}",
            )
        )
    if abi_limit_reached:
        warnings.append(
            f"Verified event ABI resolution was capped at {MAX_ABI_EVENT_ADDRESSES} "
            "unique log-emitting addresses."
        )
    if any(item.data_truncated for item in events):
        warnings.append(
            f"One or more event payloads exceeded {MAX_EVENT_DATA_BYTES} bytes; full "
            "payload SHA-256 values are retained."
        )
    return tuple(events)


def _native_transfers(
    calls: tuple[CallFrame, ...], transaction: dict[str, Any]
) -> list[AssetTransfer]:
    transfers: list[AssetTransfer] = []
    candidates: Iterable[tuple[str, str | None, str | None, int, str, str, str]]
    if calls:
        candidates = (
            (
                frame.path,
                frame.sender,
                frame.recipient,
                frame.value_wei,
                frame.call_type,
                "call_trace",
                f"call:{frame.path}",
            )
            for frame in calls
        )
    else:
        candidates = (
            (
                "0",
                _address(transaction.get("from")),
                _address(transaction.get("to")),
                hex_to_int(str(transaction.get("value") or "0x0")),
                "CALL",
                "transaction",
                "transaction",
            ),
        )
    for path, sender, recipient, value, call_type, source, evidence_ref in candidates:
        if value <= 0 or not sender or not recipient or call_type not in VALUE_TRANSFER_CALL_TYPES:
            continue
        transfers.append(
            AssetTransfer(
                transfer_id=f"native:{path}",
                asset_type="native",
                asset_address=None,
                sender=sender,
                recipient=recipient,
                amount=str(value),
                token_id=None,
                operator=None,
                source=source,
                evidence_ref=evidence_ref,
            )
        )
    return transfers


def _known_label(watchlist: Watchlist | None, chain_id: int, address: str) -> str | None:
    if not watchlist:
        return None
    watched = watchlist.contract(chain_id, address)
    return f"{watched.protocol} {watched.role}" if watched else None


def _build_entities(
    rpc: JsonRpcClient,
    *,
    chain_id: int,
    block_number: int,
    transaction: dict[str, Any],
    receipt: dict[str, Any],
    calls: tuple[CallFrame, ...],
    events: tuple[EventRecord, ...],
    transfers: tuple[AssetTransfer, ...],
    watchlist: Watchlist | None,
) -> tuple[tuple[Entity, ...], bool]:
    roles: dict[str, set[str]] = {}
    forced_kinds: dict[str, str] = {}
    truncated = False

    def add(value: str | None, role: str, kind: str | None = None) -> None:
        nonlocal truncated
        if not value:
            return
        if len(roles) >= MAX_ENTITIES and value not in roles:
            truncated = True
            return
        roles.setdefault(value, set()).add(role)
        if kind:
            forced_kinds[value] = kind

    add(_address(transaction.get("from")), "transaction_origin", "account")
    target = _address(transaction.get("to"))
    add(target, "transaction_target", "contract" if target else None)
    created = _address(receipt.get("contractAddress"))
    add(created, "created_contract", "contract")
    for frame in calls:
        add(frame.sender, "call_sender")
        add(
            frame.recipient,
            "created_contract" if frame.call_type in {"CREATE", "CREATE2"} else "call_recipient",
            "contract" if frame.call_type in {"CREATE", "CREATE2", "DELEGATECALL"} else None,
        )
    for event in events:
        add(event.address, "event_emitter", "contract")
    for transfer in transfers:
        add(transfer.sender, "asset_sender")
        add(transfer.recipient, "asset_recipient")
        add(transfer.asset_address, "asset_contract", "contract")
        add(transfer.operator, "asset_operator")

    block_ref = hex(block_number)
    entities: list[Entity] = []
    code_lookups = 0
    for address in sorted(roles):
        kind = forced_kinds.get(address)
        code_observed: bool | None = None
        code_bytes: int | None = None
        runtime_code_sha256: str | None = None
        if address == ZERO_ADDRESS:
            kind = "system"
            code_observed = False
            code_bytes = 0
        elif kind != "account" and code_lookups < MAX_CODE_LOOKUPS:
            try:
                code_lookups += 1
                code = rpc.code(address, block_ref)
                normalized_code = code.removeprefix("0x").strip("0")
                code_observed = code not in {"0x", "0x0", ""} and bool(normalized_code)
                raw_code = _hex_data(code)
                if raw_code is not None:
                    code_bytes = len(raw_code)
                    if raw_code:
                        runtime_code_sha256 = hashlib.sha256(raw_code).hexdigest()
                if kind != "contract":
                    kind = "contract" if code_observed else "account"
            except (RpcError, AttributeError):
                pass
        entities.append(
            Entity(
                address=address,
                kind=kind or "unknown",
                label=_known_label(watchlist, chain_id, address),
                roles=tuple(sorted(roles[address])),
                code_observed=code_observed,
                code_bytes=code_bytes,
                runtime_code_sha256=runtime_code_sha256,
            )
        )
    return tuple(entities), truncated


def _build_relationships(
    calls: tuple[CallFrame, ...], transfers: tuple[AssetTransfer, ...]
) -> tuple[Relationship, ...]:
    relationships: list[Relationship] = []
    for frame in calls:
        if frame.sender and frame.recipient:
            transferred_value = (
                frame.value_wei if frame.call_type in VALUE_TRANSFER_CALL_TYPES else 0
            )
            relationships.append(
                Relationship(
                    relationship_id=f"call:{frame.path}",
                    source=frame.sender,
                    target=frame.recipient,
                    relation=frame.call_type,
                    evidence_ref=f"call:{frame.path}",
                    amount=str(transferred_value) if transferred_value else None,
                )
            )
    for transfer in transfers:
        relationships.append(
            Relationship(
                relationship_id=transfer.transfer_id,
                source=transfer.sender,
                target=transfer.recipient,
                relation=f"{transfer.asset_type.upper()}_TRANSFER",
                evidence_ref=transfer.evidence_ref,
                asset_address=transfer.asset_address,
                amount=transfer.amount,
                asset_type=transfer.asset_type,
                asset_symbol=transfer.asset_symbol,
                amount_display=transfer.amount_display,
            )
        )
    return tuple(relationships)


def _build_timeline(
    calls: tuple[CallFrame, ...],
    events: tuple[EventRecord, ...],
    transfers: tuple[AssetTransfer, ...],
) -> tuple[TimelineEntry, ...]:
    timeline: list[TimelineEntry] = []
    for order, frame in enumerate(calls):
        destination = frame.recipient or "contract creation"
        function = frame.function_signature or frame.selector
        suffix = " (reverted)" if frame.error or frame.revert_reason else ""
        timeline.append(
            TimelineEntry(
                entry_id=f"call:{frame.path}",
                phase="execution",
                order=order,
                event_type=frame.call_type.lower(),
                summary=f"{frame.call_type} to {destination} via {function}{suffix}",
                evidence_ref=f"call:{frame.path}",
            )
        )
    for event in events:
        identity = event.event_signature or event.topic0 or "anonymous/unresolved"
        emitter = event.address or "unknown emitter"
        timeline.append(
            TimelineEntry(
                entry_id=f"event:{event.log_index}",
                phase="events",
                order=event.log_index,
                event_type=(
                    "verified_event" if event.decode_confidence == "verified" else "event"
                ),
                summary=f"{identity} emitted by {emitter}",
                evidence_ref=event.evidence_ref,
            )
        )
    for transfer in transfers:
        order_text = transfer.evidence_ref.split(":", 1)[-1].split(".", 1)[0]
        try:
            order = int(order_text)
        except ValueError:
            order = len(timeline)
        identifier = f" token {transfer.token_id}" if transfer.token_id is not None else ""
        timeline.append(
            TimelineEntry(
                entry_id=transfer.transfer_id,
                phase="asset_flow",
                order=order,
                event_type=f"{transfer.asset_type}_transfer",
                summary=(
                    f"{transfer.amount} {transfer.asset_type}{identifier} from "
                    f"{transfer.sender} to {transfer.recipient}"
                ),
                evidence_ref=transfer.evidence_ref,
            )
        )
    phase_order = {"execution": 0, "events": 1, "asset_flow": 2}
    return tuple(
        sorted(
            timeline,
            key=lambda item: (phase_order.get(item.phase, 99), item.order, item.entry_id),
        )
    )


def _build_findings(
    *,
    status: str,
    calls: tuple[CallFrame, ...],
    events: tuple[EventRecord, ...],
    transfers: tuple[AssetTransfer, ...],
    proxy_snapshot: ProxySnapshot | None,
    state_diff: StateDiff | None,
) -> tuple[InvestigationFinding, ...]:
    findings: list[InvestigationFinding] = []
    if status == "reverted":
        findings.append(
            InvestigationFinding(
                "transaction_reverted",
                "execution",
                "The transaction receipt records a reverted execution.",
                ("receipt",),
            )
        )
    failed = tuple(f"call:{frame.path}" for frame in calls if frame.error or frame.revert_reason)
    if failed:
        findings.append(
            InvestigationFinding(
                "reverted_internal_calls",
                "execution",
                f"The call trace contains {len(failed)} reverted internal call(s).",
                failed[:20],
            )
        )
    delegated = tuple(f"call:{frame.path}" for frame in calls if frame.call_type == "DELEGATECALL")
    if delegated:
        findings.append(
            InvestigationFinding(
                "delegated_execution",
                "control_flow",
                f"The execution graph contains {len(delegated)} DELEGATECALL frame(s).",
                delegated[:20],
            )
        )
    creations = tuple(
        f"call:{frame.path}" for frame in calls if frame.call_type in {"CREATE", "CREATE2"}
    )
    if creations:
        findings.append(
            InvestigationFinding(
                "contract_creation",
                "control_flow",
                f"The transaction created {len(creations)} contract(s) in its call graph.",
                creations[:20],
            )
        )
    token_transfers = tuple(
        transfer.evidence_ref for transfer in transfers if transfer.asset_type != "native"
    )
    native_transfers = tuple(
        transfer.evidence_ref for transfer in transfers if transfer.asset_type == "native"
    )
    if token_transfers:
        findings.append(
            InvestigationFinding(
                "token_asset_flow",
                "asset_flow",
                f"Receipt logs reconstruct {len(token_transfers)} token transfer(s).",
                token_transfers[:20],
            )
        )
    if native_transfers:
        findings.append(
            InvestigationFinding(
                "native_asset_flow",
                "asset_flow",
                f"The call graph reconstructs {len(native_transfers)} native-value transfer(s).",
                native_transfers[:20],
            )
        )
    if proxy_snapshot and proxy_snapshot.effective_implementation:
        findings.append(
            InvestigationFinding(
                "proxy_execution_context",
                "contract_identity",
                "The transaction target resolves to an implementation contract at the "
                "transaction block.",
                ("proxy_snapshot",),
            )
        )
    verified_events = tuple(
        event.evidence_ref for event in events if event.decode_confidence == "verified"
    )
    if verified_events:
        findings.append(
            InvestigationFinding(
                "verified_event_evidence",
                "event_evidence",
                f"Verified contract ABIs decoded {len(verified_events)} emitted event(s).",
                verified_events[:20],
            )
        )
    if state_diff and state_diff.accounts:
        findings.append(
            InvestigationFinding(
                "state_changes_observed",
                "state_evidence",
                f"The pre/post trace records {len(state_diff.accounts)} changed account(s) "
                f"and {state_diff.storage_change_count} changed storage slot(s).",
                ("state_diff",),
            )
        )
    return tuple(findings)


def _source_transaction(transaction: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "hash",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "from",
        "to",
        "nonce",
        "value",
        "gas",
        "gasPrice",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "type",
        "chainId",
        "input",
        "accessList",
    )
    return {field: transaction[field] for field in fields if field in transaction}


def _source_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "transactionHash",
        "transactionIndex",
        "blockHash",
        "blockNumber",
        "from",
        "to",
        "contractAddress",
        "cumulativeGasUsed",
        "gasUsed",
        "effectiveGasPrice",
        "status",
        "type",
        "logsBloom",
    )
    result = {field: receipt[field] for field in fields if field in receipt}
    raw_logs = receipt.get("logs") or []
    logs = raw_logs if isinstance(raw_logs, list) else []
    bounded_logs: list[dict[str, Any]] = []
    for item in logs[:MAX_RECEIPT_LOGS]:
        if not isinstance(item, dict):
            continue
        selected = dict(item)
        raw_data = _hex_data(item.get("data"))
        if raw_data is not None:
            selected["data"] = "0x" + raw_data[:MAX_EVENT_DATA_BYTES].hex()
            selected["dataBytes"] = len(raw_data)
            selected["dataSha256"] = hashlib.sha256(raw_data).hexdigest()
            selected["dataTruncated"] = len(raw_data) > MAX_EVENT_DATA_BYTES
        else:
            selected["data"] = str(item.get("data") or "0x")[: 2 + MAX_EVENT_DATA_BYTES * 2]
        topics = item.get("topics")
        if isinstance(topics, list):
            selected["topics"] = [str(topic)[:66] for topic in topics[:32]]
        bounded_logs.append(selected)
    result["logs"] = bounded_logs
    return result


def investigate_transaction(
    rpc: JsonRpcClient,
    chain: ChainConfig,
    transaction_hash: str,
    *,
    resolver: AbiResolver | None = None,
    watchlist: Watchlist | None = None,
    include_trace: bool = True,
    include_state_diff: bool = True,
    replay_prestate: bool = True,
) -> InvestigationCase:
    """Reconstruct one confirmed transaction into a bounded, read-only evidence case."""

    tx_hash = validate_transaction_hash(transaction_hash)
    transaction = rpc.transaction(tx_hash)
    if not transaction:
        raise RuntimeError("The transaction is not available from the configured RPC endpoints")
    returned_hash = str(transaction.get("hash") or "").lower()
    if returned_hash != tx_hash:
        raise RuntimeError("RPC transaction hash does not match the requested transaction")
    receipt = rpc.receipt(tx_hash)
    if not receipt:
        raise RuntimeError("The transaction is pending or its receipt is unavailable")
    receipt_hash = str(receipt.get("transactionHash") or "").lower()
    if receipt_hash != tx_hash:
        raise RuntimeError("RPC receipt hash does not match the requested transaction")
    block_number = _quantity(receipt.get("blockNumber"), "receipt block number")
    transaction_block = _optional_quantity(transaction.get("blockNumber"))
    if transaction_block is not None and transaction_block != block_number:
        raise RuntimeError("RPC transaction and receipt block numbers do not match")
    block = rpc.block(block_number, full_transactions=False)
    if not block:
        raise RuntimeError("The containing block is unavailable from the configured RPC endpoints")
    returned_block_number = _optional_quantity(block.get("number"))
    if returned_block_number is not None and returned_block_number != block_number:
        raise RuntimeError("RPC block number does not match the transaction receipt")
    block_hashes = {
        str(value).lower()
        for value in (
            transaction.get("blockHash"),
            receipt.get("blockHash"),
            block.get("hash"),
        )
        if value
    }
    if len(block_hashes) > 1:
        raise RuntimeError("RPC block hashes disagree; retry after the chain view stabilizes")
    block_hash = next(iter(block_hashes), None)
    raw_status = receipt.get("status")
    if raw_status is None:
        status = "unknown"
    else:
        status_value = _quantity(raw_status, "receipt status")
        status = (
            "succeeded" if status_value == 1 else "reverted" if status_value == 0 else "unknown"
        )
    gas_used = _optional_quantity(receipt.get("gasUsed"))
    effective_gas_price = _optional_quantity(
        receipt.get("effectiveGasPrice") or transaction.get("gasPrice")
    )
    transaction_fee_wei = (
        str(gas_used * effective_gas_price)
        if gas_used is not None and effective_gas_price is not None
        else None
    )
    warnings: list[str] = []
    if transaction_fee_wei is None:
        warnings.append("Transaction fee is unavailable because gas evidence is incomplete.")
    raw_receipt_logs = receipt.get("logs") or []
    if not isinstance(raw_receipt_logs, list):
        raw_receipt_logs = []
        warnings.append("Receipt logs are malformed and could not be retained.")
    receipt_logs = [
        item for item in raw_receipt_logs[:MAX_RECEIPT_LOGS] if isinstance(item, dict)
    ]
    if len(raw_receipt_logs) > MAX_RECEIPT_LOGS:
        warnings.append(f"Receipt logs were capped at {MAX_RECEIPT_LOGS} entries.")
    events = _events_from_logs(
        receipt_logs,
        resolver=resolver,
        chain_id=chain.chain_id,
        warnings=warnings,
    )

    proxy_snapshot: ProxySnapshot | None = None
    target = _address(transaction.get("to"))
    if target:
        try:
            candidate = inspect_proxy(rpc, target, block_number=block_number)
            if candidate.effective_implementation or candidate.admin or candidate.beacon:
                proxy_snapshot = candidate
        except (RpcError, AttributeError, ValueError):
            warnings.append("Proxy inspection was unavailable from the configured RPC endpoint.")

    trace: dict[str, Any] | None = None
    if include_trace:
        try:
            trace = rpc.trace_transaction(tx_hash)
            if trace is None:
                warnings.append("The RPC endpoint returned no call trace for this transaction.")
        except (RpcError, AttributeError):
            warnings.append(
                "Call tracing is unavailable; receipt logs and top-level transaction evidence "
                "remain complete."
            )
    calls, trace_truncated = (
        _flatten_trace(
            trace,
            resolver=resolver,
            chain_id=chain.chain_id,
            proxy_implementation=(
                proxy_snapshot.effective_implementation if proxy_snapshot else None
            ),
        )
        if trace
        else ((), False)
    )
    if trace_truncated:
        warnings.append(f"The call graph was capped at {MAX_CALL_FRAMES} frames.")
    truncated_calldata = sum(frame.calldata_truncated for frame in calls)
    if truncated_calldata:
        warnings.append(
            f"Calldata was display-capped at {MAX_CALLDATA_BYTES} bytes in "
            f"{truncated_calldata} call frame(s); full byte lengths and SHA-256 digests "
            "are retained."
        )

    state_diff: StateDiff | None = None
    if include_state_diff:
        try:
            raw_state_diff = rpc.trace_transaction_state_diff(tx_hash)
            if raw_state_diff is None:
                warnings.append("The RPC endpoint returned no pre/post state-diff evidence.")
            else:
                state_diff = parse_state_diff(raw_state_diff)
                warnings.extend(state_diff.warnings)
        except (RpcError, AttributeError, ValueError):
            warnings.append(
                "Pre/post account and storage changes are unavailable from this RPC endpoint."
            )

    root_calldata = str(transaction.get("input") or "0x")
    root_call: DecodedCall | None = None
    if resolver and target:
        root_call = resolver.resolve(chain.chain_id, target, root_calldata)
        if not root_call.signature and proxy_snapshot and proxy_snapshot.effective_implementation:
            implementation_call = resolver.resolve(
                chain.chain_id,
                proxy_snapshot.effective_implementation,
                root_calldata,
            )
            if implementation_call.signature:
                root_call = dataclasses.replace(
                    implementation_call,
                    source=(implementation_call.source or "verified ABI")
                    + " via proxy implementation",
                )

    transfers = tuple(
        _native_transfers(calls, transaction) + _transfers_from_logs(receipt_logs, warnings)
    )
    entities, entities_truncated = _build_entities(
        rpc,
        chain_id=chain.chain_id,
        block_number=block_number,
        transaction=transaction,
        receipt=receipt,
        calls=calls,
        events=events,
        transfers=transfers,
        watchlist=watchlist,
    )
    if entities_truncated:
        warnings.append(f"The entity inventory was capped at {MAX_ENTITIES} addresses.")
    relationships = _build_relationships(calls, transfers)
    timeline = _build_timeline(calls, events, transfers)

    historical_replay: SimulationResult | None = None
    if replay_prestate and block_number > 0:
        try:
            historical_replay = simulate_transaction(
                rpc,
                transaction,
                block_number=block_number - 1,
                include_trace=False,
            )
            if historical_replay.status != "succeeded" and status == "succeeded":
                warnings.append(
                    "Pre-state eth_call did not reproduce the confirmed outcome; use the mined "
                    "trace as primary execution evidence."
                )
        except (RpcError, AttributeError, ValueError):
            warnings.append("Historical pre-state replay is unavailable from this RPC endpoint.")

    findings = _build_findings(
        status=status,
        calls=calls,
        events=events,
        transfers=transfers,
        proxy_snapshot=proxy_snapshot,
        state_diff=state_diff,
    )
    return InvestigationCase(
        schema_version=2,
        case_id=f"{chain.name}-{tx_hash[2:18]}",
        generated_at=utc_now(),
        chain=chain.name,
        chain_id=chain.chain_id,
        explorer_url=chain.explorer_url,
        transaction_hash=tx_hash,
        block_number=block_number,
        block_hash=block_hash,
        block_timestamp=_block_timestamp(block),
        transaction_status=status,
        transaction_fee_wei=transaction_fee_wei,
        trace_available=trace is not None,
        trace_truncated=trace_truncated,
        source_transaction=_source_transaction(transaction),
        source_receipt=_source_receipt(receipt),
        root_call=root_call,
        calls=calls,
        events=events,
        transfers=transfers,
        entities=entities,
        relationships=relationships,
        timeline=timeline,
        findings=findings,
        warnings=tuple(dict.fromkeys(warnings)),
        proxy_snapshot=proxy_snapshot,
        historical_replay=historical_replay,
        state_diff=state_diff,
    )
