from __future__ import annotations

import dataclasses
from collections import defaultdict
from typing import TYPE_CHECKING

from white_radar.abi import AbiResolver
from white_radar.history import ZERO_ADDRESS, HistoryRecord, HistorySource, HistorySourceError
from white_radar.investigation import InvestigationCase, investigate_transaction
from white_radar.models import ChainConfig, utc_now
from white_radar.rpc import JsonRpcClient, RpcError
from white_radar.token_metadata import TokenMetadataResolver

if TYPE_CHECKING:
    from white_radar.config import Watchlist


@dataclasses.dataclass(frozen=True, slots=True)
class ReconstructionLimits:
    backward_blocks: int = 256
    forward_blocks: int = 512
    max_hops: int = 3
    max_transactions: int = 100
    max_frontier_addresses: int = 64
    history_records_per_address: int = 200

    def __post_init__(self) -> None:
        bounds = {
            "backward_blocks": (self.backward_blocks, 0, 100_000),
            "forward_blocks": (self.forward_blocks, 0, 100_000),
            "max_hops": (self.max_hops, 0, 8),
            "max_transactions": (self.max_transactions, 1, 2_000),
            "max_frontier_addresses": (self.max_frontier_addresses, 1, 2_000),
            "history_records_per_address": (self.history_records_per_address, 1, 5_000),
        }
        for name, (value, minimum, maximum) in bounds.items():
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")

    def to_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class TransactionContext:
    transaction_hash: str
    block_number: int
    transaction_index: int | None
    block_timestamp: str | None
    phase: str
    hop: int
    relevance_score: int
    discovery_reasons: tuple[str, ...]
    status: str
    sender: str | None
    recipient: str | None
    selector: str
    function_signature: str | None
    function_confidence: str | None
    function_source: str | None
    decoded_arguments: dict[str, object]
    call_count: int
    transfer_count: int
    trace_available: bool

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class ReconstructionEntity:
    address: str
    kind: str
    label: str | None
    roles: tuple[str, ...]
    transaction_hashes: tuple[str, ...]
    first_block: int
    last_block: int
    code_observed: bool | None
    code_bytes_min: int | None
    code_bytes_max: int | None
    runtime_code_sha256s: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class ReconstructionEdge:
    edge_id: str
    transaction_hash: str
    block_number: int
    hop: int
    source: str
    target: str
    relation: str
    asset_type: str | None
    asset_address: str | None
    asset_symbol: str | None
    raw_amount: str | None
    amount_display: str | None
    evidence_ref: str

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class ReconstructionTimelineEntry:
    entry_id: str
    transaction_hash: str
    block_number: int
    block_timestamp: str | None
    transaction_phase: str
    transaction_index: int | None
    event_phase: str
    event_order: int
    event_type: str
    summary: str
    evidence_ref: str

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class ReconstructionCoverage:
    boundary_status: str
    requested_start_block: int
    requested_end_block: int
    observed_chain_head: int
    addresses_queried: int
    history_records_considered: int
    transaction_candidates: int
    transactions_reconstructed: int
    transaction_failures: int
    transaction_limit_reached: bool
    address_limit_reached: bool
    history_sources: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class AttackReconstruction:
    schema_version: int
    reconstruction_id: str
    generated_at: str
    chain: str
    chain_id: int
    explorer_url: str
    seed_transaction_hash: str
    seed_block_number: int
    limits: ReconstructionLimits
    coverage: ReconstructionCoverage
    contexts: tuple[TransactionContext, ...]
    transactions: tuple[InvestigationCase, ...]
    entities: tuple[ReconstructionEntity, ...]
    edges: tuple[ReconstructionEdge, ...]
    timeline: tuple[ReconstructionTimelineEntry, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "reconstruction_id": self.reconstruction_id,
            "generated_at": self.generated_at,
            "chain": self.chain,
            "chain_id": self.chain_id,
            "explorer_url": self.explorer_url,
            "seed_transaction_hash": self.seed_transaction_hash,
            "seed_block_number": self.seed_block_number,
            "limits": self.limits.to_dict(),
            "coverage": self.coverage.to_dict(),
            "contexts": [item.to_dict() for item in self.contexts],
            "transactions": [item.to_dict() for item in self.transactions],
            "entities": [item.to_dict() for item in self.entities],
            "edges": [item.to_dict() for item in self.edges],
            "timeline": [item.to_dict() for item in self.timeline],
            "warnings": list(self.warnings),
        }


@dataclasses.dataclass(slots=True)
class _Candidate:
    transaction_hash: str
    block_number: int
    hop: int
    score: int = 0
    reasons: set[str] = dataclasses.field(default_factory=set)
    records: list[tuple[str, HistoryRecord]] = dataclasses.field(default_factory=list)


def _source_transaction_address(case: InvestigationCase, field: str) -> str | None:
    value = str(case.source_transaction.get(field) or "").lower()
    return value if len(value) == 42 and value.startswith("0x") else None


def _seed_frontier(case: InvestigationCase) -> dict[str, int]:
    selected: dict[str, int] = {}
    origin = _source_transaction_address(case, "from")
    if origin and origin != ZERO_ADDRESS:
        selected[origin] = 0
    target = _source_transaction_address(case, "to")
    if target and target != ZERO_ADDRESS:
        selected[target] = 0
    for transfer in case.transfers:
        if transfer.sender != ZERO_ADDRESS:
            selected[transfer.sender] = 0
        if transfer.recipient != ZERO_ADDRESS:
            selected[transfer.recipient] = 0
    return selected


def _record_reason(address: str, record: HistoryRecord) -> tuple[str, str | None]:
    if record.sender == address:
        return f"{record.record_type}:sent_by:{address}", record.recipient
    if record.recipient == address:
        return f"{record.record_type}:received_by:{address}", record.sender
    return f"{record.record_type}:linked:{address}", None


def _record_score(record: HistoryRecord, *, address: str, seed_block: int) -> int:
    base = {
        "internal": 95,
        "erc20": 90,
        "erc721": 90,
        "erc1155": 90,
        "normal": 55,
    }.get(record.record_type, 40)
    if record.value not in {None, "", "0"}:
        base += 10
    if (record.block_number < seed_block and record.recipient == address) or (
        record.block_number > seed_block and record.sender == address
    ):
        base += 15
    distance = abs(record.block_number - seed_block)
    return base + max(0, 20 - min(20, distance))


def _phase(block_number: int, seed_block: int, tx_hash: str, seed_hash: str) -> str:
    if tx_hash == seed_hash:
        return "seed"
    if block_number < seed_block:
        return "pre_seed"
    if block_number > seed_block:
        return "post_seed"
    return "same_block"


def _transaction_index(case: InvestigationCase) -> int | None:
    value = case.source_transaction.get("transactionIndex")
    if value is None:
        return None
    try:
        return int(str(value), 16)
    except ValueError:
        return None


def _context(
    case: InvestigationCase,
    *,
    seed_hash: str,
    seed_block: int,
    hop: int,
    score: int,
    reasons: tuple[str, ...],
) -> TransactionContext:
    sender = _source_transaction_address(case, "from")
    recipient = _source_transaction_address(case, "to")
    selector = str(case.source_transaction.get("input") or "0x")[:10].lower()
    return TransactionContext(
        transaction_hash=case.transaction_hash,
        block_number=case.block_number,
        transaction_index=_transaction_index(case),
        block_timestamp=case.block_timestamp,
        phase=_phase(case.block_number, seed_block, case.transaction_hash, seed_hash),
        hop=hop,
        relevance_score=max(0, min(100, score)),
        discovery_reasons=reasons,
        status=case.transaction_status,
        sender=sender,
        recipient=recipient,
        selector=selector,
        function_signature=case.root_call.signature if case.root_call else None,
        function_confidence=case.root_call.confidence if case.root_call else None,
        function_source=case.root_call.source if case.root_call else None,
        decoded_arguments=dict(case.root_call.arguments) if case.root_call else {},
        call_count=len(case.calls),
        transfer_count=len(case.transfers),
        trace_available=case.trace_available,
    )


def _aggregate_entities(
    cases: tuple[InvestigationCase, ...],
) -> tuple[ReconstructionEntity, ...]:
    roles: dict[str, set[str]] = defaultdict(set)
    transactions: dict[str, set[str]] = defaultdict(set)
    blocks: dict[str, list[int]] = defaultdict(list)
    labels: dict[str, str] = {}
    kinds: dict[str, str] = {}
    code_observations: dict[str, list[bool]] = defaultdict(list)
    code_sizes: dict[str, list[int]] = defaultdict(list)
    code_hashes: dict[str, set[str]] = defaultdict(set)
    kind_priority = {"unknown": 0, "account": 1, "system": 2, "contract": 3}
    for case in cases:
        for entity in case.entities:
            roles[entity.address].update(entity.roles)
            transactions[entity.address].add(case.transaction_hash)
            blocks[entity.address].append(case.block_number)
            if entity.label:
                labels.setdefault(entity.address, entity.label)
            if entity.code_observed is not None:
                code_observations[entity.address].append(entity.code_observed)
            if entity.code_bytes is not None:
                code_sizes[entity.address].append(entity.code_bytes)
            if entity.runtime_code_sha256:
                code_hashes[entity.address].add(entity.runtime_code_sha256)
            current = kinds.get(entity.address, "unknown")
            if kind_priority.get(entity.kind, 0) >= kind_priority.get(current, 0):
                kinds[entity.address] = entity.kind
    return tuple(
        ReconstructionEntity(
            address=address,
            kind=kinds.get(address, "unknown"),
            label=labels.get(address),
            roles=tuple(sorted(roles[address])),
            transaction_hashes=tuple(sorted(transactions[address])),
            first_block=min(blocks[address]),
            last_block=max(blocks[address]),
            code_observed=(
                any(code_observations[address]) if code_observations[address] else None
            ),
            code_bytes_min=(min(code_sizes[address]) if code_sizes[address] else None),
            code_bytes_max=(max(code_sizes[address]) if code_sizes[address] else None),
            runtime_code_sha256s=tuple(sorted(code_hashes[address])),
        )
        for address in sorted(roles)
    )


def _aggregate_edges(
    cases: tuple[InvestigationCase, ...], contexts: dict[str, TransactionContext]
) -> tuple[ReconstructionEdge, ...]:
    edges: list[ReconstructionEdge] = []
    for case in cases:
        context = contexts[case.transaction_hash]
        for relation in case.relationships:
            edges.append(
                ReconstructionEdge(
                    edge_id=f"{case.transaction_hash}:{relation.relationship_id}",
                    transaction_hash=case.transaction_hash,
                    block_number=case.block_number,
                    hop=context.hop,
                    source=relation.source,
                    target=relation.target,
                    relation=relation.relation,
                    asset_type=relation.asset_type,
                    asset_address=relation.asset_address,
                    asset_symbol=relation.asset_symbol,
                    raw_amount=relation.amount,
                    amount_display=relation.amount_display,
                    evidence_ref=f"{case.transaction_hash}:{relation.evidence_ref}",
                )
            )
    return tuple(
        sorted(edges, key=lambda item: (item.block_number, item.transaction_hash, item.edge_id))
    )


def _aggregate_timeline(
    cases: tuple[InvestigationCase, ...], contexts: dict[str, TransactionContext]
) -> tuple[ReconstructionTimelineEntry, ...]:
    entries: list[ReconstructionTimelineEntry] = []
    for case in cases:
        context = contexts[case.transaction_hash]
        for event in case.timeline:
            entries.append(
                ReconstructionTimelineEntry(
                    entry_id=f"{case.transaction_hash}:{event.entry_id}",
                    transaction_hash=case.transaction_hash,
                    block_number=case.block_number,
                    block_timestamp=case.block_timestamp,
                    transaction_phase=context.phase,
                    transaction_index=context.transaction_index,
                    event_phase=event.phase,
                    event_order=event.order,
                    event_type=event.event_type,
                    summary=event.summary,
                    evidence_ref=f"{case.transaction_hash}:{event.evidence_ref}",
                )
            )
    phase_order = {"pre_seed": 0, "same_block": 1, "seed": 2, "post_seed": 3}
    return tuple(
        sorted(
            entries,
            key=lambda item: (
                item.block_number,
                item.transaction_index if item.transaction_index is not None else 2**31,
                phase_order.get(item.transaction_phase, 9),
                item.event_phase,
                item.event_order,
                item.entry_id,
            ),
        )
    )


def reconstruct_attack_case(
    rpc: JsonRpcClient,
    chain: ChainConfig,
    seed_case: InvestigationCase,
    history: HistorySource,
    *,
    limits: ReconstructionLimits | None = None,
    resolver: AbiResolver | None = None,
    watchlist: Watchlist | None = None,
    token_metadata: TokenMetadataResolver | None = None,
    include_trace: bool = True,
) -> AttackReconstruction:
    """Expand a seed transaction into a bounded, evidence-backed candidate incident graph."""

    active_limits = limits or ReconstructionLimits()
    warnings: list[str] = []
    try:
        head = rpc.block_number()
    except (RpcError, AttributeError):
        head = seed_case.block_number + active_limits.forward_blocks
        warnings.append(
            "The chain head was unavailable; the requested forward boundary was used as the cap."
        )
    start_block = max(0, seed_case.block_number - active_limits.backward_blocks)
    end_block = min(head, seed_case.block_number + active_limits.forward_blocks)
    seed = token_metadata.enrich_case(seed_case) if token_metadata else seed_case
    cases: dict[str, InvestigationCase] = {seed.transaction_hash: seed}
    contexts: dict[str, TransactionContext] = {
        seed.transaction_hash: _context(
            seed,
            seed_hash=seed.transaction_hash,
            seed_block=seed.block_number,
            hop=0,
            score=100,
            reasons=("operator_seed",),
        )
    }
    address_hops = _seed_frontier(seed)
    queried: set[str] = set()
    candidates: dict[str, _Candidate] = {}
    history_records_considered = 0
    failures = 0
    address_limit_reached = False

    for hop in range(active_limits.max_hops):
        frontier = sorted(
            address for address, address_hop in address_hops.items() if address_hop == hop
        )
        if not frontier:
            break
        for address in frontier:
            if len(queried) >= active_limits.max_frontier_addresses:
                address_limit_reached = True
                break
            if address in queried:
                continue
            queried.add(address)
            try:
                records = history.records_for_address(
                    chain_id=chain.chain_id,
                    address=address,
                    start_block=start_block,
                    end_block=end_block,
                    anchor_block=seed.block_number,
                    limit=active_limits.history_records_per_address,
                )
            except HistorySourceError as exc:
                warnings.append(f"History lookup failed for {address}: {exc}")
                continue
            history_records_considered += len(records)
            for record in records:
                if record.transaction_hash == seed.transaction_hash:
                    continue
                candidate = candidates.setdefault(
                    record.transaction_hash,
                    _Candidate(record.transaction_hash, record.block_number, hop + 1),
                )
                reason, _counterpart = _record_reason(address, record)
                candidate.reasons.add(reason)
                candidate.records.append((address, record))
                candidate.score = max(
                    candidate.score,
                    _record_score(record, address=address, seed_block=seed.block_number),
                )
                candidate.hop = min(candidate.hop, hop + 1)
        if address_limit_reached:
            break

        available = [
            item
            for item in candidates.values()
            if item.transaction_hash not in cases and item.hop == hop + 1
        ]
        available.sort(
            key=lambda item: (
                -item.score,
                abs(item.block_number - seed.block_number),
                item.block_number,
                item.transaction_hash,
            )
        )
        remaining = active_limits.max_transactions - len(cases)
        for candidate in available[: max(0, remaining)]:
            try:
                related = investigate_transaction(
                    rpc,
                    chain,
                    candidate.transaction_hash,
                    resolver=resolver,
                    watchlist=watchlist,
                    include_trace=include_trace,
                    replay_prestate=False,
                )
            except (RuntimeError, RpcError, ValueError) as exc:
                failures += 1
                warnings.append(
                    f"Candidate {candidate.transaction_hash} could not be reconstructed "
                    f"({type(exc).__name__})."
                )
                continue
            if token_metadata:
                related = token_metadata.enrich_case(related)
            cases[related.transaction_hash] = related
            contexts[related.transaction_hash] = _context(
                related,
                seed_hash=seed.transaction_hash,
                seed_block=seed.block_number,
                hop=candidate.hop,
                score=candidate.score,
                reasons=tuple(sorted(candidate.reasons)),
            )
            if candidate.hop >= active_limits.max_hops:
                continue
            next_hop = candidate.hop
            linked_addresses = {address for address, _record in candidate.records}
            for address, record in candidate.records:
                _reason, counterpart = _record_reason(address, record)
                if counterpart and counterpart != ZERO_ADDRESS:
                    linked_addresses.add(counterpart)
            for transfer in related.transfers:
                if transfer.sender in linked_addresses and transfer.recipient != ZERO_ADDRESS:
                    linked_addresses.add(transfer.recipient)
                if transfer.recipient in linked_addresses and transfer.sender != ZERO_ADDRESS:
                    linked_addresses.add(transfer.sender)
            for linked in sorted(linked_addresses):
                if linked == ZERO_ADDRESS:
                    continue
                if linked in address_hops:
                    continue
                if len(address_hops) >= active_limits.max_frontier_addresses:
                    address_limit_reached = True
                    break
                address_hops[linked] = next_hop
        if len(cases) >= active_limits.max_transactions:
            break

    warnings.extend(history.warnings)
    ordered_cases = tuple(
        sorted(
            cases.values(),
            key=lambda item: (
                item.block_number,
                _transaction_index(item) if _transaction_index(item) is not None else 2**31,
                item.transaction_hash,
            ),
        )
    )
    ordered_contexts = tuple(contexts[item.transaction_hash] for item in ordered_cases)
    history_sources = tuple(
        sorted(
            {
                record.source
                for candidate in candidates.values()
                for _address_value, record in candidate.records
            }
        )
    )
    transaction_limit_reached = len(cases) >= active_limits.max_transactions and any(
        candidate.transaction_hash not in cases for candidate in candidates.values()
    )
    coverage = ReconstructionCoverage(
        boundary_status="bounded_candidate_chain",
        requested_start_block=start_block,
        requested_end_block=end_block,
        observed_chain_head=head,
        addresses_queried=len(queried),
        history_records_considered=history_records_considered,
        transaction_candidates=len(candidates),
        transactions_reconstructed=len(ordered_cases),
        transaction_failures=failures,
        transaction_limit_reached=transaction_limit_reached,
        address_limit_reached=address_limit_reached,
        history_sources=history_sources,
    )
    if coverage.transaction_limit_reached:
        warnings.append(
            "The transaction cap was reached; additional related transactions may exist."
        )
    if coverage.address_limit_reached:
        warnings.append("The frontier-address cap was reached; graph expansion is incomplete.")
    warnings.append(
        "The reconstructed boundary is evidence-backed but bounded; it is not proof that the "
        "earliest or final incident transaction has been identified."
    )
    return AttackReconstruction(
        schema_version=1,
        reconstruction_id=f"{chain.name}-{seed.transaction_hash[2:18]}-reconstruction",
        generated_at=utc_now(),
        chain=chain.name,
        chain_id=chain.chain_id,
        explorer_url=chain.explorer_url,
        seed_transaction_hash=seed.transaction_hash,
        seed_block_number=seed.block_number,
        limits=active_limits,
        coverage=coverage,
        contexts=ordered_contexts,
        transactions=ordered_cases,
        entities=_aggregate_entities(ordered_cases),
        edges=_aggregate_edges(ordered_cases, contexts),
        timeline=_aggregate_timeline(ordered_cases, contexts),
        warnings=tuple(dict.fromkeys(warnings)),
    )
