from __future__ import annotations

import dataclasses
import datetime as dt
import json
import logging

from white_radar.config import Settings, Watchlist, configured_endpoints
from white_radar.enrichment import ContractEnricher
from white_radar.fingerprint import BytecodeFingerprint, fingerprint_bytecode
from white_radar.invariants import InvariantCheck, check_policy_invariants
from white_radar.logging import log_context
from white_radar.models import (
    ChainConfig,
    ContractMetadata,
    RadarEvent,
    severity_for_score,
    stable_event_id,
    utc_now,
)
from white_radar.policy import ProtocolPolicy, load_policy_book
from white_radar.proxy import inspect_proxy
from white_radar.rpc import JsonRpcClient, hex_to_int
from white_radar.scoring import score_deployment, score_profile_change, score_upgrade
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier
from white_radar.tracing import internal_creations

LOGGER = logging.getLogger(__name__)

UPGRADE_TOPICS = {
    "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b": "Upgraded",
    "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f": "AdminChanged",
    "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e": "BeaconUpgraded",
}


@dataclasses.dataclass(slots=True)
class ScanStats:
    chain: str
    start_block: int | None = None
    end_block: int | None = None
    blocks: int = 0
    deployments: int = 0
    upgrades: int = 0
    events: int = 0
    alerts: int = 0
    profiles_refreshed: int = 0
    profile_changes: int = 0
    invariants_checked: int = 0
    invariant_transitions: int = 0
    rpc_endpoint_count: int = 1
    rpc_active_endpoint: int = 0

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


class ChainScanner:
    def __init__(
        self,
        *,
        settings: Settings,
        chain: ChainConfig,
        watchlist: Watchlist,
        store: RadarStore,
        notifier: TelegramNotifier,
    ) -> None:
        rpc_urls = configured_endpoints(chain.rpc_http_env, chain.rpc_http_fallback_envs)
        if not rpc_urls:
            raise RuntimeError(f"Missing {chain.rpc_http_env} for enabled chain {chain.name}")
        self.settings = settings
        self.chain = chain
        self.watchlist = watchlist
        self.store = store
        self.notifier = notifier
        self.rpc = JsonRpcClient(
            rpc_urls,
            timeout=settings.app.request_timeout_seconds,
            retries=settings.app.request_retries,
        )
        self.policy_book = load_policy_book(settings.app.policy_path)
        self.enricher = ContractEnricher(
            settings.enrichment,
            timeout=settings.app.request_timeout_seconds,
            retries=settings.app.request_retries,
        )

    def scan(self) -> ScanStats:
        actual_chain_id = self.rpc.chain_id()
        if actual_chain_id != self.chain.chain_id:
            raise RuntimeError(
                f"RPC chain mismatch for {self.chain.name}: expected {self.chain.chain_id}, "
                f"received {actual_chain_id}"
            )
        head = self.rpc.block_number()
        safe_head = max(0, head - self.chain.confirmations)
        cursor = self.store.get_cursor(self.chain.chain_id)
        start = (
            max(0, safe_head - self.chain.initial_lookback_blocks + 1)
            if cursor is None
            else cursor + 1
        )
        stats = ScanStats(chain=self.chain.name)
        self._flush_alerts(stats)
        if self.settings.analysis.invariant_checks_enabled:
            self._scan_invariants(safe_head, stats)
        if start > safe_head:
            self._set_rpc_stats(stats)
            return stats
        end = min(safe_head, start + self.chain.max_blocks_per_cycle - 1)
        stats.start_block = start
        stats.end_block = end

        # Run range-level log monitoring before advancing the confirmed-block cursor.
        # Event insertion is idempotent, so a later block failure can be retried.
        self._scan_upgrades(start, end, stats)
        for number in range(start, end + 1):
            self._scan_block(number, stats)
            self.store.set_cursor(self.chain.chain_id, number)
            stats.blocks += 1
        self._flush_alerts(stats)
        self._set_rpc_stats(stats)
        LOGGER.info("chain scan complete", extra=log_context(**stats.to_dict()))
        return stats

    def check_invariants(self) -> ScanStats:
        actual_chain_id = self.rpc.chain_id()
        if actual_chain_id != self.chain.chain_id:
            raise RuntimeError(
                f"RPC chain mismatch for {self.chain.name}: expected {self.chain.chain_id}, "
                f"received {actual_chain_id}"
            )
        safe_head = max(0, self.rpc.block_number() - self.chain.confirmations)
        stats = ScanStats(chain=self.chain.name)
        self._scan_invariants(safe_head, stats)
        self._flush_alerts(stats)
        self._set_rpc_stats(stats)
        return stats

    def refresh_profiles(self, *, limit: int, min_age_minutes: int) -> ScanStats:
        """Re-enrich a bounded batch and surface material profile drift."""

        actual_chain_id = self.rpc.chain_id()
        if actual_chain_id != self.chain.chain_id:
            raise RuntimeError(
                f"RPC chain mismatch for {self.chain.name}: expected {self.chain.chain_id}, "
                f"received {actual_chain_id}"
            )
        stats = ScanStats(chain=self.chain.name)
        profiles = self.store.profiles_due_for_refresh(
            chain_id=self.chain.chain_id,
            min_age_minutes=min_age_minutes,
            limit=limit,
        )
        for profile in profiles:
            self._refresh_profile(profile, stats)
        self._flush_alerts(stats)
        self._set_rpc_stats(stats)
        LOGGER.info("profile refresh complete", extra=log_context(**stats.to_dict()))
        return stats

    def _set_rpc_stats(self, stats: ScanStats) -> None:
        stats.rpc_endpoint_count = int(getattr(self.rpc, "endpoint_count", 1))
        stats.rpc_active_endpoint = int(getattr(self.rpc, "active_endpoint_index", 0))

    @staticmethod
    def _state_value(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        return str(value)

    def _scan_invariants(self, block_number: int, stats: ScanStats) -> None:
        policies = self.policy_book.for_chain(self.chain.chain_id)
        if not policies:
            return
        block = self.rpc.block(block_number, full_transactions=False) or {}
        block_hash = str(block.get("hash") or "") or None
        for policy in policies:
            for check in check_policy_invariants(
                self.rpc,
                policy,
                block_number=block_number,
                block_hash=block_hash,
            ):
                stats.invariants_checked += 1
                self._record_invariant_transition(policy, check, stats)

    def _record_invariant_transition(
        self,
        policy: ProtocolPolicy,
        check: InvariantCheck,
        stats: ScanStats,
    ) -> None:
        previous = self.store.record_invariant_state(
            chain_id=self.chain.chain_id,
            policy_address=policy.address,
            invariant_name=check.name,
            status=check.status,
            observed_value=self._state_value(check.observed),
            expected_value=self._state_value(check.expected),
            block_number=check.block_number,
            block_hash=check.block_hash,
        )
        previous_status = str(previous.get("status")) if previous else None
        previous_value = str(previous.get("observed_value")) if previous else None
        current_value = self._state_value(check.observed)
        changed = previous_status != check.status or previous_value != current_value
        if not changed or check.status == "unavailable":
            return
        recovery = check.status == "ok" and previous_status in {"violated", "error"}
        if check.status == "ok" and not recovery:
            return
        event_type = "protocol_invariant_recovered" if recovery else "protocol_invariant_violation"
        error_score = max(50, check.score - 15)
        score = 20 if recovery else (error_score if check.status == "error" else check.score)
        reasons = (
            (
                f"Protocol invariant {check.name} returned to its configured baseline.",
                f"Previous state was {previous_status}.",
            )
            if recovery
            else (
                (
                    f"Protocol invariant {check.name} is {check.status} "
                    f"at pinned block {check.block_number}."
                ),
                f"Observed {current_value}; configured operator is {check.operator}.",
            )
        )
        event = RadarEvent(
            event_id=stable_event_id(
                event_type,
                self.chain.chain_id,
                policy.address,
                check.name,
                check.block_number,
                check.status,
                current_value,
            ),
            observed_at=utc_now(),
            event_type=event_type,
            title=(
                "Protocol invariant recovered"
                if recovery
                else "Protocol invariant requires investigation"
            ),
            summary=(
                f"{policy.protocol} invariant {check.name} changed to {check.status} "
                f"on {self.chain.display_name}."
            ),
            chain=self.chain.name,
            chain_id=self.chain.chain_id,
            score=score,
            severity=severity_for_score(score),
            confidence=0.98 if check.status != "error" else 0.8,
            reasons=reasons,
            recommended_action=(
                "Correlate the invariant transition with governance, upgrades, oracle inputs, "
                "and the protocol change calendar; preserve the pinned-block evidence."
            ),
            subject_address=policy.address,
            block_number=check.block_number,
            evidence={"contract": f"{self.chain.explorer_url}/address/{policy.address}"},
            metadata={
                "protocol": policy.protocol,
                "invariant": check.to_dict(),
                "previous_status": previous_status,
                "previous_observed_value": previous_value,
                "policy_sha256": self.policy_book.source_sha256,
            },
        )
        self._record_and_alert(event, stats)
        stats.invariant_transitions += 1

    def _refresh_profile(self, profile: dict[str, object], stats: ScanStats) -> None:
        address = str(profile["address"])
        code = self.rpc.code(address)
        fingerprint = fingerprint_bytecode(code)
        metadata = self.enricher.enrich(
            self.rpc,
            chain_id=self.chain.chain_id,
            address=address,
        )
        new_values: dict[str, object] = {
            "bytecode_sha256": fingerprint.raw_sha256,
            "normalized_sha256": fingerprint.normalized_sha256,
            "verified": int(metadata.verified),
            "verification_source": metadata.verification_source,
            "contract_name": metadata.contract_name,
            "is_proxy": int(metadata.is_proxy),
            "implementation": metadata.implementation,
            "admin": metadata.admin,
            "beacon": metadata.beacon,
        }
        changes = {
            field: {"previous": profile.get(field), "current": value}
            for field, value in new_values.items()
            if profile.get(field) != value
        }
        observed_at = utc_now()
        similar = self.store.similar_contracts(
            chain_id=self.chain.chain_id,
            address=address,
            fingerprint=fingerprint,
        )
        self.store.upsert_contract_profile(
            chain_id=self.chain.chain_id,
            address=address,
            fingerprint=fingerprint,
            metadata=metadata,
            observed_at=observed_at,
        )
        stats.profiles_refreshed += 1
        if not changes:
            return

        deployer = str(profile.get("deployer_address") or "")
        tx_hash = str(profile.get("tx_hash") or "")
        block_number = int(str(profile.get("block_number") or 0))
        deployer_watch = self.watchlist.deployer(self.chain.chain_id, deployer)
        if deployer and tx_hash:
            self._register_identity(
                address=address,
                deployer=deployer,
                tx_hash=tx_hash,
                block_number=block_number,
                observed_at=observed_at,
                metadata=metadata,
                fingerprint=fingerprint,
                similar=similar,
                deployer_label=deployer_watch.label if deployer_watch else None,
            )
        watched = self.watchlist.contract(self.chain.chain_id, address)
        score = score_profile_change(
            changed_fields=frozenset(changes),
            watched_protocol=watched.protocol if watched else None,
        )
        change_identity = "|".join(
            f"{field}:{value['current']}" for field, value in sorted(changes.items())
        )
        event = RadarEvent(
            event_id=stable_event_id(
                "contract_profile_changed",
                self.chain.chain_id,
                address,
                change_identity,
            ),
            observed_at=observed_at,
            event_type="contract_profile_changed",
            title="Contract intelligence changed",
            summary=(
                f"Scheduled re-enrichment observed {len(changes)} changed field(s) for "
                f"{address} on {self.chain.display_name}."
            ),
            chain=self.chain.name,
            chain_id=self.chain.chain_id,
            score=score.score,
            severity=severity_for_score(score.score),
            confidence=score.confidence,
            reasons=score.reasons,
            recommended_action=score.recommended_action,
            subject_address=address,
            deployer_address=deployer or None,
            tx_hash=tx_hash or None,
            block_number=block_number or None,
            evidence={
                "contract": f"{self.chain.explorer_url}/address/{address}",
                **(
                    {"original_deployment": f"{self.chain.explorer_url}/tx/{tx_hash}"}
                    if tx_hash
                    else {}
                ),
            },
            metadata={
                "protocol": watched.protocol if watched else None,
                "role": watched.role if watched else None,
                "changes": changes,
                "verified": metadata.verified,
                "verification_source": metadata.verification_source,
                "contract_name": metadata.contract_name,
                "normalized_bytecode_sha256": fingerprint.normalized_sha256,
                "is_proxy": metadata.is_proxy,
                "implementation": metadata.implementation,
                "admin": metadata.admin,
                "beacon": metadata.beacon,
                "similar_contracts": similar,
            },
        )
        self._record_and_alert(event, stats)
        stats.profile_changes += 1

    def _scan_block(self, number: int, stats: ScanStats) -> None:
        block = self.rpc.block(number, full_transactions=True)
        if not block:
            raise RuntimeError(f"Block {number} was not returned by {self.chain.name}")
        block_timestamp = dt.datetime.fromtimestamp(
            hex_to_int(str(block.get("timestamp") or "0x0")), tz=dt.UTC
        ).isoformat(timespec="seconds")
        transactions = block.get("transactions") or []
        for transaction in transactions:
            if not isinstance(transaction, dict):
                continue
            tx_hash = str(transaction.get("hash") or "").lower()
            sender = str(transaction.get("from") or "").lower()
            destination = str(transaction.get("to") or "").lower() or None
            if not tx_hash or not sender:
                continue
            if (
                self.chain.trace_internal_creations
                and destination
                and self.watchlist.contract(self.chain.chain_id, destination)
            ):
                self._scan_internal_creations(
                    tx_hash=tx_hash,
                    transaction_sender=sender,
                    block_number=number,
                    block_timestamp=block_timestamp,
                    stats=stats,
                )
            if destination is not None:
                continue
            receipt = self.rpc.receipt(tx_hash)
            if not receipt or hex_to_int(str(receipt.get("status") or "0x0")) != 1:
                continue
            address = str(receipt.get("contractAddress") or "").lower()
            if not address:
                continue
            self._process_deployment(
                address=address,
                deployer=sender,
                tx_hash=tx_hash,
                block_number=number,
                block_timestamp=block_timestamp,
                creation_type="CREATE",
                trace_depth=0,
                transaction_sender=sender,
                stats=stats,
            )

    def _scan_internal_creations(
        self,
        *,
        tx_hash: str,
        transaction_sender: str,
        block_number: int,
        block_timestamp: str,
        stats: ScanStats,
    ) -> None:
        try:
            trace = self.rpc.trace_transaction(tx_hash)
        except Exception:
            LOGGER.exception(
                "inventory transaction trace failed",
                extra=log_context(chain=self.chain.name, tx_hash=tx_hash),
            )
            return
        if not trace:
            return
        for creation in internal_creations(trace):
            self._process_deployment(
                address=creation.address,
                deployer=creation.creator,
                tx_hash=tx_hash,
                block_number=block_number,
                block_timestamp=block_timestamp,
                creation_type=creation.creation_type,
                trace_depth=creation.depth,
                transaction_sender=transaction_sender,
                stats=stats,
            )

    def _process_deployment(
        self,
        *,
        address: str,
        deployer: str,
        tx_hash: str,
        block_number: int,
        block_timestamp: str,
        creation_type: str,
        trace_depth: int,
        transaction_sender: str,
        stats: ScanStats,
    ) -> None:
        code = self.rpc.code(address, hex(block_number))
        fingerprint = fingerprint_bytecode(code)
        metadata = self.enricher.enrich(self.rpc, chain_id=self.chain.chain_id, address=address)
        observed_at = utc_now()
        inserted = self.store.add_deployment(
            chain_id=self.chain.chain_id,
            address=address,
            deployer_address=deployer,
            tx_hash=tx_hash,
            block_number=block_number,
            observed_at=observed_at,
            contract_name=metadata.contract_name,
            is_proxy=metadata.is_proxy,
        )
        if not inserted:
            return
        similar = self.store.similar_contracts(
            chain_id=self.chain.chain_id,
            address=address,
            fingerprint=fingerprint,
        )
        self.store.upsert_contract_profile(
            chain_id=self.chain.chain_id,
            address=address,
            fingerprint=fingerprint,
            metadata=metadata,
            observed_at=observed_at,
        )
        related = self.store.related_deployments(self.chain.chain_id, deployer)
        deployer_watch = self.watchlist.deployer(self.chain.chain_id, deployer)
        exact_matches = sum(bool(item["exact_normalized_match"]) for item in similar)
        score = score_deployment(
            chain=self.chain,
            metadata=metadata,
            bytecode_size=fingerprint.bytecode_size,
            cluster_size=len(related),
            watched_deployer_label=deployer_watch.label if deployer_watch else None,
            exact_match_count=exact_matches,
            similar_count=len(similar),
        )
        self._register_identity(
            address=address,
            deployer=deployer,
            tx_hash=tx_hash,
            block_number=block_number,
            observed_at=observed_at,
            metadata=metadata,
            fingerprint=fingerprint,
            similar=similar,
            deployer_label=deployer_watch.label if deployer_watch else None,
        )
        event_type = "internal_contract_deployment" if trace_depth else "contract_deployment"
        event = RadarEvent(
            event_id=stable_event_id(event_type, self.chain.chain_id, tx_hash, address),
            observed_at=observed_at,
            event_type=event_type,
            title=(
                f"Internal contract creation ({creation_type})"
                if trace_depth
                else "New contract deployment"
            ),
            summary=(
                f"{metadata.contract_name or 'Unlabelled contract'} deployed on "
                f"{self.chain.display_name} by {deployer}."
            ),
            chain=self.chain.name,
            chain_id=self.chain.chain_id,
            score=score.score,
            severity=severity_for_score(score.score),
            confidence=score.confidence,
            reasons=score.reasons,
            recommended_action=score.recommended_action,
            subject_address=address,
            deployer_address=deployer,
            tx_hash=tx_hash,
            block_number=block_number,
            evidence={
                "transaction": f"{self.chain.explorer_url}/tx/{tx_hash}",
                "contract": f"{self.chain.explorer_url}/address/{address}",
                "deployer": f"{self.chain.explorer_url}/address/{deployer}",
            },
            metadata={
                "block_timestamp": block_timestamp,
                "bytecode_size": fingerprint.bytecode_size,
                "normalized_bytecode_size": fingerprint.normalized_size,
                "solidity_metadata_size": fingerprint.metadata_size,
                "bytecode_sha256": fingerprint.raw_sha256,
                "normalized_bytecode_sha256": fingerprint.normalized_sha256,
                "bytecode_simhash64": fingerprint.simhash64,
                "similar_contracts": similar,
                "verified": metadata.verified,
                "verification_source": metadata.verification_source,
                "contract_name": metadata.contract_name,
                "is_proxy": metadata.is_proxy,
                "implementation": metadata.implementation,
                "admin": metadata.admin,
                "beacon": metadata.beacon,
                "deployer_cluster_size": len(related),
                "related_contracts": related,
                "creation_type": creation_type,
                "trace_depth": trace_depth,
                "transaction_sender": transaction_sender,
            },
        )
        self._record_and_alert(event, stats)
        stats.deployments += 1

    def _register_identity(
        self,
        *,
        address: str,
        deployer: str,
        tx_hash: str,
        block_number: int,
        observed_at: str,
        metadata: ContractMetadata,
        fingerprint: BytecodeFingerprint,
        similar: list[dict[str, object]],
        deployer_label: str | None,
    ) -> None:
        contract_metadata = {
            "contract_name": metadata.contract_name,
            "verified": metadata.verified,
            "normalized_bytecode_sha256": fingerprint.normalized_sha256,
        }
        contract_node = self.store.upsert_identity_node(
            chain_id=self.chain.chain_id,
            kind="contract",
            value=address,
            label=metadata.contract_name,
            metadata=contract_metadata,
        )
        deployer_node = self.store.upsert_identity_node(
            chain_id=self.chain.chain_id,
            kind="deployer",
            value=deployer,
            label=deployer_label,
        )
        edge_evidence = {"transaction": tx_hash, "block_number": block_number}
        self.store.upsert_identity_edge(
            chain_id=self.chain.chain_id,
            source_node_id=deployer_node,
            relation="DEPLOYED",
            target_node_id=contract_node,
            evidence=edge_evidence,
            observed_at=observed_at,
        )
        relationships = (
            ("implementation", "contract", "DELEGATES_TO"),
            ("admin", "account", "ADMINISTERED_BY"),
            ("beacon", "contract", "USES_BEACON"),
        )
        for field, kind, relation in relationships:
            value = getattr(metadata, field)
            if not value:
                continue
            target = self.store.upsert_identity_node(
                chain_id=self.chain.chain_id,
                kind=kind,
                value=str(value),
            )
            self.store.upsert_identity_edge(
                chain_id=self.chain.chain_id,
                source_node_id=contract_node,
                relation=relation,
                target_node_id=target,
                evidence=edge_evidence,
                observed_at=observed_at,
            )
        for item in similar:
            other_address = str(item.get("address") or "")
            if not other_address:
                continue
            other = self.store.upsert_identity_node(
                chain_id=self.chain.chain_id,
                kind="contract",
                value=other_address,
                label=str(item.get("contract_name") or "") or None,
            )
            self.store.upsert_identity_edge(
                chain_id=self.chain.chain_id,
                source_node_id=contract_node,
                relation=(
                    "BYTECODE_MATCHES"
                    if item.get("exact_normalized_match")
                    else "BYTECODE_SIMILAR_TO"
                ),
                target_node_id=other,
                evidence={
                    "similarity": item.get("similarity"),
                    "normalized_bytecode_sha256": fingerprint.normalized_sha256,
                },
                observed_at=observed_at,
            )

    def _scan_upgrades(self, start: int, end: int, stats: ScanStats) -> None:
        watched_addresses = sorted(self.watchlist.addresses_for_chain(self.chain.chain_id))
        if not self.chain.monitor_global_upgrades and not watched_addresses:
            return
        addresses = None if self.chain.monitor_global_upgrades else watched_addresses
        logs = self.rpc.logs(
            from_block=start,
            to_block=end,
            topics=[list(UPGRADE_TOPICS)],
            addresses=addresses,
        )
        for entry in logs:
            topics = entry.get("topics") or []
            if not topics:
                continue
            topic = str(topics[0]).lower()
            event_name = UPGRADE_TOPICS.get(topic)
            if not event_name:
                continue
            proxy = str(entry.get("address") or "").lower()
            tx_hash = str(entry.get("transactionHash") or "").lower()
            block_number = hex_to_int(str(entry.get("blockNumber") or "0x0"))
            watched = self.watchlist.contract(self.chain.chain_id, proxy)
            score = score_upgrade(
                watched_protocol=watched.protocol if watched else None,
                global_scan=self.chain.monitor_global_upgrades,
            )
            proxy_snapshot = None
            try:
                proxy_snapshot = inspect_proxy(self.rpc, proxy, block_number=block_number)
            except Exception:
                LOGGER.exception(
                    "proxy snapshot failed",
                    extra=log_context(chain=self.chain.name, address=proxy),
                )
            snapshot_delta = proxy_snapshot.score_delta if proxy_snapshot else 0
            final_score = min(100, score.score + snapshot_delta)
            snapshot_reasons = (
                tuple(item.summary for item in proxy_snapshot.findings) if proxy_snapshot else ()
            )
            indexed_address = None
            if len(topics) > 1 and len(str(topics[1])) >= 42:
                indexed_address = "0x" + str(topics[1])[-40:].lower()
            event = RadarEvent(
                event_id=stable_event_id(
                    "proxy_control_event", self.chain.chain_id, tx_hash, proxy, event_name
                ),
                observed_at=utc_now(),
                event_type="proxy_control_event",
                title=f"Proxy control event: {event_name}",
                summary=f"{event_name} emitted by {proxy} on {self.chain.display_name}.",
                chain=self.chain.name,
                chain_id=self.chain.chain_id,
                score=final_score,
                severity=severity_for_score(final_score),
                confidence=score.confidence,
                reasons=score.reasons + snapshot_reasons,
                recommended_action=score.recommended_action,
                subject_address=proxy,
                tx_hash=tx_hash,
                block_number=block_number,
                evidence={
                    "transaction": f"{self.chain.explorer_url}/tx/{tx_hash}",
                    "proxy": f"{self.chain.explorer_url}/address/{proxy}",
                },
                metadata={
                    "proxy_event": event_name,
                    "indexed_address": indexed_address,
                    "protocol": watched.protocol if watched else None,
                    "role": watched.role if watched else None,
                    "bounty_url": watched.bounty_url if watched else "",
                    "contact_uri": watched.contact_uri if watched else "",
                    "verification_source": "on-chain event log",
                    "proxy_snapshot": proxy_snapshot.to_dict() if proxy_snapshot else None,
                },
            )
            proxy_node = self.store.upsert_identity_node(
                chain_id=self.chain.chain_id,
                kind="contract",
                value=proxy,
                label=f"{watched.protocol} {watched.role}" if watched else None,
            )
            if watched:
                protocol_node = self.store.upsert_identity_node(
                    chain_id=self.chain.chain_id,
                    kind="protocol",
                    value=watched.protocol,
                    label=watched.protocol,
                )
                self.store.upsert_identity_edge(
                    chain_id=self.chain.chain_id,
                    source_node_id=protocol_node,
                    relation="CONTAINS",
                    target_node_id=proxy_node,
                    evidence={"watchlist": True, "bounty_url": watched.bounty_url},
                    observed_at=event.observed_at,
                )
            if indexed_address:
                relation_by_event = {
                    "Upgraded": ("contract", "DELEGATES_TO"),
                    "BeaconUpgraded": ("contract", "USES_BEACON"),
                    "AdminChanged": ("account", "ADMINISTERED_BY"),
                }
                target_kind, relation = relation_by_event[event_name]
                target_node = self.store.upsert_identity_node(
                    chain_id=self.chain.chain_id,
                    kind=target_kind,
                    value=indexed_address,
                )
                self.store.upsert_identity_edge(
                    chain_id=self.chain.chain_id,
                    source_node_id=proxy_node,
                    relation=relation,
                    target_node_id=target_node,
                    evidence={"transaction": tx_hash, "event": event_name},
                    observed_at=event.observed_at,
                )
            self._record_and_alert(event, stats)
            stats.upgrades += 1

    def _record_and_alert(self, event: RadarEvent, stats: ScanStats) -> None:
        if not self.store.add_event(event):
            return
        self.store.open_incident(
            event,
            minimum_score=self.settings.app.incident_minimum_score,
            sla_minutes=self.settings.app.incident_sla_minutes,
            protocol=str(event.metadata.get("protocol") or "") or None,
        )
        stats.events += 1
        LOGGER.info("radar event", extra=log_context(**event.to_dict()))

    def _flush_alerts(self, stats: ScanStats) -> None:
        for event in self.store.pending_alerts(self.chain.chain_id):
            if not self.notifier.should_send(event, self.chain):
                continue
            try:
                if self.notifier.send(event, self.chain):
                    self.store.mark_alerted(event.event_id)
                    stats.alerts += 1
            except Exception:
                LOGGER.exception(
                    "alert delivery failed",
                    extra=log_context(chain=self.chain.name, event_id=event.event_id),
                )
