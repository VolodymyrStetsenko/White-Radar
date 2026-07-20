from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import os

from white_radar.config import Settings, Watchlist
from white_radar.enrichment import ContractEnricher
from white_radar.logging import log_context
from white_radar.models import (
    ChainConfig,
    RadarEvent,
    severity_for_score,
    stable_event_id,
    utc_now,
)
from white_radar.rpc import JsonRpcClient, hex_to_int
from white_radar.scoring import score_deployment, score_upgrade
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier

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
        rpc_url = os.getenv(chain.rpc_http_env, "").strip()
        if not rpc_url:
            raise RuntimeError(f"Missing {chain.rpc_http_env} for enabled chain {chain.name}")
        self.settings = settings
        self.chain = chain
        self.watchlist = watchlist
        self.store = store
        self.notifier = notifier
        self.rpc = JsonRpcClient(
            rpc_url,
            timeout=settings.app.request_timeout_seconds,
            retries=settings.app.request_retries,
        )
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
        if start > safe_head:
            return stats
        end = min(safe_head, start + self.chain.max_blocks_per_cycle - 1)
        stats.start_block = start
        stats.end_block = end

        # Run range-level log monitoring before advancing the confirmed-block cursor.
        # Event insertion is idempotent, so a later block failure is safe to retry.
        self._scan_upgrades(start, end, stats)
        for number in range(start, end + 1):
            self._scan_block(number, stats)
            self.store.set_cursor(self.chain.chain_id, number)
            stats.blocks += 1
        self._flush_alerts(stats)
        LOGGER.info("chain scan complete", extra=log_context(**stats.to_dict()))
        return stats

    def _scan_block(self, number: int, stats: ScanStats) -> None:
        block = self.rpc.block(number, full_transactions=True)
        if not block:
            raise RuntimeError(f"Block {number} was not returned by {self.chain.name}")
        block_timestamp = dt.datetime.fromtimestamp(
            hex_to_int(str(block.get("timestamp") or "0x0")), tz=dt.UTC
        ).isoformat(timespec="seconds")
        transactions = block.get("transactions") or []
        for transaction in transactions:
            if not isinstance(transaction, dict) or transaction.get("to") is not None:
                continue
            tx_hash = str(transaction.get("hash") or "").lower()
            deployer = str(transaction.get("from") or "").lower()
            if not tx_hash or not deployer:
                continue
            receipt = self.rpc.receipt(tx_hash)
            if not receipt or hex_to_int(str(receipt.get("status") or "0x0")) != 1:
                continue
            address = str(receipt.get("contractAddress") or "").lower()
            if not address:
                continue
            code = self.rpc.code(address, hex(number))
            bytecode_size = max(0, (len(code.removeprefix("0x")) // 2))
            metadata = self.enricher.enrich(self.rpc, chain_id=self.chain.chain_id, address=address)
            observed_at = utc_now()
            inserted = self.store.add_deployment(
                chain_id=self.chain.chain_id,
                address=address,
                deployer_address=deployer,
                tx_hash=tx_hash,
                block_number=number,
                observed_at=observed_at,
                contract_name=metadata.contract_name,
                is_proxy=metadata.is_proxy,
            )
            if not inserted:
                continue
            related = self.store.related_deployments(self.chain.chain_id, deployer)
            deployer_watch = self.watchlist.deployer(self.chain.chain_id, deployer)
            score = score_deployment(
                chain=self.chain,
                metadata=metadata,
                bytecode_size=bytecode_size,
                cluster_size=len(related),
                watched_deployer_label=deployer_watch.label if deployer_watch else None,
            )
            event = RadarEvent(
                event_id=stable_event_id(
                    "contract_deployment", self.chain.chain_id, tx_hash, address
                ),
                observed_at=observed_at,
                event_type="contract_deployment",
                title="New contract deployment",
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
                block_number=number,
                evidence={
                    "transaction": f"{self.chain.explorer_url}/tx/{tx_hash}",
                    "contract": f"{self.chain.explorer_url}/address/{address}",
                    "deployer": f"{self.chain.explorer_url}/address/{deployer}",
                },
                metadata={
                    "block_timestamp": block_timestamp,
                    "bytecode_size": bytecode_size,
                    "verified": metadata.verified,
                    "verification_source": metadata.verification_source,
                    "contract_name": metadata.contract_name,
                    "is_proxy": metadata.is_proxy,
                    "implementation": metadata.implementation,
                    "admin": metadata.admin,
                    "beacon": metadata.beacon,
                    "deployer_cluster_size": len(related),
                    "related_contracts": related,
                },
            )
            self._record_and_alert(event, stats)
            stats.deployments += 1

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
                score=score.score,
                severity=severity_for_score(score.score),
                confidence=score.confidence,
                reasons=score.reasons,
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
                },
            )
            self._record_and_alert(event, stats)
            stats.upgrades += 1

    def _record_and_alert(self, event: RadarEvent, stats: ScanStats) -> None:
        if not self.store.add_event(event):
            return
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
