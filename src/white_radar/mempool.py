from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import urllib.parse

from white_radar.config import Settings, Watchlist
from white_radar.logging import log_context
from white_radar.models import (
    ChainConfig,
    RadarEvent,
    severity_for_score,
    stable_event_id,
    utc_now,
)
from white_radar.policy import PolicyBook, assess_pending, load_policy_book
from white_radar.rpc import JsonRpcClient, hex_to_int
from white_radar.scoring import score_pending
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier

LOGGER = logging.getLogger(__name__)
ALCHEMY_FILTERED_PENDING_CHAINS = frozenset({1, 137, 11155111})


def pending_subscription_request(
    chain: ChainConfig, ws_url: str, watched_addresses: frozenset[str]
) -> tuple[str, dict[str, object]]:
    host = (urllib.parse.urlsplit(ws_url).hostname or "").lower()
    use_alchemy = chain.pending_subscription == "alchemy" or (
        chain.pending_subscription == "auto"
        and host.endswith("alchemy.com")
        and chain.chain_id in ALCHEMY_FILTERED_PENDING_CHAINS
    )
    if use_alchemy:
        if chain.chain_id not in ALCHEMY_FILTERED_PENDING_CHAINS:
            raise RuntimeError(
                "Alchemy filtered pending subscriptions are not supported for this chain"
            )
        if len(watched_addresses) > 1000:
            raise RuntimeError("Alchemy pending address filter supports at most 1000 addresses")
        return (
            "alchemy_pendingTransactions",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_subscribe",
                "params": [
                    "alchemy_pendingTransactions",
                    {"toAddress": sorted(watched_addresses), "hashesOnly": False},
                ],
            },
        )
    return (
        "newPendingTransactions",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_subscribe",
            "params": ["newPendingTransactions"],
        },
    )


async def watch_pending_transactions(
    *,
    settings: Settings,
    chain: ChainConfig,
    watchlist: Watchlist,
    store: RadarStore,
    notifier: TelegramNotifier,
) -> None:
    """Observe pending transactions to explicitly watched contracts without broadcasting."""
    ws_url = os.getenv(chain.rpc_ws_env, "").strip()
    http_url = os.getenv(chain.rpc_http_env, "").strip()
    if not ws_url.startswith(("ws://", "wss://")):
        raise RuntimeError(f"Missing or invalid {chain.rpc_ws_env}")
    if not http_url:
        raise RuntimeError(f"Missing {chain.rpc_http_env}")
    watched_addresses = watchlist.addresses_for_chain(chain.chain_id)
    if not watched_addresses:
        raise RuntimeError(
            "Pending monitoring requires at least one explicitly authorized contract "
            "in watchlist.toml"
        )
    subscription_type, subscription_request = pending_subscription_request(
        chain, ws_url, watched_addresses
    )
    policy_book = load_policy_book(settings.app.policy_path)

    from websockets.asyncio.client import connect

    rpc = JsonRpcClient(
        http_url,
        timeout=settings.app.request_timeout_seconds,
        retries=settings.app.request_retries,
    )
    if rpc.chain_id() != chain.chain_id:
        raise RuntimeError("HTTP RPC chain does not match configured pending stream chain")

    backoff = 1
    while True:
        try:
            async with connect(
                ws_url,
                ping_interval=20,
                ping_timeout=20,
                max_size=2_000_000,
                open_timeout=settings.app.request_timeout_seconds,
            ) as websocket:
                await websocket.send(json.dumps(subscription_request))
                acknowledgement = json.loads(await websocket.recv())
                if acknowledgement.get("error") or not acknowledgement.get("result"):
                    raise RuntimeError(f"Pending subscription rejected: {acknowledgement}")
                LOGGER.info(
                    "pending subscription active",
                    extra=log_context(
                        chain=chain.name,
                        watched_contracts=len(watched_addresses),
                        subscription_type=subscription_type,
                    ),
                )
                store.record_heartbeat(
                    service_name="pending_observer",
                    chain_id=chain.chain_id,
                    details={
                        "chain": chain.name,
                        "subscription_type": subscription_type,
                        "watched_contracts": len(watched_addresses),
                    },
                )
                await _flush_alerts(chain=chain, store=store, notifier=notifier)
                backoff = 1
                heartbeat = asyncio.create_task(
                    _heartbeat_loop(
                        store=store,
                        chain=chain,
                        subscription_type=subscription_type,
                        watched_contracts=len(watched_addresses),
                    )
                )
                try:
                    async for raw_message in websocket:
                        await _handle_message(
                            raw_message,
                            rpc=rpc,
                            chain=chain,
                            watchlist=watchlist,
                            store=store,
                            notifier=notifier,
                            subscription_type=subscription_type,
                            policy_book=policy_book,
                            incident_minimum_score=settings.app.incident_minimum_score,
                            incident_sla_minutes=settings.app.incident_sla_minutes,
                        )
                finally:
                    heartbeat.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await heartbeat
        except asyncio.CancelledError:
            store.record_heartbeat(
                service_name="pending_observer",
                chain_id=chain.chain_id,
                status="stopped",
                details={"chain": chain.name},
            )
            raise
        except Exception as exc:
            store.record_heartbeat(
                service_name="pending_observer",
                chain_id=chain.chain_id,
                status="degraded",
                details={"chain": chain.name, "retry_seconds": backoff},
                last_error=type(exc).__name__,
            )
            LOGGER.error(
                "pending stream disconnected", extra=log_context(chain=chain.name, retry=backoff)
            )
            await asyncio.sleep(backoff)
            backoff = min(30, backoff * 2)


async def _heartbeat_loop(
    *,
    store: RadarStore,
    chain: ChainConfig,
    subscription_type: str,
    watched_contracts: int,
) -> None:
    while True:
        store.record_heartbeat(
            service_name="pending_observer",
            chain_id=chain.chain_id,
            details={
                "chain": chain.name,
                "subscription_type": subscription_type,
                "watched_contracts": watched_contracts,
            },
        )
        await asyncio.sleep(30)


async def _handle_message(
    raw_message: str | bytes,
    *,
    rpc: JsonRpcClient,
    chain: ChainConfig,
    watchlist: Watchlist,
    store: RadarStore,
    notifier: TelegramNotifier,
    subscription_type: str = "newPendingTransactions",
    policy_book: PolicyBook | None = None,
    incident_minimum_score: int = 70,
    incident_sla_minutes: int = 30,
) -> None:
    try:
        message = json.loads(raw_message)
    except (json.JSONDecodeError, TypeError):
        return
    result = message.get("params", {}).get("result")
    transaction: dict[str, object] | None
    if isinstance(result, dict):
        transaction = result
        tx_hash = str(transaction.get("hash") or "")
    elif isinstance(result, str):
        tx_hash = result
        transaction = await asyncio.to_thread(rpc.transaction, tx_hash)
    else:
        return
    if not tx_hash or not transaction:
        return
    destination = str(transaction.get("to") or "").lower()
    watched = watchlist.contract(chain.chain_id, destination)
    if not watched:
        return
    calldata = str(transaction.get("input") or "0x")
    selector = calldata[:10].lower() if len(calldata) >= 10 else "0x"
    native_value = hex_to_int(str(transaction.get("value") or "0x0"))
    sender = str(transaction.get("from") or "").lower() or None
    policy = (policy_book or PolicyBook.empty()).contract(chain.chain_id, destination)
    assessment = (
        assess_pending(
            policy,
            sender=sender,
            selector=selector,
            native_value_wei=native_value,
        )
        if policy
        else None
    )
    policy_critical = bool(policy and selector in policy.critical_selectors)
    score = score_pending(
        protocol=watched.protocol,
        critical_selector=selector in watched.critical_selectors or policy_critical,
        native_value_wei=native_value,
    )
    final_score = min(100, score.score + (assessment.score_delta if assessment else 0))
    reasons = score.reasons + (
        tuple(finding.reason for finding in assessment.findings) if assessment else ()
    )
    event = RadarEvent(
        event_id=stable_event_id("pending_watch", chain.chain_id, tx_hash),
        observed_at=utc_now(),
        event_type="pending_watch",
        title="Pending transaction to watched contract",
        summary=f"Pending transaction targets {watched.protocol} ({watched.role}).",
        chain=chain.name,
        chain_id=chain.chain_id,
        score=final_score,
        severity=severity_for_score(final_score),
        confidence=min(
            0.98,
            score.confidence + (0.05 if assessment and assessment.findings else 0),
        ),
        reasons=reasons,
        recommended_action=score.recommended_action,
        subject_address=destination,
        deployer_address=sender,
        tx_hash=tx_hash.lower(),
        evidence={"transaction": f"{chain.explorer_url}/tx/{tx_hash}"},
        metadata={
            "protocol": watched.protocol,
            "role": watched.role,
            "selector": selector,
            "critical_selector": selector in watched.critical_selectors or policy_critical,
            "native_value_wei": native_value,
            "calldata_size_bytes": max(0, (len(calldata.removeprefix("0x")) // 2)),
            "gas": hex_to_int(str(transaction.get("gas") or "0x0")),
            "max_fee_per_gas": hex_to_int(
                str(transaction.get("maxFeePerGas") or transaction.get("gasPrice") or "0x0")
            ),
            "bounty_url": watched.bounty_url,
            "contact_uri": watched.contact_uri,
            "verification_source": "provider mempool observation",
            "subscription_type": subscription_type,
            "policy_configured": policy is not None,
            "policy_baseline_match": assessment.baseline_match if assessment else None,
            "policy_findings": (
                [finding.to_dict() for finding in assessment.findings] if assessment else []
            ),
            "policy_sha256": policy_book.source_sha256 if policy and policy_book else None,
        },
    )
    if not store.add_event(event):
        return
    store.open_incident(
        event,
        minimum_score=incident_minimum_score,
        sla_minutes=(
            policy.incident_sla_minutes
            if policy and policy.incident_sla_minutes is not None
            else incident_sla_minutes
        ),
        protocol=watched.protocol,
    )
    protocol_node = store.upsert_identity_node(
        chain_id=chain.chain_id,
        kind="protocol",
        value=watched.protocol,
        label=watched.protocol,
    )
    contract_node = store.upsert_identity_node(
        chain_id=chain.chain_id,
        kind="contract",
        value=destination,
        label=f"{watched.protocol} {watched.role}",
    )
    store.upsert_identity_edge(
        chain_id=chain.chain_id,
        source_node_id=protocol_node,
        relation="CONTAINS",
        target_node_id=contract_node,
        evidence={"watchlist": True, "bounty_url": watched.bounty_url},
        observed_at=event.observed_at,
    )
    sender = event.deployer_address
    if sender:
        sender_node = store.upsert_identity_node(
            chain_id=chain.chain_id,
            kind="account",
            value=sender,
        )
        store.upsert_identity_edge(
            chain_id=chain.chain_id,
            source_node_id=sender_node,
            relation="OBSERVED_PENDING_CALL_TO",
            target_node_id=contract_node,
            evidence={"transaction": tx_hash, "selector": selector},
            observed_at=event.observed_at,
        )
    LOGGER.warning("pending watch event", extra=log_context(**event.to_dict()))
    if notifier.should_send(event, chain):
        try:
            if await asyncio.to_thread(notifier.send, event, chain):
                store.mark_alerted(event.event_id)
        except Exception:
            LOGGER.exception(
                "pending alert delivery failed",
                extra=log_context(chain=chain.name, event_id=event.event_id),
            )


async def _flush_alerts(
    *, chain: ChainConfig, store: RadarStore, notifier: TelegramNotifier
) -> None:
    for event in store.pending_alerts(chain.chain_id):
        if not notifier.should_send(event, chain):
            continue
        try:
            if await asyncio.to_thread(notifier.send, event, chain):
                store.mark_alerted(event.event_id)
        except Exception:
            LOGGER.exception(
                "pending outbox delivery failed",
                extra=log_context(chain=chain.name, event_id=event.event_id),
            )
