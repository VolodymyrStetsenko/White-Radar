from __future__ import annotations

import asyncio
import json
import logging
import os

from white_radar.config import Settings, Watchlist
from white_radar.logging import log_context
from white_radar.models import (
    ChainConfig,
    RadarEvent,
    severity_for_score,
    stable_event_id,
    utc_now,
)
from white_radar.rpc import JsonRpcClient, hex_to_int
from white_radar.scoring import score_pending
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier

LOGGER = logging.getLogger(__name__)


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
                await websocket.send(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "eth_subscribe",
                            "params": ["newPendingTransactions"],
                        }
                    )
                )
                acknowledgement = json.loads(await websocket.recv())
                if acknowledgement.get("error") or not acknowledgement.get("result"):
                    raise RuntimeError(f"Pending subscription rejected: {acknowledgement}")
                LOGGER.info(
                    "pending subscription active",
                    extra=log_context(chain=chain.name, watched_contracts=len(watched_addresses)),
                )
                await _flush_alerts(chain=chain, store=store, notifier=notifier)
                backoff = 1
                async for raw_message in websocket:
                    await _handle_message(
                        raw_message,
                        rpc=rpc,
                        chain=chain,
                        watchlist=watchlist,
                        store=store,
                        notifier=notifier,
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception(
                "pending stream disconnected", extra=log_context(chain=chain.name, retry=backoff)
            )
            await asyncio.sleep(backoff)
            backoff = min(30, backoff * 2)


async def _handle_message(
    raw_message: str | bytes,
    *,
    rpc: JsonRpcClient,
    chain: ChainConfig,
    watchlist: Watchlist,
    store: RadarStore,
    notifier: TelegramNotifier,
) -> None:
    try:
        message = json.loads(raw_message)
    except (json.JSONDecodeError, TypeError):
        return
    tx_hash = message.get("params", {}).get("result")
    if not isinstance(tx_hash, str):
        return
    transaction = await asyncio.to_thread(rpc.transaction, tx_hash)
    if not transaction:
        return
    destination = str(transaction.get("to") or "").lower()
    watched = watchlist.contract(chain.chain_id, destination)
    if not watched:
        return
    calldata = str(transaction.get("input") or "0x")
    selector = calldata[:10].lower() if len(calldata) >= 10 else "0x"
    native_value = hex_to_int(str(transaction.get("value") or "0x0"))
    score = score_pending(
        protocol=watched.protocol,
        critical_selector=selector in watched.critical_selectors,
        native_value_wei=native_value,
    )
    event = RadarEvent(
        event_id=stable_event_id("pending_watch", chain.chain_id, tx_hash),
        observed_at=utc_now(),
        event_type="pending_watch",
        title="Pending transaction to watched contract",
        summary=f"Pending transaction targets {watched.protocol} ({watched.role}).",
        chain=chain.name,
        chain_id=chain.chain_id,
        score=score.score,
        severity=severity_for_score(score.score),
        confidence=score.confidence,
        reasons=score.reasons,
        recommended_action=score.recommended_action,
        subject_address=destination,
        deployer_address=str(transaction.get("from") or "").lower() or None,
        tx_hash=tx_hash.lower(),
        evidence={"transaction": f"{chain.explorer_url}/tx/{tx_hash}"},
        metadata={
            "protocol": watched.protocol,
            "role": watched.role,
            "selector": selector,
            "critical_selector": selector in watched.critical_selectors,
            "native_value_wei": native_value,
            "calldata_size_bytes": max(0, (len(calldata.removeprefix("0x")) // 2)),
            "gas": hex_to_int(str(transaction.get("gas") or "0x0")),
            "max_fee_per_gas": hex_to_int(
                str(transaction.get("maxFeePerGas") or transaction.get("gasPrice") or "0x0")
            ),
            "bounty_url": watched.bounty_url,
            "contact_uri": watched.contact_uri,
            "verification_source": "provider mempool observation",
        },
    )
    if not store.add_event(event):
        return
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
