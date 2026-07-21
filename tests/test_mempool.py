from __future__ import annotations

import dataclasses
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.common import ETHEREUM, settings_for
from white_radar.config import Watchlist
from white_radar.mempool import (
    _handle_message,
    pending_subscription_request,
    watch_pending_transactions,
)
from white_radar.models import ContractWatch
from white_radar.policy import PolicyBook, ProtocolPolicy
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier

WATCHED_ADDRESS = "0x" + "11" * 20


class FakePendingRpc:
    def __init__(self, transaction: dict[str, object] | None) -> None:
        self._transaction = transaction

    def transaction(self, _tx_hash: str) -> dict[str, object] | None:
        return self._transaction


class PendingTests(unittest.IsolatedAsyncioTestCase):
    def test_builds_filtered_alchemy_or_standard_subscription(self) -> None:
        addresses = frozenset({WATCHED_ADDRESS})
        mode, request = pending_subscription_request(
            ETHEREUM,
            "wss://eth-mainnet.g.alchemy.com/v2/example",
            addresses,
        )
        self.assertEqual(mode, "alchemy_pendingTransactions")
        self.assertEqual(request["params"][1]["toAddress"], [WATCHED_ADDRESS])  # type: ignore[index]
        mode, request = pending_subscription_request(
            ETHEREUM, "wss://rpc.example.invalid", addresses
        )
        self.assertEqual(mode, "newPendingTransactions")
        self.assertEqual(request["params"], ["newPendingTransactions"])

        unsupported = dataclasses.replace(ETHEREUM, chain_id=8453, pending_subscription="alchemy")
        with self.assertRaises(RuntimeError):
            pending_subscription_request(unsupported, "wss://base.g.alchemy.com", addresses)
        with self.assertRaises(RuntimeError):
            pending_subscription_request(
                ETHEREUM,
                "wss://eth-mainnet.g.alchemy.com",
                frozenset("0x" + f"{index:040x}" for index in range(1001)),
            )

    async def test_records_only_watchlisted_pending_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = settings_for(root)
            store = RadarStore(settings.app.database_path)
            store.initialize()
            watchlist = Watchlist(
                (
                    ContractWatch(
                        chain_id=1,
                        address=WATCHED_ADDRESS,
                        protocol="Example",
                        role="proxy",
                        bounty_url="https://example.invalid/security",
                        critical_selectors=("0x12345678",),
                    ),
                ),
                (),
            )
            notifier = TelegramNotifier(settings.telegram, True, 1, 1)
            transaction = {
                "from": "0x" + "22" * 20,
                "to": WATCHED_ADDRESS,
                "input": "0x12345678" + "00" * 32,
                "value": "0x1",
                "gas": "0x5208",
                "maxFeePerGas": "0x10",
            }
            message = json.dumps({"params": {"result": "0x" + "aa" * 32}})
            await _handle_message(
                message,
                rpc=FakePendingRpc(transaction),  # type: ignore[arg-type]
                chain=ETHEREUM,
                watchlist=watchlist,
                store=store,
                notifier=notifier,
            )
            events = store.recent_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].metadata["selector"], "0x12345678")
            self.assertNotIn("calldata", events[0].metadata)
            self.assertIn("Do not replay", events[0].recommended_action)
            self.assertEqual(store.intelligence_counts()["identity_edges"], 2)

    async def test_accepts_filtered_full_transaction_without_rpc_lookup(self) -> None:
        class NoLookupRpc:
            def transaction(self, _tx_hash: str) -> dict[str, object] | None:
                raise AssertionError("filtered full transactions must not trigger an RPC lookup")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = settings_for(root)
            store = RadarStore(settings.app.database_path)
            store.initialize()
            watchlist = Watchlist(
                (
                    ContractWatch(
                        chain_id=1,
                        address=WATCHED_ADDRESS,
                        protocol="Example",
                        critical_selectors=(),
                    ),
                ),
                (),
            )
            notifier = TelegramNotifier(settings.telegram, True, 1, 1)
            transaction = {
                "hash": "0x" + "ab" * 32,
                "from": "0x" + "22" * 20,
                "to": WATCHED_ADDRESS,
                "input": "0x12345678",
                "value": "0x0",
            }
            await _handle_message(
                json.dumps({"params": {"result": transaction}}),
                rpc=NoLookupRpc(),  # type: ignore[arg-type]
                chain=ETHEREUM,
                watchlist=watchlist,
                store=store,
                notifier=notifier,
                subscription_type="alchemy_pendingTransactions",
            )
            event = store.recent_events(1)[0]
            self.assertEqual(event.tx_hash, transaction["hash"])
            self.assertEqual(event.metadata["subscription_type"], "alchemy_pendingTransactions")

    async def test_applies_protocol_policy_and_opens_incident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = settings_for(root)
            store = RadarStore(settings.app.database_path)
            store.initialize()
            watchlist = Watchlist(
                (
                    ContractWatch(
                        chain_id=1,
                        address=WATCHED_ADDRESS,
                        protocol="Example",
                    ),
                ),
                (),
            )
            policy_book = PolicyBook(
                (
                    ProtocolPolicy(
                        chain_id=1,
                        address=WATCHED_ADDRESS,
                        protocol="Example",
                        authorized_senders=frozenset({"0x" + "44" * 20}),
                        allowed_selectors=frozenset({"0x87654321"}),
                        critical_selectors=frozenset(),
                        max_native_value_wei=0,
                        incident_sla_minutes=10,
                    ),
                ),
                "a" * 64,
            )
            transaction = {
                "hash": "0x" + "cd" * 32,
                "from": "0x" + "22" * 20,
                "to": WATCHED_ADDRESS,
                "input": "0x12345678",
                "value": "0x1",
            }
            await _handle_message(
                json.dumps({"params": {"result": transaction}}),
                rpc=FakePendingRpc(None),  # type: ignore[arg-type]
                chain=ETHEREUM,
                watchlist=watchlist,
                store=store,
                notifier=TelegramNotifier(settings.telegram, True, 1, 1),
                policy_book=policy_book,
            )
            event = store.recent_events(1)[0]
            self.assertEqual(event.score, 100)
            self.assertFalse(event.metadata["policy_baseline_match"])
            self.assertEqual(len(event.metadata["policy_findings"]), 3)
            self.assertIsNotNone(store.incident_for_event(event.event_id))

    async def test_ignores_invalid_unresolved_and_unwatched_messages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = settings_for(root)
            store = RadarStore(settings.app.database_path)
            store.initialize()
            notifier = TelegramNotifier(settings.telegram, True, 1, 1)
            watchlist = Watchlist((), ())
            for raw, transaction in (
                ("not-json", None),
                (json.dumps({"params": {}}), None),
                (json.dumps({"params": {"result": "0x1"}}), None),
                (
                    json.dumps({"params": {"result": "0x2"}}),
                    {"to": "0x" + "33" * 20},
                ),
            ):
                await _handle_message(
                    raw,
                    rpc=FakePendingRpc(transaction),  # type: ignore[arg-type]
                    chain=ETHEREUM,
                    watchlist=watchlist,
                    store=store,
                    notifier=notifier,
                )
            self.assertEqual(store.counts()["events"], 0)

    async def test_pending_stream_requires_ws_and_authorized_watchlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = settings_for(root)
            store = RadarStore(settings.app.database_path)
            store.initialize()
            notifier = TelegramNotifier(settings.telegram, True, 1, 1)
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
                await watch_pending_transactions(
                    settings=settings,
                    chain=ETHEREUM,
                    watchlist=Watchlist((), ()),
                    store=store,
                    notifier=notifier,
                )
            with (
                patch.dict(
                    os.environ,
                    {
                        "RPC_ETHEREUM_HTTP": "https://example.invalid",
                        "RPC_ETHEREUM_WS": "wss://example.invalid",
                    },
                    clear=True,
                ),
                self.assertRaises(RuntimeError),
            ):
                await watch_pending_transactions(
                    settings=settings,
                    chain=ETHEREUM,
                    watchlist=Watchlist((), ()),
                    store=store,
                    notifier=notifier,
                )


if __name__ == "__main__":
    unittest.main()
