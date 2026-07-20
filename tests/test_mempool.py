from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.common import ETHEREUM, settings_for
from white_radar.config import Watchlist
from white_radar.mempool import _handle_message, watch_pending_transactions
from white_radar.models import ContractWatch
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier

WATCHED_ADDRESS = "0x" + "11" * 20


class FakePendingRpc:
    def __init__(self, transaction: dict[str, object] | None) -> None:
        self._transaction = transaction

    def transaction(self, _tx_hash: str) -> dict[str, object] | None:
        return self._transaction


class PendingTests(unittest.IsolatedAsyncioTestCase):
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
