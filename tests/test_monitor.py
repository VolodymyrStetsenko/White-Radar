from __future__ import annotations

import dataclasses
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.common import ETHEREUM, settings_for
from white_radar.config import Watchlist
from white_radar.models import ContractMetadata, ContractWatch, DeployerWatch
from white_radar.monitor import ChainScanner
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier


class FakeRpc:
    def chain_id(self) -> int:
        return 1

    def block_number(self) -> int:
        return 102

    def block(self, number: int, *, full_transactions: bool = True) -> dict[str, Any]:
        return {
            "timestamp": hex(1_750_000_000 + number),
            "transactions": [
                {
                    "hash": "0x" + f"{number:064x}",
                    "from": "0x" + "22" * 20,
                    "to": None,
                }
            ],
        }

    def receipt(self, tx_hash: str) -> dict[str, Any]:
        suffix = tx_hash[-40:]
        return {"status": "0x1", "contractAddress": "0x" + suffix}

    def code(self, address: str, block: str = "latest") -> str:
        return "0x" + "60" * 12_000

    def logs(self, **_kwargs: object) -> list[dict[str, Any]]:
        return []


class FakeEnricher:
    def enrich(self, *_args: object, **_kwargs: object) -> ContractMetadata:
        return ContractMetadata(
            verified=True,
            verification_source="Sourcify",
            contract_name="Pool",
            is_proxy=True,
            implementation="0x" + "44" * 20,
        )


class ChangedEnricher:
    def enrich(self, *_args: object, **_kwargs: object) -> ContractMetadata:
        return ContractMetadata(
            verified=True,
            verification_source="Sourcify",
            contract_name="Pool",
            is_proxy=True,
            implementation="0x" + "55" * 20,
        )


class MonitoringTests(unittest.TestCase):
    def test_groups_related_deployments_and_persists_events(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"RPC_ETHEREUM_HTTP": "https://example.invalid/v2/test"}),
        ):
            root = Path(directory)
            settings = settings_for(root)
            store = RadarStore(settings.app.database_path)
            store.initialize()
            watchlist = Watchlist(
                (),
                (
                    DeployerWatch(
                        chain_id=1,
                        address="0x" + "22" * 20,
                        label="Authorized release deployer",
                    ),
                ),
            )
            notifier = TelegramNotifier(
                settings.telegram,
                settings.app.dry_run,
                settings.app.request_timeout_seconds,
                settings.app.request_retries,
            )
            scanner = ChainScanner(
                settings=settings,
                chain=ETHEREUM,
                watchlist=watchlist,
                store=store,
                notifier=notifier,
            )
            scanner.rpc = FakeRpc()  # type: ignore[assignment]
            scanner.enricher = FakeEnricher()  # type: ignore[assignment]
            stats = scanner.scan()

            self.assertEqual(stats.blocks, 2)
            self.assertEqual(stats.deployments, 2)
            self.assertEqual(store.counts()["events"], 2)
            latest = store.recent_events(1)[0]
            self.assertEqual(latest.metadata["deployer_cluster_size"], 2)
            self.assertGreaterEqual(latest.score, 90)
            self.assertEqual(store.intelligence_counts()["profiles"], 2)
            self.assertGreaterEqual(store.intelligence_counts()["identity_edges"], 3)

            scanner.enricher = ChangedEnricher()  # type: ignore[assignment]
            refresh = scanner.refresh_profiles(limit=10, min_age_minutes=0)
            self.assertEqual(refresh.profiles_refreshed, 2)
            self.assertEqual(refresh.profile_changes, 2)
            self.assertEqual(
                sum(
                    event.event_type == "contract_profile_changed"
                    for event in store.recent_events()
                ),
                2,
            )

    def test_traces_internal_creations_only_for_authorized_watchlist_target(self) -> None:
        factory = "0x" + "66" * 20
        created = "0x" + "77" * 20
        creator = "0x" + "88" * 20

        class TraceRpc(FakeRpc):
            def block(self, number: int, *, full_transactions: bool = True) -> dict[str, Any]:
                return {
                    "timestamp": hex(1_750_000_000 + number),
                    "transactions": [
                        {
                            "hash": "0x" + f"{number:064x}",
                            "from": "0x" + "22" * 20,
                            "to": factory,
                        }
                    ],
                }

            def trace_transaction(self, _tx_hash: str) -> dict[str, Any]:
                return {
                    "type": "CALL",
                    "from": "0x" + "22" * 20,
                    "to": factory,
                    "calls": [
                        {"type": "CREATE2", "from": creator, "to": created},
                    ],
                }

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"RPC_ETHEREUM_HTTP": "https://example.invalid/v2/test"}),
        ):
            root = Path(directory)
            settings = settings_for(root)
            store = RadarStore(settings.app.database_path)
            store.initialize()
            watchlist = Watchlist(
                (
                    ContractWatch(
                        chain_id=1,
                        address=factory,
                        protocol="Authorized Factory",
                        role="factory",
                    ),
                ),
                (),
            )
            notifier = TelegramNotifier(settings.telegram, True, 1, 1)
            chain = dataclasses.replace(ETHEREUM, trace_internal_creations=True)
            scanner = ChainScanner(
                settings=settings,
                chain=chain,
                watchlist=watchlist,
                store=store,
                notifier=notifier,
            )
            scanner.rpc = TraceRpc()  # type: ignore[assignment]
            scanner.enricher = FakeEnricher()  # type: ignore[assignment]
            stats = scanner.scan()
            self.assertEqual(stats.deployments, 1)
            events = store.recent_events()
            self.assertTrue(
                all(event.event_type == "internal_contract_deployment" for event in events)
            )
            self.assertTrue(all(event.metadata["creation_type"] == "CREATE2" for event in events))
            self.assertTrue(all(event.metadata["trace_depth"] == 1 for event in events))


if __name__ == "__main__":
    unittest.main()
