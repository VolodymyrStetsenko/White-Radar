from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.common import sample_event
from white_radar.storage import RadarStore


class StorageTests(unittest.TestCase):
    def test_events_and_deployments_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RadarStore(Path(directory) / "radar.sqlite3")
            store.initialize()
            event = sample_event()
            self.assertTrue(store.add_event(event))
            self.assertFalse(store.add_event(event))
            self.assertTrue(
                store.add_deployment(
                    chain_id=1,
                    address=event.subject_address or "",
                    deployer_address=event.deployer_address or "",
                    tx_hash=event.tx_hash or "",
                    block_number=event.block_number or 0,
                    observed_at=event.observed_at,
                    contract_name="Pool",
                    is_proxy=True,
                )
            )
            self.assertFalse(
                store.add_deployment(
                    chain_id=1,
                    address=event.subject_address or "",
                    deployer_address=event.deployer_address or "",
                    tx_hash=event.tx_hash or "",
                    block_number=event.block_number or 0,
                    observed_at=event.observed_at,
                    contract_name="Pool",
                    is_proxy=True,
                )
            )
            self.assertEqual(store.counts(), {"events": 1, "deployments": 1, "alerts": 0})

    def test_cursor_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RadarStore(root / "radar.sqlite3")
            store.initialize()
            store.set_cursor(1, 123)
            self.assertEqual(store.get_cursor(1), 123)
            store.add_event(sample_event())
            destination = root / "events.jsonl"
            self.assertEqual(store.export_jsonl(destination), 1)
            self.assertIn("case-123", destination.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
