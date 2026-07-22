from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from tests.common import ETHEREUM
from tests.test_investigation import (
    ORIGIN,
    RECIPIENT,
    TX_HASH,
    FakeResolver,
    InvestigationRpc,
)
from white_radar.history import HistoryRecord
from white_radar.investigation import investigate_transaction
from white_radar.reconstruction import ReconstructionLimits, reconstruct_attack_case
from white_radar.reconstruction_bundle import (
    RECONSTRUCTION_BUNDLE_FILES,
    write_reconstruction_bundle,
)

RELATED_HASH = "0x" + "bc" * 32


class ReconstructionRpc(InvestigationRpc):
    def block_number(self) -> int:
        return 110

    def transaction(self, tx_hash: str) -> dict[str, object] | None:
        transaction = super().transaction(tx_hash)
        if transaction is not None and tx_hash == RELATED_HASH:
            transaction["blockNumber"] = "0x65"
        return transaction

    def receipt(self, tx_hash: str) -> dict[str, object] | None:
        receipt = super().receipt(tx_hash)
        if receipt is not None and tx_hash == RELATED_HASH:
            receipt["blockNumber"] = "0x65"
        return receipt


class FixtureHistory:
    @property
    def warnings(self) -> tuple[str, ...]:
        return ()

    def records_for_address(
        self,
        *,
        chain_id: int,
        address: str,
        start_block: int,
        end_block: int,
        anchor_block: int,
        limit: int,
    ) -> tuple[HistoryRecord, ...]:
        del chain_id, start_block, end_block, anchor_block, limit
        if address != ORIGIN:
            return ()
        return (
            HistoryRecord(
                transaction_hash=RELATED_HASH,
                block_number=101,
                transaction_index=2,
                timestamp=1_700_000_000,
                sender=ORIGIN,
                recipient=RECIPIENT,
                record_type="erc20",
                value="1000",
                asset_address="0x" + "55" * 20,
                token_id=None,
                source="fixture:index",
            ),
        )


class ReconstructionTests(unittest.TestCase):
    def test_expands_seed_into_bounded_cross_transaction_graph(self) -> None:
        rpc = ReconstructionRpc()
        seed = investigate_transaction(
            rpc,  # type: ignore[arg-type]
            ETHEREUM,
            TX_HASH,
            resolver=FakeResolver(),  # type: ignore[arg-type]
            replay_prestate=False,
        )
        reconstruction = reconstruct_attack_case(
            rpc,  # type: ignore[arg-type]
            ETHEREUM,
            seed,
            FixtureHistory(),
            resolver=FakeResolver(),  # type: ignore[arg-type]
            limits=ReconstructionLimits(
                backward_blocks=5,
                forward_blocks=10,
                max_hops=1,
                max_transactions=5,
                max_frontier_addresses=8,
                history_records_per_address=20,
            ),
        )
        self.assertEqual(len(reconstruction.transactions), 2)
        self.assertEqual(
            {item.transaction_hash for item in reconstruction.contexts},
            {TX_HASH, RELATED_HASH},
        )
        related = next(
            item for item in reconstruction.contexts if item.transaction_hash == RELATED_HASH
        )
        self.assertEqual(related.phase, "post_seed")
        self.assertEqual(related.hop, 1)
        self.assertTrue(any("erc20:sent_by" in item for item in related.discovery_reasons))
        self.assertEqual(related.function_source, "fixture")
        self.assertEqual(related.decoded_arguments, {"amount": 7})
        self.assertTrue(
            all(edge.evidence_ref.startswith("0x") for edge in reconstruction.edges)
        )
        self.assertEqual(reconstruction.coverage.boundary_status, "bounded_candidate_chain")
        self.assertFalse(reconstruction.coverage.transaction_limit_reached)

    def test_writes_professional_reconstruction_bundle_and_manifest(self) -> None:
        rpc = ReconstructionRpc()
        seed = investigate_transaction(
            rpc,  # type: ignore[arg-type]
            ETHEREUM,
            TX_HASH,
            replay_prestate=False,
        )
        reconstruction = reconstruct_attack_case(
            rpc,  # type: ignore[arg-type]
            ETHEREUM,
            seed,
            FixtureHistory(),
            limits=ReconstructionLimits(max_hops=1, max_transactions=5),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            result = write_reconstruction_bundle(reconstruction, root)
            self.assertEqual({item.name for item in result.files}, set(RECONSTRUCTION_BUNDLE_FILES))
            report = (root / "report.md").read_text(encoding="utf-8")
            self.assertIn("Chronological transaction inventory", report)
            self.assertIn("Asset-flow ledger", report)
            graph = (root / "graph.html").read_text(encoding="utf-8")
            self.assertIn("Search address, transaction, label, selector", graph)
            self.assertIn("marker-end", graph)
            calls_csv = (root / "calls.csv").read_text(encoding="utf-8")
            self.assertIn("calldata_sha256", calls_csv.splitlines()[0])
            self.assertIn("decoded_arguments", calls_csv.splitlines()[0])
            ET.parse(root / "graph.graphml")
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 3)
            self.assertIn("events.csv", {item["path"] for item in manifest["files"]})
            self.assertIn("state_changes.csv", {item["path"] for item in manifest["files"]})
            for item in manifest["files"]:
                path = root / item["path"]
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])


if __name__ == "__main__":
    unittest.main()
