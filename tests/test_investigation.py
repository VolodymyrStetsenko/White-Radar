from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tests.common import ETHEREUM
from white_radar.abi import DecodedCall, DecodedEvent
from white_radar.case_bundle import BUNDLE_FILES, write_case_bundle
from white_radar.enrichment import EIP1967_SLOTS
from white_radar.investigation import (
    TRANSFER_BATCH_TOPIC,
    TRANSFER_SINGLE_TOPIC,
    TRANSFER_TOPIC,
    investigate_transaction,
)
from white_radar.rpc import RpcError

TX_HASH = "0x" + "aa" * 32
ORIGIN = "0x" + "11" * 20
TARGET = "0x" + "22" * 20
IMPLEMENTATION = "0x" + "33" * 20
RECIPIENT = "0x" + "44" * 20
TOKEN = "0x" + "55" * 20


def topic_address(address: str) -> str:
    return "0x" + "00" * 12 + address[2:]


class FakeResolver:
    def resolve(
        self,
        chain_id: int,
        address: str,
        calldata: str,
        *,
        fallback_signature: str | None = None,
    ) -> DecodedCall:
        signature = "execute(uint256)" if address == TARGET else None
        return DecodedCall(calldata[:10], signature, {"amount": 7}, "fixture", "f" * 64)

    def resolve_event(
        self,
        chain_id: int,
        address: str,
        topics: list[str],
        data: str,
    ) -> DecodedEvent | None:
        del chain_id, data
        if address != TOKEN or not topics or topics[0] != TRANSFER_TOPIC:
            return None
        return DecodedEvent(
            topic0=topics[0],
            signature="Transfer(address,address,uint256)",
            name="Transfer",
            arguments={"value": 1_000},
            source="fixture ABI",
            abi_sha256="e" * 64,
        )


class InvestigationRpc:
    def transaction(self, tx_hash: str) -> dict[str, Any] | None:
        return {
            "hash": tx_hash,
            "blockHash": "0x" + "bb" * 32,
            "blockNumber": "0x64",
            "from": ORIGIN,
            "to": TARGET,
            "input": "0x12345678" + f"{7:064x}",
            "value": "0xa",
            "gas": "0x30d40",
            "gasPrice": "0x2",
            "nonce": "0x1",
        }

    def receipt(self, tx_hash: str) -> dict[str, Any] | None:
        return {
            "transactionHash": tx_hash,
            "blockHash": "0x" + "bb" * 32,
            "blockNumber": "0x64",
            "from": ORIGIN,
            "to": TARGET,
            "status": "0x1",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x2",
            "logs": [
                {
                    "address": TOKEN,
                    "topics": [TRANSFER_TOPIC, topic_address(ORIGIN), topic_address(RECIPIENT)],
                    "data": "0x" + f"{1_000:064x}",
                    "logIndex": "0x3",
                }
            ],
        }

    def block(self, number: int, *, full_transactions: bool = False) -> dict[str, Any]:
        return {
            "number": hex(number),
            "hash": "0x" + "bb" * 32,
            "timestamp": "0x68500000",
        }

    def trace_transaction(self, tx_hash: str) -> dict[str, Any]:
        return {
            "type": "CALL",
            "from": ORIGIN,
            "to": TARGET,
            "input": "0x12345678" + f"{7:064x}",
            "value": "0xa",
            "gas": "0x30d40",
            "gasUsed": "0x10000",
            "calls": [
                {
                    "type": "DELEGATECALL",
                    "from": TARGET,
                    "to": IMPLEMENTATION,
                    "input": "0x12345678" + f"{7:064x}",
                    # Inherited call value is context, not an implementation transfer.
                    "value": "0x9",
                    "gas": "0x10000",
                    "gasUsed": "0x5000",
                    "calls": [
                        {
                            "type": "CALL",
                            "from": IMPLEMENTATION,
                            "to": RECIPIENT,
                            "input": "0x",
                            "value": "0x5",
                            "gas": "0x1000",
                            "gasUsed": "0x500",
                        }
                    ],
                }
            ],
        }

    def trace_transaction_state_diff(self, tx_hash: str) -> dict[str, Any]:
        del tx_hash
        return {
            "pre": {
                TARGET: {
                    "balance": "0xa",
                    "nonce": "0x1",
                    "code": "0x6000",
                    "storage": {"0x01": "0x02"},
                }
            },
            "post": {
                TARGET: {
                    "balance": "0x5",
                    "nonce": "0x2",
                    "code": "0x6000",
                    "storage": {"0x01": "0x03"},
                }
            },
        }

    def storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        assert slot in EIP1967_SLOTS.values()
        return "0x" + "00" * 32

    def code(self, address: str, block: str = "latest") -> str:
        return "0x6000" if address in {TARGET, IMPLEMENTATION, TOKEN} else "0x"

    def eth_call(self, transaction: dict[str, object], block: str = "latest") -> str:
        return "0x"


class InvestigationTests(unittest.TestCase):
    def test_reconstructs_calls_transfers_entities_and_historical_replay(self) -> None:
        case = investigate_transaction(
            InvestigationRpc(),  # type: ignore[arg-type]
            ETHEREUM,
            TX_HASH,
            resolver=FakeResolver(),  # type: ignore[arg-type]
        )
        self.assertEqual(case.transaction_status, "succeeded")
        self.assertEqual(len(case.calls), 3)
        self.assertEqual(
            [item.asset_type for item in case.transfers],
            ["native", "native", "erc20"],
        )
        self.assertEqual(
            [item.amount for item in case.transfers if item.asset_type == "native"],
            ["10", "5"],
        )
        delegate_edge = next(item for item in case.relationships if item.relation == "DELEGATECALL")
        self.assertIsNone(delegate_edge.amount)
        self.assertEqual(case.transfers[-1].amount, "1000")
        self.assertEqual(case.root_call.signature, "execute(uint256)")  # type: ignore[union-attr]
        self.assertEqual(case.calls[0].decoded_arguments, {"amount": 7})
        self.assertEqual(case.events[0].event_signature, "Transfer(address,address,uint256)")
        self.assertEqual(case.events[0].decode_confidence, "verified")
        self.assertEqual(case.calls[0].calldata_bytes, 36)
        self.assertEqual(
            case.calls[0].calldata_sha256,
            hashlib.sha256(bytes.fromhex(case.calls[0].calldata[2:])).hexdigest(),
        )
        target_entity = next(item for item in case.entities if item.address == TARGET)
        self.assertEqual(target_entity.code_bytes, 2)
        self.assertEqual(
            target_entity.runtime_code_sha256,
            hashlib.sha256(bytes.fromhex("6000")).hexdigest(),
        )
        self.assertTrue(case.trace_available)
        self.assertEqual(case.historical_replay.block_number, 99)  # type: ignore[union-attr]
        self.assertIn("delegated_execution", {item.code for item in case.findings})
        self.assertIn("verified_event_evidence", {item.code for item in case.findings})
        self.assertIn("state_changes_observed", {item.code for item in case.findings})
        self.assertEqual(case.state_diff.storage_change_count, 1)  # type: ignore[union-attr]
        self.assertIn(TOKEN, {item.address for item in case.entities})

    def test_trace_unavailability_preserves_receipt_analysis(self) -> None:
        class NoTraceRpc(InvestigationRpc):
            def trace_transaction(self, tx_hash: str) -> dict[str, Any]:
                raise RpcError("method unavailable")

        case = investigate_transaction(
            NoTraceRpc(),  # type: ignore[arg-type]
            ETHEREUM,
            TX_HASH,
            include_trace=True,
            replay_prestate=False,
        )
        self.assertFalse(case.trace_available)
        self.assertEqual(len(case.calls), 0)
        self.assertEqual([item.asset_type for item in case.transfers], ["native", "erc20"])
        self.assertEqual(case.transfers[0].evidence_ref, "transaction")
        self.assertEqual(case.transfers[0].source, "transaction")
        self.assertTrue(any("Call tracing is unavailable" in item for item in case.warnings))

    def test_decodes_erc721_and_erc1155_transfer_logs(self) -> None:
        def word(value: int) -> str:
            return f"{value:064x}"

        class MultiTokenRpc(InvestigationRpc):
            def receipt(self, tx_hash: str) -> dict[str, Any] | None:
                receipt = super().receipt(tx_hash)
                assert receipt is not None
                batch_data = "0x" + "".join(
                    [
                        word(64),
                        word(160),
                        word(2),
                        word(7),
                        word(8),
                        word(2),
                        word(70),
                        word(80),
                    ]
                )
                receipt["logs"] = [
                    {
                        "address": TOKEN,
                        "topics": [
                            TRANSFER_TOPIC,
                            topic_address(ORIGIN),
                            topic_address(RECIPIENT),
                            hex(99),
                        ],
                        "data": "0x",
                        "logIndex": "0x1",
                    },
                    {
                        "address": TOKEN,
                        "topics": [
                            TRANSFER_SINGLE_TOPIC,
                            topic_address(TARGET),
                            topic_address(ORIGIN),
                            topic_address(RECIPIENT),
                        ],
                        "data": "0x" + word(7) + word(70),
                        "logIndex": "0x2",
                    },
                    {
                        "address": TOKEN,
                        "topics": [
                            TRANSFER_BATCH_TOPIC,
                            topic_address(TARGET),
                            topic_address(ORIGIN),
                            topic_address(RECIPIENT),
                        ],
                        "data": batch_data,
                        "logIndex": "0x3",
                    },
                ]
                return receipt

        case = investigate_transaction(
            MultiTokenRpc(),  # type: ignore[arg-type]
            ETHEREUM,
            TX_HASH,
            include_trace=False,
            replay_prestate=False,
        )
        token_transfers = [item for item in case.transfers if item.asset_type != "native"]
        self.assertEqual(
            [(item.asset_type, item.token_id, item.amount) for item in token_transfers],
            [
                ("erc721", "99", "1"),
                ("erc1155", "7", "70"),
                ("erc1155", "7", "70"),
                ("erc1155", "8", "80"),
            ],
        )

    def test_rejects_inconsistent_block_evidence(self) -> None:
        class InconsistentBlockRpc(InvestigationRpc):
            def block(self, number: int, *, full_transactions: bool = False) -> dict[str, Any]:
                block = super().block(number, full_transactions=full_transactions)
                block["hash"] = "0x" + "cc" * 32
                return block

        with self.assertRaisesRegex(RuntimeError, "block hashes disagree"):
            investigate_transaction(
                InconsistentBlockRpc(),  # type: ignore[arg-type]
                ETHEREUM,
                TX_HASH,
                include_trace=False,
                replay_prestate=False,
            )

    def test_marks_missing_receipt_status_and_fee_as_unknown(self) -> None:
        class LegacyReceiptRpc(InvestigationRpc):
            def receipt(self, tx_hash: str) -> dict[str, Any] | None:
                receipt = super().receipt(tx_hash)
                assert receipt is not None
                receipt.pop("status")
                receipt.pop("effectiveGasPrice")
                return receipt

            def transaction(self, tx_hash: str) -> dict[str, Any] | None:
                transaction = super().transaction(tx_hash)
                assert transaction is not None
                transaction.pop("gasPrice")
                return transaction

        case = investigate_transaction(
            LegacyReceiptRpc(),  # type: ignore[arg-type]
            ETHEREUM,
            TX_HASH,
            include_trace=False,
            replay_prestate=False,
        )
        self.assertEqual(case.transaction_status, "unknown")
        self.assertIsNone(case.transaction_fee_wei)
        self.assertTrue(any("fee is unavailable" in item for item in case.warnings))

    def test_writes_integrity_manifest_and_portable_graphs(self) -> None:
        case = investigate_transaction(
            InvestigationRpc(),  # type: ignore[arg-type]
            ETHEREUM,
            TX_HASH,
            replay_prestate=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "case"
            result = write_case_bundle(case, destination)
            self.assertEqual({item.name for item in result.files}, set(BUNDLE_FILES))
            manifest = json.loads(result.manifest.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 2)
            for item in manifest["files"]:
                path = destination / item["path"]
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])
            self.assertIn("<graphml", (destination / "graph.graphml").read_text())
            self.assertIn(
                "White Radar investigation graph",
                (destination / "graph.html").read_text(),
            )
            self.assertIn("event_signature", (destination / "events.csv").read_text())
            self.assertIn(TARGET, (destination / "state_changes.csv").read_text())
            with self.assertRaises(FileExistsError):
                write_case_bundle(case, destination)

    def test_refuses_symbolic_link_bundle_artifact(self) -> None:
        case = investigate_transaction(
            InvestigationRpc(),  # type: ignore[arg-type]
            ETHEREUM,
            TX_HASH,
            include_trace=False,
            replay_prestate=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "case"
            destination.mkdir()
            target = Path(directory) / "outside.json"
            target.write_text("preserve", encoding="utf-8")
            (destination / "case.json").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                write_case_bundle(case, destination, overwrite=True)
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
