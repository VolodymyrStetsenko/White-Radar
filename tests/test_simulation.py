from __future__ import annotations

import unittest
from typing import Any

from white_radar.rpc import RpcError
from white_radar.simulation import (
    build_call_object,
    simulate_transaction,
    summarize_call_trace,
    transaction_fingerprint,
)


class SimulationRpc:
    def block_number(self) -> int:
        return 100

    def block(self, number: int, *, full_transactions: bool = False) -> dict[str, Any]:
        return {"number": hex(number), "hash": "0x" + "ab" * 32}

    def eth_call(self, transaction: dict[str, object], block: str) -> str:
        assert transaction["data"] == "0x12345678"
        assert block == "0x64"
        return "0x" + "01" * 32

    def trace_call(self, transaction: dict[str, object], block: str) -> dict[str, Any]:
        return {
            "type": "CALL",
            "to": transaction["to"],
            "value": "0x1",
            "calls": [
                {
                    "type": "DELEGATECALL",
                    "to": "0x" + "33" * 20,
                    "calls": [
                        {"type": "CREATE2", "to": "0x" + "44" * 20},
                        {"type": "SELFDESTRUCT", "to": "0x" + "55" * 20},
                    ],
                }
            ],
        }


class RevertingRpc(SimulationRpc):
    def eth_call(self, transaction: dict[str, object], block: str) -> str:
        raise RpcError("execution reverted")


class SimulationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transaction: dict[str, object] = {
            "from": "0x" + "11" * 20,
            "to": "0x" + "22" * 20,
            "input": "0x12345678",
            "value": "0x1",
            "gas": "0x100000",
        }

    def test_builds_sanitized_call_and_deterministic_fingerprint(self) -> None:
        call = build_call_object(self.transaction)
        self.assertEqual(call["data"], "0x12345678")
        self.assertNotIn("hash", call)
        first = transaction_fingerprint(self.transaction)
        second = transaction_fingerprint(dict(self.transaction))
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        with_nonce = transaction_fingerprint({**self.transaction, "nonce": "0x1"})
        self.assertNotEqual(first, with_nonce)
        with self.assertRaises(ValueError):
            build_call_object({"input": "0xnot-hex"})

    def test_state_pinned_simulation_summarizes_runtime_behavior(self) -> None:
        result = simulate_transaction(
            SimulationRpc(),  # type: ignore[arg-type]
            self.transaction,
            include_trace=True,
        )
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.block_number, 100)
        self.assertEqual(result.return_data_size, 32)
        self.assertIsNotNone(result.return_data_sha256)
        self.assertIsNotNone(result.trace)
        assert result.trace is not None
        self.assertEqual(result.trace.call_count, 4)
        self.assertEqual(result.trace.delegatecall_count, 1)
        self.assertEqual(result.trace.create_count, 1)
        self.assertEqual(result.trace.selfdestruct_count, 1)
        self.assertGreater(result.score_delta, 0)
        self.assertIn("destructive_execution_path", {item.code for item in result.findings})

    def test_reverted_call_is_evidence_without_a_trace_requirement(self) -> None:
        result = simulate_transaction(
            RevertingRpc(),  # type: ignore[arg-type]
            self.transaction,
            block_number=99,
        )
        self.assertEqual(result.status, "reverted")
        self.assertEqual(result.block_number, 99)
        self.assertEqual(result.error_class, "RpcError")

    def test_trace_summary_bounds_invalid_children(self) -> None:
        summary = summarize_call_trace({"type": "CALL", "calls": [None, "invalid"]})
        self.assertEqual(summary.call_count, 1)


if __name__ == "__main__":
    unittest.main()
