from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from white_radar.invariants import check_invariant, compare_values, decode_return_data
from white_radar.policy import ProtocolInvariant, load_policy_book
from white_radar.rpc import RpcError


class InvariantRpc:
    def __init__(self, result: str = "0x" + f"{100:064x}") -> None:
        self.result = result

    def eth_call(self, transaction: dict[str, object], block: str) -> str:
        assert transaction["data"] == "0x18160ddd"
        assert block == "0x64"
        return self.result


class ErrorRpc(InvariantRpc):
    def eth_call(self, transaction: dict[str, object], block: str) -> str:
        raise RpcError("endpoint unavailable")


class InvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.invariant = ProtocolInvariant(
            name="Supply ceiling",
            target="0x" + "11" * 20,
            call_data="0x18160ddd",
            decode_as="uint256",
            operator="lte",
            expected=100,
            score=90,
            alert_on_error=True,
        )

    def test_decodes_and_compares_supported_abi_words(self) -> None:
        self.assertEqual(decode_return_data("0x" + f"{42:064x}", "uint256"), 42)
        self.assertTrue(decode_return_data("0x" + f"{1:064x}", "bool"))
        self.assertTrue(compare_values(10, 10, "eq"))
        self.assertTrue(compare_values(10, 11, "lt"))
        self.assertTrue(compare_values(0, None, "zero"))
        self.assertFalse(compare_values(0, None, "nonzero"))
        with self.assertRaises(ValueError):
            decode_return_data("0x01", "uint256")

    def test_reports_ok_violation_and_rpc_error_at_a_pinned_block(self) -> None:
        ok = check_invariant(
            InvariantRpc(),  # type: ignore[arg-type]
            self.invariant,
            block_number=100,
            block_hash="0x" + "aa" * 32,
        )
        self.assertEqual(ok.status, "ok")
        violated = check_invariant(
            InvariantRpc("0x" + f"{101:064x}"),  # type: ignore[arg-type]
            self.invariant,
            block_number=100,
            block_hash=None,
        )
        self.assertEqual(violated.status, "violated")
        error = check_invariant(
            ErrorRpc(),  # type: ignore[arg-type]
            self.invariant,
            block_number=100,
            block_hash=None,
        )
        self.assertEqual(error.status, "error")
        self.assertEqual(error.error_class, "RpcError")

    def test_policy_schema_loads_labels_and_protocol_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policies.toml"
            path.write_text(
                """
schema_version = 2
[[protocols]]
chain_id = 1
address = "0x1111111111111111111111111111111111111111"
protocol = "Example"

[protocols.selector_labels]
"0x18160ddd" = "totalSupply()"

[[protocols.invariants]]
name = "Supply ceiling"
call_data = "0x18160ddd"
decode_as = "uint256"
operator = "lte"
expected = 100
score = 90
""",
                encoding="utf-8",
            )
            book = load_policy_book(path)
        policy = book.policies[0]
        self.assertEqual(policy.selector_label("0x18160ddd"), "totalSupply()")
        self.assertEqual(policy.invariants[0].target, policy.address)
        self.assertEqual(policy.invariants[0].score, 90)


if __name__ == "__main__":
    unittest.main()
