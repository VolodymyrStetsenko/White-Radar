from __future__ import annotations

import unittest
from typing import Any

from white_radar.enrichment import EIP1967_SLOTS
from white_radar.proxy import IMPLEMENTATION_SELECTOR, PROXIABLE_UUID_SELECTOR, inspect_proxy


def address_word(address: str | None) -> str:
    return "0x" + ("0" * 64 if address is None else "0" * 24 + address[2:])


class ProxyRpc:
    def __init__(self, *, runtime_code: str = "0x60006000") -> None:
        self.implementation = "0x" + "22" * 20
        self.admin = "0x" + "33" * 20
        self.runtime_code = runtime_code

    def block_number(self) -> int:
        return 200

    def block(self, number: int, *, full_transactions: bool = False) -> dict[str, Any]:
        return {"hash": "0x" + "ab" * 32}

    def storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        values = {
            EIP1967_SLOTS["implementation"]: self.implementation,
            EIP1967_SLOTS["admin"]: self.admin,
            EIP1967_SLOTS["beacon"]: None,
        }
        return address_word(values[slot])

    def code(self, address: str, block: str = "latest") -> str:
        return self.runtime_code

    def eth_call(self, transaction: dict[str, object], block: str = "latest") -> str:
        assert transaction["data"] == PROXIABLE_UUID_SELECTOR
        return EIP1967_SLOTS["implementation"]


class ProxyTests(unittest.TestCase):
    def test_inspects_eip1967_and_uups_state_at_a_pinned_block(self) -> None:
        rpc = ProxyRpc()
        snapshot = inspect_proxy(rpc, "0x" + "11" * 20)  # type: ignore[arg-type]
        self.assertEqual(snapshot.block_number, 200)
        self.assertEqual(snapshot.implementation, rpc.implementation)
        self.assertEqual(snapshot.effective_implementation, rpc.implementation)
        self.assertEqual(snapshot.admin, rpc.admin)
        self.assertGreater(snapshot.implementation_code_size, 0)
        self.assertTrue(snapshot.uups_compatible)
        self.assertEqual(snapshot.findings, ())

    def test_flags_an_implementation_without_runtime_code(self) -> None:
        snapshot = inspect_proxy(
            ProxyRpc(runtime_code="0x"),  # type: ignore[arg-type]
            "0x" + "11" * 20,
            block_number=199,
        )
        self.assertEqual(snapshot.block_number, 199)
        self.assertIn(
            "implementation_without_runtime_code",
            {finding.code for finding in snapshot.findings},
        )

    def test_resolves_legacy_proxy_through_implementation_call(self) -> None:
        implementation = "0x" + "77" * 20

        class LegacyProxyRpc(ProxyRpc):
            def storage_at(self, address: str, slot: str, block: str = "latest") -> str:
                return address_word(None)

            def eth_call(self, transaction: dict[str, object], block: str = "latest") -> str:
                if transaction["data"] == IMPLEMENTATION_SELECTOR:
                    return address_word(implementation)
                if transaction["data"] == PROXIABLE_UUID_SELECTOR:
                    return EIP1967_SLOTS["implementation"]
                raise AssertionError("unexpected selector")

        snapshot = inspect_proxy(
            LegacyProxyRpc(),  # type: ignore[arg-type]
            "0x" + "11" * 20,
            block_number=199,
        )
        self.assertEqual(snapshot.implementation, implementation)
        self.assertEqual(snapshot.effective_implementation, implementation)


if __name__ == "__main__":
    unittest.main()
