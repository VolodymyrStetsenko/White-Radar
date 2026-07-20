from __future__ import annotations

import unittest

from white_radar.rpc import JsonRpcClient, ReadOnlyViolation


class ReadOnlyRpcTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rpc = JsonRpcClient("https://example.invalid/v2/not-a-real-key", retries=1)

    def test_rejects_raw_transaction_broadcast(self) -> None:
        with self.assertRaises(ReadOnlyViolation):
            self.rpc.call("eth_sendRawTransaction", ["0xdeadbeef"])

    def test_rejects_unlocked_account_broadcast(self) -> None:
        with self.assertRaises(ReadOnlyViolation):
            self.rpc.call("eth_sendTransaction", [{"to": "0x0"}])

    def test_rejects_wallet_and_personal_methods(self) -> None:
        for method in ("personal_sign", "wallet_addEthereumChain", "miner_start"):
            with self.subTest(method=method), self.assertRaises(ReadOnlyViolation):
                self.rpc.call(method, [])


if __name__ == "__main__":
    unittest.main()
