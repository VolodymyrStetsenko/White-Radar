from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from white_radar.abi import (
    AbiResolver,
    build_selector_catalog,
    canonical_abi_type,
    decode_static_arguments,
    keccak_256,
    selector_for_signature,
)
from white_radar.storage import RadarStore

TRANSFER_ABI = {
    "type": "function",
    "name": "transfer",
    "inputs": [
        {"name": "recipient", "type": "address"},
        {"name": "amount", "type": "uint256"},
    ],
}


class AbiTests(unittest.TestCase):
    def test_ethereum_keccak_and_known_function_selectors(self) -> None:
        self.assertEqual(
            keccak_256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(selector_for_signature("transfer(address,uint256)"), "0xa9059cbb")
        self.assertEqual(selector_for_signature("balanceOf(address)"), "0x70a08231")
        self.assertEqual(selector_for_signature("totalSupply()"), "0x18160ddd")

    def test_tuple_signatures_and_static_argument_decoding(self) -> None:
        self.assertEqual(
            canonical_abi_type(
                {
                    "type": "tuple[]",
                    "components": [{"type": "address"}, {"type": "uint256"}],
                }
            ),
            "(address,uint256)[]",
        )
        recipient = "11" * 20
        calldata = "0xa9059cbb" + "0" * 24 + recipient + f"{125:064x}"
        decoded = decode_static_arguments(TRANSFER_ABI, calldata)
        self.assertEqual(decoded["recipient"], "0x" + recipient)
        self.assertEqual(decoded["amount"], 125)
        self.assertEqual(
            build_selector_catalog([TRANSFER_ABI]),
            {"0xa9059cbb": "transfer(address,uint256)"},
        )

    def test_resolver_caches_a_bounded_selector_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RadarStore(Path(directory) / "radar.sqlite3")
            store.initialize()
            resolver = AbiResolver(store, timeout=1, retries=1)
            contract = "0x" + "22" * 20
            calldata = "0xa9059cbb" + "0" * 24 + "11" * 20 + f"{7:064x}"
            response = {"result": json.dumps([TRANSFER_ABI])}
            with (
                patch.dict(os.environ, {"ETHERSCAN_API_KEY": "test-value"}),
                patch("white_radar.abi.request_json", return_value=response) as request,
            ):
                decoded = resolver.resolve(1, contract, calldata)

            self.assertEqual(request.call_count, 1)
            self.assertEqual(decoded.signature, "transfer(address,uint256)")
            self.assertEqual(decoded.arguments["amount"], 7)
            self.assertEqual(decoded.source, "Etherscan")
            self.assertEqual(len(decoded.abi_sha256 or ""), 64)
            cached = store.get_abi_catalog(1, contract)
            self.assertIsNotNone(cached)
            assert cached is not None
            self.assertEqual(cached["selectors"]["0xa9059cbb"], decoded.signature)


if __name__ == "__main__":
    unittest.main()
