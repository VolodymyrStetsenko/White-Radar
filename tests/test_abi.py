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
    event_signature,
    keccak_256,
    selector_for_signature,
    topic_for_event_signature,
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

AUDIT_EVENT_ABI = {
    "type": "event",
    "name": "Audit",
    "anonymous": False,
    "inputs": [
        {"name": "actor", "type": "address", "indexed": True},
        {"name": "message", "type": "string", "indexed": False},
        {"name": "category", "type": "string", "indexed": True},
        {"name": "amount", "type": "uint256", "indexed": False},
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

    def test_resolver_marks_builtin_selector_matches_as_unverified_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RadarStore(Path(directory) / "radar.sqlite3")
            store.initialize()
            resolver = AbiResolver(store, timeout=1, retries=1)
            contract = "0x" + "22" * 20
            recipient = "11" * 20
            calldata = "0x40c10f19" + "0" * 24 + recipient + f"{25:064x}"
            with patch.dict(os.environ, {}, clear=True):
                decoded = resolver.resolve(1, contract, calldata)
            self.assertEqual(decoded.signature, "mint(address,uint256)")
            self.assertEqual(decoded.arguments["to"], "0x" + recipient)
            self.assertEqual(decoded.arguments["amount"], 25)
            self.assertEqual(decoded.confidence, "candidate")
            self.assertIn("unverified", decoded.source or "")

    def test_decodes_verified_event_and_preserves_indexed_dynamic_hash(self) -> None:
        signature = event_signature(AUDIT_EVENT_ABI)
        assert signature is not None
        actor = "0x" + "11" * 20
        category_hash = "0x" + "77" * 32
        topics = [
            topic_for_event_signature(signature),
            "0x" + "00" * 12 + actor[2:],
            category_hash,
        ]
        message = b"hello"
        data = "0x" + (
            f"{64:064x}"
            f"{9:064x}"
            f"{len(message):064x}"
            + message.hex().ljust(64, "0")
        )
        with tempfile.TemporaryDirectory() as directory:
            store = RadarStore(Path(directory) / "radar.sqlite3")
            store.initialize()
            resolver = AbiResolver(store, timeout=1, retries=1)
            contract = "0x" + "22" * 20
            response = {"result": json.dumps([AUDIT_EVENT_ABI])}
            with (
                patch.dict(os.environ, {"ETHERSCAN_API_KEY": "test-value"}),
                patch("white_radar.abi.request_json", return_value=response),
            ):
                decoded = resolver.resolve_event(1, contract, topics, data)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded.signature, signature)
        self.assertEqual(decoded.arguments["actor"], actor)
        self.assertEqual(decoded.arguments["message"], "hello")
        self.assertEqual(decoded.arguments["category"], {"indexed_hash": category_hash})
        self.assertEqual(decoded.arguments["amount"], 9)
        self.assertEqual(decoded.confidence, "verified")


if __name__ == "__main__":
    unittest.main()
