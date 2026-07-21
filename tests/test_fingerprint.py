from __future__ import annotations

import unittest

from white_radar.fingerprint import (
    fingerprint_bytecode,
    simhash_similarity,
    strip_solidity_metadata,
)


class FingerprintTests(unittest.TestCase):
    def test_strips_conservative_solidity_metadata_trailer(self) -> None:
        runtime = bytes.fromhex("6001600055") * 30
        metadata = b"\xa2dipfsX\x20" + b"a" * 32 + b"dsolcC\x00\x08\x1e"
        bytecode = runtime + metadata + len(metadata).to_bytes(2, "big")
        normalized, removed = strip_solidity_metadata(bytecode)
        self.assertEqual(normalized, runtime)
        self.assertEqual(removed, len(metadata) + 2)

        fingerprint = fingerprint_bytecode("0x" + bytecode.hex())
        self.assertEqual(fingerprint.bytecode_size, len(bytecode))
        self.assertEqual(fingerprint.normalized_size, len(runtime))
        self.assertEqual(fingerprint.metadata_size, len(metadata) + 2)

    def test_keeps_unrecognized_or_invalid_trailer(self) -> None:
        raw = b"\x60\x00\x60\x00\x00\x02"
        self.assertEqual(strip_solidity_metadata(raw), (raw, 0))
        invalid = fingerprint_bytecode("0xnot-hex")
        self.assertEqual(invalid.bytecode_size, 0)
        self.assertEqual(invalid.simhash64, "0" * 16)

    def test_similarity_is_deterministic_and_bounded(self) -> None:
        left = fingerprint_bytecode("0x" + ("6001600055" * 200))
        same = fingerprint_bytecode("0x" + ("6001600055" * 200))
        changed = fingerprint_bytecode("0x" + ("6001600055" * 199) + "6002600055")
        self.assertEqual(simhash_similarity(left.simhash64, same.simhash64), 1.0)
        self.assertGreater(simhash_similarity(left.simhash64, changed.simhash64), 0.8)
        self.assertEqual(simhash_similarity("bad", same.simhash64), 0.0)


if __name__ == "__main__":
    unittest.main()
