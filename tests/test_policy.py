from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from white_radar.config import ConfigurationError
from white_radar.policy import MAX_POLICY_BYTES, assess_pending, load_policy_book


class PolicyTests(unittest.TestCase):
    def test_loads_normalizes_and_assesses_protocol_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policies.toml"
            path.write_text(
                """
schema_version = 1
[[protocols]]
chain_id = 1
address = "0x1111111111111111111111111111111111111111"
protocol = "Example"
authorized_senders = ["0x2222222222222222222222222222222222222222"]
allowed_selectors = ["0x12345678"]
critical_selectors = ["0x12345678"]
max_native_value_wei = 0
incident_sla_minutes = 15
""",
                encoding="utf-8",
            )
            book = load_policy_book(path)
        self.assertIsNotNone(book.source_sha256)
        policy = book.contract(1, "0x1111111111111111111111111111111111111111")
        self.assertIsNotNone(policy)
        assert policy is not None
        matching = assess_pending(
            policy,
            sender="0x2222222222222222222222222222222222222222",
            selector="0x12345678",
            native_value_wei=0,
        )
        self.assertTrue(matching.baseline_match)
        self.assertEqual([item.code for item in matching.findings], ["critical_selector"])

        anomalous = assess_pending(
            policy,
            sender="0x3333333333333333333333333333333333333333",
            selector="0x87654321",
            native_value_wei=1,
        )
        self.assertEqual(anomalous.score_delta, 40)
        self.assertEqual(
            {item.code for item in anomalous.findings},
            {
                "sender_outside_baseline",
                "selector_outside_baseline",
                "native_value_above_baseline",
            },
        )

    def test_missing_invalid_duplicate_and_oversized_policy_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(load_policy_book(root / "missing.toml").policies, ())
            duplicate = root / "duplicate.toml"
            entry = """
[[protocols]]
chain_id=1
address="0x1111111111111111111111111111111111111111"
protocol="Example"
"""
            duplicate.write_text(entry + entry, encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                load_policy_book(duplicate)
            oversized = root / "oversized.toml"
            oversized.write_bytes(b"#" * (MAX_POLICY_BYTES + 1))
            with self.assertRaises(ConfigurationError):
                load_policy_book(oversized)


if __name__ == "__main__":
    unittest.main()
