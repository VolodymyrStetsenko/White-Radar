from __future__ import annotations

import unittest

from white_radar.state_diff import parse_state_diff


class StateDiffTests(unittest.TestCase):
    def test_normalizes_prestate_diff_and_preserves_missing_values(self) -> None:
        address = "0x" + "Aa" * 20
        created = "0x" + "bb" * 20
        result = parse_state_diff(
            {
                "pre": {
                    address: {
                        "balance": "0x64",
                        "nonce": "0x1",
                        "code": "0x6000",
                        "storage": {"0x01": "0x10", "0x02": "0x20"},
                    }
                },
                "post": {
                    address.lower(): {
                        "balance": "0x5a",
                        "nonce": "0x2",
                        "code": "0x6000",
                        "storage": {"0x01": "0x11"},
                    },
                    created: {"balance": "0x0", "nonce": "0x1", "code": "0x6001"},
                },
            }
        )
        self.assertEqual(len(result.accounts), 2)
        modified = next(item for item in result.accounts if item.address == address.lower())
        self.assertEqual(modified.balance_before_wei, "100")
        self.assertEqual(modified.balance_after_wei, "90")
        self.assertEqual(modified.nonce_before, 1)
        self.assertEqual(modified.nonce_after, 2)
        self.assertEqual(len(modified.storage_changes), 2)
        deleted_slot = next(item for item in modified.storage_changes if item.slot == "0x02")
        self.assertEqual(deleted_slot.before, "0x20")
        self.assertIsNone(deleted_slot.after)
        created_account = next(item for item in result.accounts if item.address == created)
        self.assertEqual(created_account.change_type, "created_or_newly_materialized")

    def test_applies_storage_bound_without_dropping_account_level_evidence(self) -> None:
        first = "0x" + "11" * 20
        second = "0x" + "22" * 20
        result = parse_state_diff(
            {
                "pre": {
                    first: {"storage": {"0x01": "0x01", "0x02": "0x02"}},
                    second: {"balance": "0x1", "storage": {"0x03": "0x03"}},
                },
                "post": {
                    first: {"storage": {"0x01": "0x09", "0x02": "0x08"}},
                    second: {"balance": "0x2", "storage": {"0x03": "0x04"}},
                },
            },
            max_storage_changes=1,
        )
        self.assertEqual(len(result.accounts), 2)
        self.assertEqual(result.storage_change_count, 1)
        self.assertTrue(result.truncated)


if __name__ == "__main__":
    unittest.main()
