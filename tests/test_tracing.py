from __future__ import annotations

import unittest

from white_radar.tracing import internal_creations


class TracingTests(unittest.TestCase):
    def test_extracts_successful_nested_create_frames(self) -> None:
        creator = "0x" + "11" * 20
        first = "0x" + "22" * 20
        second = "0x" + "33" * 20
        trace = {
            "type": "CALL",
            "from": "0x" + "aa" * 20,
            "to": creator,
            "calls": [
                {"type": "CREATE", "from": creator, "to": first},
                {
                    "type": "CALL",
                    "from": creator,
                    "to": "0x" + "44" * 20,
                    "calls": [
                        {"type": "CREATE2", "from": creator, "to": second},
                        {"type": "CREATE", "from": creator, "to": first},
                    ],
                },
                {"type": "CREATE", "from": creator, "to": "0x1", "error": "revert"},
            ],
        }
        found = internal_creations(trace)
        self.assertEqual([item.address for item in found], [first, second])
        self.assertEqual(found[0].depth, 1)
        self.assertEqual(found[1].creation_type, "CREATE2")

    def test_ignores_top_level_or_malformed_frames(self) -> None:
        address = "0x" + "11" * 20
        trace = {"type": "CREATE", "from": address, "to": address, "calls": [None, "bad"]}
        self.assertEqual(internal_creations(trace), ())


if __name__ == "__main__":
    unittest.main()
