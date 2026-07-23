from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from tests.test_investigation import ORIGIN, RECIPIENT, TOKEN
from white_radar.history import EtherscanHistorySource, HistorySourceError, _bounded_window

TX_BEFORE = "0x" + "12" * 32
TX_AFTER = "0x" + "34" * 32


class HistoryTests(unittest.TestCase):
    def test_rpc_window_is_centered_on_the_seed_when_capped(self) -> None:
        self.assertEqual(_bounded_window(0, 100, 50, 11), (45, 55, True))
        self.assertEqual(_bounded_window(0, 100, 2, 11), (0, 10, True))
        self.assertEqual(_bounded_window(10, 20, 15, 11), (10, 20, False))

    def test_etherscan_history_combines_nearest_backward_and_forward_records(self) -> None:
        def response(
            method: str,
            url: str,
            *,
            timeout: int,
            retries: int,
            params: dict[str, Any],
        ) -> dict[str, Any]:
            del method, url, timeout, retries
            action = params["action"]
            sort = params["sort"]
            if action == "txlist" and sort == "desc":
                return {
                    "status": "1",
                    "message": "OK",
                    "result": [
                        {
                            "hash": TX_BEFORE,
                            "blockNumber": "99",
                            "transactionIndex": "4",
                            "timeStamp": "1000",
                            "from": RECIPIENT,
                            "to": ORIGIN,
                            "value": "10",
                        }
                    ],
                }
            if action == "tokentx" and sort == "asc":
                return {
                    "status": "1",
                    "message": "OK",
                    "result": [
                        {
                            "hash": TX_AFTER,
                            "blockNumber": "101",
                            "transactionIndex": "1",
                            "timeStamp": "1010",
                            "from": ORIGIN,
                            "to": RECIPIENT,
                            "value": "25",
                            "contractAddress": TOKEN,
                        }
                    ],
                }
            return {"status": "0", "message": "No transactions found", "result": []}

        with patch("white_radar.history.request_json", side_effect=response):
            source = EtherscanHistorySource(api_key="test", retries=1)
            records = source.records_for_address(
                chain_id=1,
                address=ORIGIN,
                start_block=90,
                end_block=110,
                anchor_block=100,
                limit=20,
            )
        self.assertEqual({item.transaction_hash for item in records}, {TX_BEFORE, TX_AFTER})
        self.assertEqual({item.record_type for item in records}, {"normal", "erc20"})
        self.assertTrue(all(item.source.startswith("etherscan_v2:") for item in records))

    def test_etherscan_history_requires_a_key(self) -> None:
        source = EtherscanHistorySource(api_key="")
        with self.assertRaises(HistorySourceError):
            source.records_for_address(
                chain_id=1,
                address=ORIGIN,
                start_block=1,
                end_block=2,
                anchor_block=1,
                limit=10,
            )


if __name__ == "__main__":
    unittest.main()
