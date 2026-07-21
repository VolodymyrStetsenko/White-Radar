from __future__ import annotations

import unittest
from unittest.mock import patch

from white_radar.config import EnrichmentConfig
from white_radar.enrichment import ContractEnricher, storage_word_to_address


class FakeStorageRpc:
    def storage_at(self, _address: str, slot: str, _block: str = "latest") -> str:
        if slot.endswith("bbc"):
            return "0x" + "00" * 12 + "11" * 20
        return "0x" + "00" * 32


class EnrichmentTests(unittest.TestCase):
    def test_extracts_address_from_eip1967_storage_word(self) -> None:
        address = "11" * 20
        self.assertEqual(
            storage_word_to_address("0x" + "00" * 12 + address),
            "0x" + address,
        )

    def test_ignores_zero_storage_word(self) -> None:
        self.assertIsNone(storage_word_to_address("0x" + "00" * 32))

    def test_sourcify_and_proxy_metadata_are_combined(self) -> None:
        enricher = ContractEnricher(
            EnrichmentConfig(sourcify_enabled=True, etherscan_enabled=True),
            timeout=1,
            retries=1,
        )
        with patch(
            "white_radar.enrichment.request_json",
            return_value={"compilation": {"name": "Pool"}},
        ):
            metadata = enricher.enrich(
                FakeStorageRpc(),  # type: ignore[arg-type]
                chain_id=1,
                address="0x" + "22" * 20,
            )
        self.assertTrue(metadata.verified)
        self.assertEqual(metadata.verification_source, "Sourcify")
        self.assertEqual(metadata.contract_name, "Pool")
        self.assertTrue(metadata.is_proxy)
        self.assertEqual(metadata.implementation, "0x" + "11" * 20)

    def test_falls_back_to_etherscan_v2(self) -> None:
        enricher = ContractEnricher(
            EnrichmentConfig(sourcify_enabled=False, etherscan_enabled=True),
            timeout=1,
            retries=1,
        )
        response = {
            "result": [
                {
                    "SourceCode": "contract Pool {}",
                    "ABI": "[]",
                    "ContractName": "Pool",
                    "Proxy": "1",
                    "Implementation": "0x" + "33" * 20,
                }
            ]
        }
        with (
            patch.dict("os.environ", {"ETHERSCAN_API_KEY": "test-key"}),
            patch("white_radar.enrichment.request_json", return_value=response),
        ):
            metadata = enricher.enrich(
                FakeStorageRpc(),  # type: ignore[arg-type]
                chain_id=1,
                address="0x" + "22" * 20,
            )
        self.assertEqual(metadata.verification_source, "Etherscan")
        self.assertEqual(metadata.contract_name, "Pool")

    def test_no_explorer_key_returns_unverified(self) -> None:
        enricher = ContractEnricher(
            EnrichmentConfig(sourcify_enabled=False, etherscan_enabled=True),
            timeout=1,
            retries=1,
        )
        with patch.dict("os.environ", {}, clear=True):
            metadata = enricher.enrich(
                FakeStorageRpc(),  # type: ignore[arg-type]
                chain_id=1,
                address="0x" + "22" * 20,
            )
        self.assertFalse(metadata.verified)


if __name__ == "__main__":
    unittest.main()
