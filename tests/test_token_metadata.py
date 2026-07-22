from __future__ import annotations

import unittest

from tests.test_investigation import TOKEN, InvestigationRpc
from white_radar.token_metadata import TokenMetadataResolver, format_token_amount


def abi_string(value: str) -> str:
    raw = value.encode("utf-8")
    padding = b"\x00" * ((32 - len(raw) % 32) % 32)
    return "0x" + (32).to_bytes(32, "big").hex() + len(raw).to_bytes(32, "big").hex() + (
        raw + padding
    ).hex()


class MetadataRpc(InvestigationRpc):
    def eth_call(self, transaction: dict[str, object], block: str = "latest") -> str:
        assert transaction["to"] == TOKEN
        assert block == "0x64"
        selector = transaction["data"]
        if selector == "0x06fdde03":
            return abi_string("Evidence Token")
        if selector == "0x95d89b41":
            return abi_string("EVID")
        if selector == "0x313ce567":
            return "0x" + f"{6:064x}"
        return "0x"


class TokenMetadataTests(unittest.TestCase):
    def test_formats_raw_integer_units_without_floating_point(self) -> None:
        self.assertEqual(format_token_amount("1234500", 6), "1.2345")
        self.assertEqual(format_token_amount("1000000", 6), "1")
        self.assertIsNone(format_token_amount("invalid", 18))

    def test_resolves_historical_token_metadata(self) -> None:
        resolver = TokenMetadataResolver(MetadataRpc())  # type: ignore[arg-type]
        metadata = resolver.resolve(TOKEN, 100)
        assert metadata is not None
        self.assertEqual(metadata.name, "Evidence Token")
        self.assertEqual(metadata.symbol, "EVID")
        self.assertEqual(metadata.decimals, 6)


if __name__ == "__main__":
    unittest.main()
