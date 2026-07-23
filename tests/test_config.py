from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from white_radar.config import (
    ConfigurationError,
    configured_endpoints,
    load_settings,
    load_watchlist,
)


class ConfigurationTests(unittest.TestCase):
    def test_loads_chain_configuration(self) -> None:
        project = Path(__file__).resolve().parents[1]
        settings = load_settings(project / "config.example.toml")
        self.assertEqual(settings.chain_by_name("ethereum").chain_id, 1)
        self.assertTrue(settings.chain_by_name("ethereum").enabled)
        self.assertTrue(settings.app.dry_run)
        self.assertTrue(settings.analysis.invariant_checks_enabled)
        self.assertEqual(
            settings.chain_by_name("ethereum").rpc_http_fallback_envs,
            ("RPC_ETHEREUM_HTTP_SECONDARY",),
        )
        monad = settings.chain_by_name("monad")
        self.assertEqual(monad.chain_id, 143)
        self.assertEqual(monad.rpc_http_env, "RPC_MONAD_HTTP")
        self.assertEqual(monad.rpc_ws_env, "RPC_MONAD_WS")
        self.assertFalse(monad.enabled)

    def test_resolves_unique_rpc_fallbacks_from_environment(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "PRIMARY": "https://primary.invalid",
                "SECONDARY": "https://secondary.invalid",
                "DUPLICATE": "https://primary.invalid",
            },
            clear=True,
        ):
            self.assertEqual(
                configured_endpoints("PRIMARY", ("SECONDARY", "DUPLICATE")),
                ("https://primary.invalid", "https://secondary.invalid"),
            )

    def test_watchlist_normalizes_addresses_and_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "watchlist.toml"
            path.write_text(
                """
[[contracts]]
chain_id = 1
address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
protocol = "Example"
critical_selectors = ["0xABCDEF01"]

[[deployers]]
chain_id = 1
address = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
label = "Release deployer"
""",
                encoding="utf-8",
            )
            watchlist = load_watchlist(path)
        self.assertEqual(watchlist.contracts[0].address, "0x" + "a" * 40)
        self.assertEqual(watchlist.contracts[0].critical_selectors, ("0xabcdef01",))
        self.assertEqual(watchlist.deployers[0].address, "0x" + "b" * 40)

    def test_rejects_malformed_contract_address(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "watchlist.toml"
            path.write_text(
                '[[contracts]]\nchain_id=1\naddress="0x123"\nprotocol="Bad"\n',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_watchlist(path)


if __name__ == "__main__":
    unittest.main()
