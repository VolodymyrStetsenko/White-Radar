from __future__ import annotations

import dataclasses
import unittest
from unittest.mock import patch

from tests.common import ETHEREUM, sample_event
from white_radar.config import TelegramConfig
from white_radar.http import HttpError
from white_radar.models import ChainConfig
from white_radar.telegram import TelegramNotifier, event_buttons, render_event


class TelegramFormattingTests(unittest.TestCase):
    def test_renders_professional_context(self) -> None:
        text = render_event(sample_event(), ETHEREUM)
        self.assertIn("WHITE RADAR", text)
        self.assertIn("Deployer:", text)
        self.assertIn("0x2222222222222222222222222222222222222222", text)
        self.assertIn("Related contracts", text)
        self.assertIn("Verifier", text)
        self.assertIn("Recommended action", text)
        self.assertLessEqual(len(text), 4000)

    def test_includes_explorer_buttons(self) -> None:
        buttons = event_buttons(sample_event(), ETHEREUM)
        labels = {button["text"] for row in buttons for button in row}
        self.assertEqual(labels, {"Transaction", "Contract"})

    def test_renders_pending_policy_context_without_claiming_intent(self) -> None:
        event = dataclasses.replace(
            sample_event(),
            event_type="pending_watch",
            metadata={
                "protocol": "Example",
                "role": "proxy",
                "selector": "0x12345678",
                "function_signature": "review(uint256)",
                "decoded_arguments": {"caseId": 7},
                "abi_source": "Etherscan",
                "native_value_wei": 1,
                "policy_configured": True,
                "policy_baseline_match": False,
                "policy_findings": [{"code": "selector_outside_baseline"}],
                "simulation": {
                    "status": "succeeded",
                    "block_number": 100,
                    "trace": {
                        "call_count": 2,
                        "max_depth": 1,
                        "delegatecall_count": 1,
                        "create_count": 0,
                        "value_call_count": 1,
                        "reverted_call_count": 0,
                        "selfdestruct_count": 0,
                    },
                    "findings": [{"code": "delegated_execution_path"}],
                },
            },
        )
        text = render_event(event, ETHEREUM)
        self.assertIn("Sender:", text)
        self.assertIn("Policy baseline:</b> REVIEW", text)
        self.assertIn("selector_outside_baseline", text)
        self.assertIn("review(uint256)", text)
        self.assertIn("caseId", text)
        self.assertIn("Runtime flags", text)
        self.assertIn("delegated_execution_path", text)

    def test_notifier_delivers_and_respects_dry_run(self) -> None:
        config = TelegramConfig(enabled=True, minimum_score=60, send_testnet_alerts=False)
        notifier = TelegramNotifier(config, False, 2, 1)
        with (
            patch.dict(
                "os.environ",
                {"TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "123"},
            ),
            patch("white_radar.telegram.request_json", return_value={"ok": True}) as request,
        ):
            self.assertTrue(notifier.send(sample_event(), ETHEREUM))
            self.assertEqual(request.call_count, 1)

        dry = TelegramNotifier(config, True, 2, 1)
        with patch.dict(
            "os.environ",
            {"TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "123"},
        ):
            self.assertFalse(dry.send(sample_event(), ETHEREUM))

    def test_notifier_filters_testnet_and_wraps_http_error(self) -> None:
        config = TelegramConfig(enabled=True, minimum_score=60, send_testnet_alerts=False)
        testnet = ChainConfig(
            name="test",
            display_name="Test",
            chain_id=2,
            enabled=True,
            is_testnet=True,
            rpc_http_env="RPC_TEST",
            rpc_ws_env="RPC_TEST_WS",
            explorer_url="https://example.invalid",
        )
        notifier = TelegramNotifier(config, False, 2, 1)
        self.assertFalse(notifier.should_send(sample_event(), testnet))
        with (
            patch.dict(
                "os.environ",
                {"TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "123"},
            ),
            patch("white_radar.telegram.request_json", side_effect=HttpError("offline")),
            self.assertRaises(RuntimeError),
        ):
            notifier.send(sample_event(), ETHEREUM)


if __name__ == "__main__":
    unittest.main()
