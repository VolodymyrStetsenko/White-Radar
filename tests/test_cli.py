from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.common import sample_event, settings_for
from white_radar.cli import (
    _load_runtime,
    _validated_address,
    build_parser,
    cmd_doctor,
    cmd_health,
    cmd_incident_transition,
    cmd_incidents,
    cmd_init,
    cmd_preview,
    main,
)
from white_radar.config import ConfigurationError, Watchlist
from white_radar.storage import RadarStore


class CliTests(unittest.TestCase):
    def test_validates_contract_addresses_for_analysis_commands(self) -> None:
        address = "0x" + "AB" * 20
        self.assertEqual(_validated_address(address), address.lower())
        with self.assertRaises(ConfigurationError):
            _validated_address("0x1234")

    def test_parser_and_init_preserve_existing_files(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["status"]).command, "status")
        self.assertEqual(
            parser.parse_args(
                ["simulate", "--chain", "ethereum", "--tx-hash", "0x" + "11" * 32]
            ).command,
            "simulate",
        )
        investigation = parser.parse_args(
            ["investigate", "--chain", "ethereum", "--tx-hash", "0x" + "11" * 32]
        )
        self.assertTrue(investigation.trace)
        self.assertTrue(investigation.replay)
        self.assertTrue(investigation.state_diff)
        self.assertFalse(investigation.single_transaction)
        self.assertEqual(investigation.backward_blocks, 256)
        self.assertEqual(investigation.forward_blocks, 512)
        self.assertEqual(investigation.max_hops, 3)
        self.assertEqual(investigation.history_source, "auto")
        without_state = parser.parse_args(
            [
                "investigate",
                "--chain",
                "ethereum",
                "--tx-hash",
                "0x" + "11" * 32,
                "--no-state-diff",
            ]
        )
        self.assertFalse(without_state.state_diff)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.toml"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(cmd_init(str(config)), 0)
            created = json.loads(output.getvalue())["created"]
            self.assertEqual(len(created), 4)
            config.write_text(config.read_text(encoding="utf-8") + "\n# preserved\n")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd_init(str(config)), 0)
            self.assertIn("# preserved", config.read_text(encoding="utf-8"))
            self.assertEqual((root / ".env").stat().st_mode & 0o777, 0o600)

    def test_runtime_doctor_preview_and_status_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.toml"
            with contextlib.redirect_stdout(io.StringIO()):
                cmd_init(str(config))
            with patch.dict(
                os.environ,
                {"RPC_ETHEREUM_HTTP": "https://example.invalid"},
                clear=False,
            ):
                settings, watchlist, store, _notifier = _load_runtime(str(config))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cmd_doctor(settings, watchlist, online=False), 0)
                store.add_event(sample_event())
                preview = io.StringIO()
                with contextlib.redirect_stdout(preview):
                    self.assertEqual(cmd_preview(settings, store, None), 0)
                self.assertIn("WHITE RADAR", preview.getvalue())

                status = io.StringIO()
                with contextlib.redirect_stdout(status), self.assertRaises(SystemExit) as exited:
                    main(["--config", str(config), "status"])
                self.assertEqual(exited.exception.code, 0)
                self.assertIn('"events": 1', status.getvalue())

    def test_preview_without_events_returns_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = settings_for(Path(directory))
            store = RadarStore(settings.app.database_path)
            store.initialize()
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cmd_preview(settings, store, None), 1)

    def test_incident_and_health_operator_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = settings_for(Path(directory))
            store = RadarStore(settings.app.database_path)
            store.initialize()
            event = sample_event()
            store.add_event(event)
            incident = store.open_incident(event, minimum_score=70, sla_minutes=15)
            assert incident is not None
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd_incidents(store, status="new", limit=10), 0)
                self.assertEqual(
                    cmd_incident_transition(
                        store,
                        incident_id=incident.incident_id,
                        status="acknowledged",
                        actor="operator",
                        note="Review started.",
                    ),
                    0,
                )
                self.assertEqual(
                    cmd_health(settings, Watchlist((), ()), store, stale_after=None), 1
                )
            store.record_heartbeat(service_name="confirmed_scanner", chain_id=1)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd_health(settings, Watchlist((), ()), store, stale_after=120), 0)


if __name__ == "__main__":
    unittest.main()
