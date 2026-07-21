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
    build_parser,
    cmd_doctor,
    cmd_init,
    cmd_preview,
    main,
)
from white_radar.storage import RadarStore


class CliTests(unittest.TestCase):
    def test_parser_and_init_preserve_existing_files(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["status"]).command, "status")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.toml"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(cmd_init(str(config)), 0)
            created = json.loads(output.getvalue())["created"]
            self.assertEqual(len(created), 3)
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


if __name__ == "__main__":
    unittest.main()
