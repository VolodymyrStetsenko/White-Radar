from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import signal
import sys
import time
from pathlib import Path

from white_radar import __version__
from white_radar.config import (
    ConfigurationError,
    Settings,
    Watchlist,
    load_dotenv,
    load_settings,
    load_watchlist,
)
from white_radar.logging import configure_logging, log_context
from white_radar.mempool import watch_pending_transactions
from white_radar.models import ChainConfig
from white_radar.monitor import ChainScanner
from white_radar.rpc import JsonRpcClient
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier, render_event

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="white-radar",
        description="Read-only multi-chain security monitoring and incident triage.",
    )
    parser.add_argument("--version", action="version", version=f"White Radar {__version__}")
    parser.add_argument(
        "--config",
        default=os.getenv("WHITE_RADAR_CONFIG", "config.toml"),
        help="Path to config.toml (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Create local config and watchlist from safe examples.")

    doctor = subparsers.add_parser("doctor", help="Validate configuration and RPC identity.")
    doctor.add_argument("--online", action="store_true", help="Call enabled RPC endpoints.")

    once = subparsers.add_parser("run-once", help="Scan one confirmed block range.")
    once.add_argument("--chain", action="append", help="Scan only this configured chain name.")

    daemon = subparsers.add_parser("daemon", help="Continuously scan confirmed block ranges.")
    daemon.add_argument("--chain", action="append", help="Scan only this configured chain name.")

    pending = subparsers.add_parser(
        "watch-pending",
        help="Read-only pending observer limited to explicitly watched contracts.",
    )
    pending.add_argument("--chain", required=True, help="One configured chain name.")

    subparsers.add_parser("status", help="Show local database counters and chain cursors.")

    recent = subparsers.add_parser("events", help="Print recent normalized events as JSON.")
    recent.add_argument("--limit", type=int, default=20)

    export = subparsers.add_parser("export", help="Export all normalized events to JSONL.")
    export.add_argument("destination", type=Path)

    alert = subparsers.add_parser(
        "preview-alert", help="Render one stored event in Telegram HTML without sending it."
    )
    alert.add_argument("--event-id", help="Specific recent event ID; defaults to latest.")
    return parser


def _load_runtime(config_path: str) -> tuple[Settings, Watchlist, RadarStore, TelegramNotifier]:
    config_file = Path(config_path).expanduser().resolve()
    load_dotenv(config_file.parent / ".env")
    settings = load_settings(config_file)
    configure_logging(settings.app.log_level)
    watchlist = load_watchlist(settings.app.watchlist_path)
    store = RadarStore(settings.app.database_path)
    store.initialize()
    notifier = TelegramNotifier(
        settings.telegram,
        settings.app.dry_run,
        settings.app.request_timeout_seconds,
        settings.app.request_retries,
    )
    return settings, watchlist, store, notifier


def _selected_chains(settings: Settings, names: list[str] | None) -> tuple[ChainConfig, ...]:
    if names:
        selected = tuple(settings.chain_by_name(name) for name in names)
        disabled = [chain.name for chain in selected if not chain.enabled]
        if disabled:
            raise ConfigurationError(f"Selected chains are disabled: {', '.join(disabled)}")
        return selected
    return settings.enabled_chains()


def cmd_init(config_path: str) -> int:
    destination = Path(config_path).expanduser().resolve()
    root = destination.parent
    package_root = Path(__file__).resolve().parents[2]
    example_config = package_root / "config.example.toml"
    example_watchlist = package_root / "watchlist.example.toml"
    env_example = package_root / ".env.example"
    root.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    for source, target in (
        (example_config, destination),
        (example_watchlist, root / "watchlist.toml"),
        (env_example, root / ".env"),
    ):
        if target.exists():
            continue
        shutil.copyfile(source, target)
        if target.name == ".env":
            target.chmod(0o600)
        created.append(str(target))
    (root / "data").mkdir(exist_ok=True)
    print(json.dumps({"created": created, "existing_files_preserved": True}, indent=2))
    return 0


def cmd_doctor(settings: Settings, watchlist: Watchlist, *, online: bool) -> int:
    checks: list[dict[str, object]] = []
    enabled = settings.enabled_chains()
    checks.append(
        {
            "check": "enabled_chains",
            "ok": bool(enabled),
            "detail": [chain.name for chain in enabled],
        }
    )
    checks.append(
        {
            "check": "database_parent",
            "ok": settings.app.database_path.parent.exists(),
            "detail": str(settings.app.database_path.parent),
        }
    )
    checks.append(
        {
            "check": "watchlist",
            "ok": True,
            "detail": {
                "contracts": len(watchlist.contracts),
                "deployers": len(watchlist.deployers),
            },
        }
    )
    for chain in enabled:
        url_present = bool(os.getenv(chain.rpc_http_env, "").strip())
        entry: dict[str, object] = {
            "check": f"rpc:{chain.name}",
            "ok": url_present,
            "detail": f"environment variable {chain.rpc_http_env}",
        }
        if online and url_present:
            try:
                rpc = JsonRpcClient(
                    os.environ[chain.rpc_http_env],
                    timeout=settings.app.request_timeout_seconds,
                    retries=settings.app.request_retries,
                )
                actual = rpc.chain_id()
                entry["ok"] = actual == chain.chain_id
                entry["detail"] = {"expected_chain_id": chain.chain_id, "actual_chain_id": actual}
            except Exception as exc:
                entry["ok"] = False
                entry["detail"] = f"RPC check failed: {exc}"
        checks.append(entry)
    if settings.telegram.enabled:
        checks.append(
            {
                "check": "telegram_credentials",
                "ok": bool(
                    os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
                    and os.getenv("TELEGRAM_CHAT_ID", "").strip()
                ),
                "detail": "credential presence only; values were not printed",
            }
        )
    ok = all(bool(check["ok"]) for check in checks)
    print(json.dumps({"ok": ok, "dry_run": settings.app.dry_run, "checks": checks}, indent=2))
    return 0 if ok else 1


def _scan_once(
    settings: Settings,
    watchlist: Watchlist,
    store: RadarStore,
    notifier: TelegramNotifier,
    names: list[str] | None,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for chain in _selected_chains(settings, names):
        try:
            scanner = ChainScanner(
                settings=settings,
                chain=chain,
                watchlist=watchlist,
                store=store,
                notifier=notifier,
            )
            results.append(scanner.scan().to_dict())
        except Exception as exc:
            LOGGER.exception("chain scan failed", extra=log_context(chain=chain.name))
            results.append({"chain": chain.name, "error": str(exc)})
    return results


def cmd_daemon(
    settings: Settings,
    watchlist: Watchlist,
    store: RadarStore,
    notifier: TelegramNotifier,
    names: list[str] | None,
) -> int:
    running = True

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    while running:
        results = _scan_once(settings, watchlist, store, notifier, names)
        print(json.dumps({"cycle": results}, separators=(",", ":")))
        deadline = time.monotonic() + settings.app.poll_interval_seconds
        while running and time.monotonic() < deadline:
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
    LOGGER.info("daemon stopped")
    return 0


def cmd_preview(settings: Settings, store: RadarStore, event_id: str | None) -> int:
    events = store.recent_events(100 if event_id else 1)
    event = (
        next((item for item in events if item.event_id == event_id), None)
        if event_id
        else (events[0] if events else None)
    )
    if not event:
        print("No matching event found.", file=sys.stderr)
        return 1
    chain = settings.chain_by_name(event.chain)
    print(render_event(event, chain))
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "init":
        raise SystemExit(cmd_init(args.config))
    try:
        settings, watchlist, store, notifier = _load_runtime(args.config)
        if args.command == "doctor":
            code = cmd_doctor(settings, watchlist, online=args.online)
        elif args.command == "run-once":
            results = _scan_once(settings, watchlist, store, notifier, args.chain)
            print(json.dumps(results, indent=2))
            code = 1 if any("error" in item for item in results) else 0
        elif args.command == "daemon":
            code = cmd_daemon(settings, watchlist, store, notifier, args.chain)
        elif args.command == "watch-pending":
            chain = settings.chain_by_name(args.chain)
            if not chain.enabled:
                raise ConfigurationError(f"Chain is disabled: {chain.name}")
            asyncio.run(
                watch_pending_transactions(
                    settings=settings,
                    chain=chain,
                    watchlist=watchlist,
                    store=store,
                    notifier=notifier,
                )
            )
            code = 0
        elif args.command == "status":
            print(json.dumps({"counts": store.counts(), "cursors": store.cursors()}, indent=2))
            code = 0
        elif args.command == "events":
            for event in store.recent_events(max(1, min(500, args.limit))):
                print(event.to_json())
            code = 0
        elif args.command == "export":
            count = store.export_jsonl(args.destination.resolve())
            print(json.dumps({"events": count, "destination": str(args.destination.resolve())}))
            code = 0
        elif args.command == "preview-alert":
            code = cmd_preview(settings, store, args.event_id)
        else:
            parser.error(f"Unknown command: {args.command}")
    except (ConfigurationError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 1
    raise SystemExit(code)


if __name__ == "__main__":
    main()
