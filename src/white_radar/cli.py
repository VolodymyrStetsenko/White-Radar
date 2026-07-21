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
from white_radar.abi import AbiResolver
from white_radar.config import (
    ADDRESS_RE,
    ConfigurationError,
    Settings,
    Watchlist,
    configured_endpoints,
    load_dotenv,
    load_settings,
    load_watchlist,
)
from white_radar.logging import configure_logging, log_context
from white_radar.mempool import watch_pending_transactions
from white_radar.models import ChainConfig, IncidentStatus, RadarEvent
from white_radar.monitor import ChainScanner
from white_radar.policy import load_policy_book
from white_radar.proxy import inspect_proxy
from white_radar.reporting import render_digest, render_incident_report
from white_radar.rpc import JsonRpcClient
from white_radar.simulation import simulate_transaction
from white_radar.storage import RadarStore
from white_radar.telegram import TelegramNotifier, render_event

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="white-radar",
        description="Multi-chain protocol defense monitoring and incident intelligence.",
    )
    parser.add_argument("--version", action="version", version=f"White Radar {__version__}")
    parser.add_argument(
        "--config",
        default=os.getenv("WHITE_RADAR_CONFIG", "config.toml"),
        help="Path to config.toml (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Create local config and inventory from sanitized examples.")

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

    refresh = subparsers.add_parser(
        "refresh-profiles",
        help="Re-enrich a bounded batch of stored contract profiles and detect drift.",
    )
    refresh.add_argument("--chain", required=True, help="One configured chain name.")
    refresh.add_argument("--limit", type=int, default=25, help="Maximum profiles (1-500).")
    refresh.add_argument(
        "--min-age-minutes",
        type=int,
        default=60,
        help="Refresh profiles not checked within this interval.",
    )

    subparsers.add_parser("status", help="Show local database counters and chain cursors.")

    recent = subparsers.add_parser("events", help="Print recent normalized events as JSON.")
    recent.add_argument("--limit", type=int, default=20)

    export = subparsers.add_parser("export", help="Export all normalized events to JSONL.")
    export.add_argument("destination", type=Path)

    alert = subparsers.add_parser(
        "preview-alert", help="Render one stored event in Telegram HTML without sending it."
    )
    alert.add_argument("--event-id", help="Specific recent event ID; defaults to latest.")

    graph = subparsers.add_parser(
        "graph", help="Export the evidence-backed identity neighborhood for an address."
    )
    graph.add_argument("--chain", required=True, help="One configured chain name.")
    graph.add_argument("--address", required=True, help="Seed address.")
    graph.add_argument("--depth", type=int, default=2, help="Relationship depth (0-4).")

    report = subparsers.add_parser(
        "report", help="Create a Markdown incident-triage report from a stored case."
    )
    report.add_argument("--event-id", help="Specific recent event ID; defaults to latest.")
    report.add_argument("--output", type=Path, help="Write Markdown to this path.")
    report.add_argument("--graph-depth", type=int, default=2, help="Identity depth (0-4).")

    digest = subparsers.add_parser(
        "digest", help="Render a compact Telegram-compatible case digest."
    )
    digest.add_argument("--hours", type=int, default=24, help="Lookback window in hours.")
    digest.add_argument(
        "--send",
        action="store_true",
        help="Send to configured Telegram; printing is the default.",
    )

    incidents = subparsers.add_parser(
        "incidents", help="List incident cases and acknowledgement deadlines."
    )
    incidents.add_argument("--status", choices=[status.value for status in IncidentStatus])
    incidents.add_argument("--limit", type=int, default=50)

    transition = subparsers.add_parser(
        "incident-transition", help="Apply an audited incident workflow transition."
    )
    transition.add_argument("--incident-id", required=True)
    transition.add_argument(
        "--status",
        required=True,
        choices=[status.value for status in IncidentStatus],
    )
    transition.add_argument("--actor", required=True, help="Operator identity recorded in history.")
    transition.add_argument("--note", default="", help="Short evidence-based transition note.")

    health = subparsers.add_parser(
        "health", help="Check scanner heartbeats and return non-zero for stale services."
    )
    health.add_argument("--stale-after", type=int, help="Override the configured stale threshold.")

    simulate = subparsers.add_parser(
        "simulate", help="Run a state-pinned read-only simulation for a watched transaction."
    )
    simulate.add_argument("--chain", required=True, help="One configured chain name.")
    simulate.add_argument("--tx-hash", required=True, help="Transaction hash available to the RPC.")
    simulate.add_argument(
        "--block",
        type=int,
        help="Pinned block number; defaults to current head.",
    )
    simulate.add_argument("--trace", action="store_true", help="Request a callTracer summary.")

    proxy = subparsers.add_parser(
        "inspect-proxy", help="Inspect EIP-1967, beacon, implementation, and UUPS state."
    )
    proxy.add_argument("--chain", required=True, help="One configured chain name.")
    proxy.add_argument("--address", required=True, help="Proxy address.")
    proxy.add_argument("--block", type=int, help="Pinned block number; defaults to current head.")

    invariants = subparsers.add_parser(
        "check-invariants", help="Evaluate protocol invariants at a confirmed block."
    )
    invariants.add_argument("--chain", required=True, help="One configured chain name.")

    abi = subparsers.add_parser(
        "abi", help="Resolve and cache a verified function-selector catalog."
    )
    abi.add_argument("--chain", required=True, help="One configured chain name.")
    abi.add_argument("--address", required=True, help="Contract address.")
    abi.add_argument("--refresh", action="store_true", help="Refresh the cached catalog.")
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
    example_policies = package_root / "policies.example.toml"
    env_example = package_root / ".env.example"
    root.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    for source, target in (
        (example_config, destination),
        (example_watchlist, root / "watchlist.toml"),
        (example_policies, root / "policies.toml"),
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
    policy_book = load_policy_book(settings.app.policy_path)
    checks.append(
        {
            "check": "policy_pack",
            "ok": True,
            "detail": {
                "path": str(settings.app.policy_path),
                "policies": len(policy_book.policies),
                "sha256": policy_book.source_sha256,
            },
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
        endpoint_envs = (chain.rpc_http_env, *chain.rpc_http_fallback_envs)
        present = [name for name in endpoint_envs if os.getenv(name, "").strip()]
        entry: dict[str, object] = {
            "check": f"rpc:{chain.name}",
            "ok": bool(os.getenv(chain.rpc_http_env, "").strip()),
            "detail": {
                "configured_endpoint_variables": list(endpoint_envs),
                "present_endpoint_variables": present,
            },
        }
        if online and entry["ok"]:
            endpoint_results: list[dict[str, object]] = []
            for name in present:
                try:
                    rpc = JsonRpcClient(
                        os.environ[name],
                        timeout=settings.app.request_timeout_seconds,
                        retries=settings.app.request_retries,
                    )
                    actual = rpc.chain_id()
                    endpoint_results.append(
                        {
                            "environment_variable": name,
                            "ok": actual == chain.chain_id,
                            "expected_chain_id": chain.chain_id,
                            "actual_chain_id": actual,
                        }
                    )
                except Exception as exc:
                    endpoint_results.append(
                        {
                            "environment_variable": name,
                            "ok": False,
                            "error_class": type(exc).__name__,
                        }
                    )
            entry["ok"] = bool(endpoint_results) and all(
                bool(item["ok"]) for item in endpoint_results
            )
            entry["detail"] = endpoint_results
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
            result = scanner.scan().to_dict()
            store.record_heartbeat(
                service_name="confirmed_scanner",
                chain_id=chain.chain_id,
                details={"chain": chain.name, "cycle": result},
            )
            results.append(result)
        except Exception as exc:
            store.record_heartbeat(
                service_name="confirmed_scanner",
                chain_id=chain.chain_id,
                status="degraded",
                details={"chain": chain.name},
                last_error=type(exc).__name__,
            )
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


def _find_event(store: RadarStore, event_id: str | None) -> RadarEvent | None:
    events = store.recent_events(500 if event_id else 1)
    if event_id:
        return next((item for item in events if item.event_id == event_id), None)
    return events[0] if events else None


def cmd_report(
    settings: Settings,
    store: RadarStore,
    *,
    event_id: str | None,
    output: Path | None,
    graph_depth: int,
) -> int:
    event = _find_event(store, event_id)
    if not isinstance(event, RadarEvent):
        print("No matching event found.", file=sys.stderr)
        return 1
    chain = settings.chain_by_name(event.chain)
    graph = (
        store.identity_neighborhood(
            chain_id=event.chain_id,
            value=event.subject_address,
            depth=graph_depth,
        )
        if event.subject_address
        else None
    )
    incident = store.incident_for_event(event.event_id)
    report = render_incident_report(event, chain, graph=graph, incident=incident)
    if output:
        destination = output.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report, encoding="utf-8")
        print(json.dumps({"event_id": event.event_id, "destination": str(destination)}))
    else:
        print(report, end="")
    return 0


def cmd_digest(
    settings: Settings,
    store: RadarStore,
    notifier: TelegramNotifier,
    *,
    hours: int,
    send: bool,
) -> int:
    bounded_hours = max(1, min(24 * 31, hours))
    events = store.events_since(hours=bounded_hours)
    incidents = store.list_incidents(limit=500)
    chains = {chain.name: chain for chain in settings.chains}
    digest = render_digest(
        events,
        chains,
        hours=bounded_hours,
        incidents=incidents,
        overdue_incident_ids={item.incident_id for item in store.overdue_incidents(limit=500)},
    )
    print(digest)
    if send and not notifier.send_digest(digest):
        raise RuntimeError(
            "Digest was not sent. Enable Telegram and set WHITE_RADAR_DRY_RUN=false first."
        )
    return 0


def cmd_incidents(store: RadarStore, *, status: str | None, limit: int) -> int:
    selected = IncidentStatus(status) if status else None
    cases = store.list_incidents(status=selected, limit=limit)
    print(json.dumps([incident.to_dict() for incident in cases], indent=2))
    return 0


def cmd_incident_transition(
    store: RadarStore,
    *,
    incident_id: str,
    status: str,
    actor: str,
    note: str,
) -> int:
    incident = store.transition_incident(
        incident_id,
        IncidentStatus(status),
        actor=actor,
        note=note,
    )
    print(
        json.dumps(
            {
                "incident": incident.to_dict(),
                "history": store.incident_history(incident.incident_id),
            },
            indent=2,
        )
    )
    return 0


def _expected_health_services(settings: Settings, watchlist: Watchlist) -> set[tuple[str, int]]:
    expected = {("confirmed_scanner", chain.chain_id) for chain in settings.enabled_chains()}
    for chain in settings.enabled_chains():
        if configured_endpoints(
            chain.rpc_ws_env, chain.rpc_ws_fallback_envs
        ) and watchlist.addresses_for_chain(chain.chain_id):
            expected.add(("pending_observer", chain.chain_id))
    return expected


def cmd_health(
    settings: Settings,
    watchlist: Watchlist,
    store: RadarStore,
    *,
    stale_after: int | None,
) -> int:
    snapshot = store.health_snapshot(
        stale_after_seconds=(
            max(30, stale_after)
            if stale_after is not None
            else settings.app.heartbeat_stale_after_seconds
        ),
        expected_services=_expected_health_services(settings, watchlist),
    )
    print(json.dumps(snapshot, indent=2))
    return 0 if snapshot["ok"] else 1


def _rpc_for_chain(settings: Settings, chain: ChainConfig) -> JsonRpcClient:
    endpoints = configured_endpoints(chain.rpc_http_env, chain.rpc_http_fallback_envs)
    if not endpoints:
        raise ConfigurationError(f"No HTTP RPC endpoint is configured for {chain.name}")
    rpc = JsonRpcClient(
        endpoints,
        timeout=settings.app.request_timeout_seconds,
        retries=settings.app.request_retries,
    )
    actual_chain_id = rpc.chain_id()
    if actual_chain_id != chain.chain_id:
        raise ConfigurationError(
            f"RPC chain mismatch for {chain.name}: expected {chain.chain_id}, "
            f"received {actual_chain_id}"
        )
    return rpc


def _validated_address(address: str) -> str:
    normalized = address.lower()
    if not ADDRESS_RE.fullmatch(normalized):
        raise ConfigurationError(f"Invalid contract address: {address}")
    return normalized


def cmd_simulate(
    settings: Settings,
    watchlist: Watchlist,
    *,
    chain_name: str,
    tx_hash: str,
    block_number: int | None,
    trace: bool,
) -> int:
    chain = settings.chain_by_name(chain_name)
    rpc = _rpc_for_chain(settings, chain)
    transaction = rpc.transaction(tx_hash)
    if not transaction:
        raise RuntimeError("The transaction is not available from the configured RPC endpoints")
    destination = str(transaction.get("to") or "").lower()
    if not watchlist.contract(chain.chain_id, destination):
        raise ConfigurationError("Simulation is limited to destinations in watchlist.toml")
    result = simulate_transaction(
        rpc,
        transaction,
        block_number=block_number,
        include_trace=trace,
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def cmd_proxy_inspect(
    settings: Settings,
    *,
    chain_name: str,
    address: str,
    block_number: int | None,
) -> int:
    chain = settings.chain_by_name(chain_name)
    snapshot = inspect_proxy(
        _rpc_for_chain(settings, chain),
        _validated_address(address),
        block_number=block_number,
    )
    print(json.dumps(snapshot.to_dict(), indent=2))
    return 0


def cmd_abi(
    settings: Settings,
    store: RadarStore,
    *,
    chain_name: str,
    address: str,
    refresh: bool,
) -> int:
    chain = settings.chain_by_name(chain_name)
    normalized_address = _validated_address(address)
    resolver = AbiResolver(
        store,
        timeout=settings.app.request_timeout_seconds,
        retries=settings.app.request_retries,
    )
    selectors, source, digest = resolver.catalog(
        chain.chain_id,
        normalized_address,
        refresh=refresh,
    )
    print(
        json.dumps(
            {
                "chain": chain.name,
                "address": normalized_address,
                "source": source,
                "abi_sha256": digest,
                "selectors": selectors,
            },
            indent=2,
        )
    )
    return 0 if selectors else 1


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
        elif args.command == "refresh-profiles":
            chain = settings.chain_by_name(args.chain)
            if not chain.enabled:
                raise ConfigurationError(f"Chain is disabled: {chain.name}")
            scanner = ChainScanner(
                settings=settings,
                chain=chain,
                watchlist=watchlist,
                store=store,
                notifier=notifier,
            )
            try:
                result = scanner.refresh_profiles(
                    limit=max(1, min(500, args.limit)),
                    min_age_minutes=max(0, args.min_age_minutes),
                )
            except Exception as exc:
                store.record_heartbeat(
                    service_name="profile_refresh",
                    chain_id=chain.chain_id,
                    status="degraded",
                    details={"chain": chain.name},
                    last_error=type(exc).__name__,
                )
                raise
            store.record_heartbeat(
                service_name="profile_refresh",
                chain_id=chain.chain_id,
                details={"chain": chain.name, "cycle": result.to_dict()},
            )
            print(json.dumps(result.to_dict(), indent=2))
            code = 0
        elif args.command == "status":
            print(
                json.dumps(
                    {
                        "counts": store.counts(),
                        "intelligence": store.intelligence_counts(),
                        "incidents": store.incident_counts(),
                        "health": store.health_snapshot(
                            stale_after_seconds=settings.app.heartbeat_stale_after_seconds,
                            expected_services=_expected_health_services(settings, watchlist),
                        ),
                        "cursors": store.cursors(),
                    },
                    indent=2,
                )
            )
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
        elif args.command == "graph":
            chain = settings.chain_by_name(args.chain)
            print(
                json.dumps(
                    store.identity_neighborhood(
                        chain_id=chain.chain_id,
                        value=args.address,
                        depth=args.depth,
                    ),
                    indent=2,
                )
            )
            code = 0
        elif args.command == "report":
            code = cmd_report(
                settings,
                store,
                event_id=args.event_id,
                output=args.output,
                graph_depth=args.graph_depth,
            )
        elif args.command == "digest":
            code = cmd_digest(
                settings,
                store,
                notifier,
                hours=args.hours,
                send=args.send,
            )
        elif args.command == "incidents":
            code = cmd_incidents(store, status=args.status, limit=max(1, min(500, args.limit)))
        elif args.command == "incident-transition":
            code = cmd_incident_transition(
                store,
                incident_id=args.incident_id,
                status=args.status,
                actor=args.actor,
                note=args.note,
            )
        elif args.command == "health":
            code = cmd_health(
                settings,
                watchlist,
                store,
                stale_after=args.stale_after,
            )
        elif args.command == "simulate":
            code = cmd_simulate(
                settings,
                watchlist,
                chain_name=args.chain,
                tx_hash=args.tx_hash,
                block_number=args.block,
                trace=args.trace,
            )
        elif args.command == "inspect-proxy":
            code = cmd_proxy_inspect(
                settings,
                chain_name=args.chain,
                address=args.address,
                block_number=args.block,
            )
        elif args.command == "check-invariants":
            chain = settings.chain_by_name(args.chain)
            if not chain.enabled:
                raise ConfigurationError(f"Chain is disabled: {chain.name}")
            scanner = ChainScanner(
                settings=settings,
                chain=chain,
                watchlist=watchlist,
                store=store,
                notifier=notifier,
            )
            print(json.dumps(scanner.check_invariants().to_dict(), indent=2))
            code = 0
        elif args.command == "abi":
            code = cmd_abi(
                settings,
                store,
                chain_name=args.chain,
                address=args.address,
                refresh=args.refresh,
            )
        else:
            parser.error(f"Unknown command: {args.command}")
    except (ConfigurationError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 1
    raise SystemExit(code)


if __name__ == "__main__":
    main()
