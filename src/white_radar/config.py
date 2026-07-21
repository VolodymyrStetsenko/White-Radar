from __future__ import annotations

import dataclasses
import os
import re
import tomllib
from pathlib import Path
from typing import Any

from white_radar.models import ChainConfig, ContractWatch, DeployerWatch

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
SELECTOR_RE = re.compile(r"^0x[a-fA-F0-9]{8}$")


class ConfigurationError(ValueError):
    """Raised when operational configuration is unsafe or invalid."""


@dataclasses.dataclass(frozen=True, slots=True)
class AppConfig:
    database_path: Path
    watchlist_path: Path
    policy_path: Path
    poll_interval_seconds: int
    request_timeout_seconds: int
    request_retries: int
    incident_minimum_score: int
    incident_sla_minutes: int
    heartbeat_stale_after_seconds: int
    log_level: str
    dry_run: bool


@dataclasses.dataclass(frozen=True, slots=True)
class TelegramConfig:
    enabled: bool
    minimum_score: int
    send_testnet_alerts: bool


@dataclasses.dataclass(frozen=True, slots=True)
class EnrichmentConfig:
    sourcify_enabled: bool
    etherscan_enabled: bool


@dataclasses.dataclass(frozen=True, slots=True)
class Settings:
    root: Path
    app: AppConfig
    telegram: TelegramConfig
    enrichment: EnrichmentConfig
    chains: tuple[ChainConfig, ...]

    def enabled_chains(self) -> tuple[ChainConfig, ...]:
        return tuple(chain for chain in self.chains if chain.enabled)

    def chain_by_name(self, name: str) -> ChainConfig:
        for chain in self.chains:
            if chain.name == name:
                return chain
        raise ConfigurationError(f"Unknown chain: {name}")


@dataclasses.dataclass(frozen=True, slots=True)
class Watchlist:
    contracts: tuple[ContractWatch, ...]
    deployers: tuple[DeployerWatch, ...]

    def contract(self, chain_id: int, address: str | None) -> ContractWatch | None:
        if not address:
            return None
        normalized = address.lower()
        return next(
            (
                item
                for item in self.contracts
                if item.chain_id == chain_id and item.address == normalized
            ),
            None,
        )

    def deployer(self, chain_id: int, address: str | None) -> DeployerWatch | None:
        if not address:
            return None
        normalized = address.lower()
        return next(
            (
                item
                for item in self.deployers
                if item.chain_id == chain_id and item.address == normalized
            ),
            None,
        )

    def addresses_for_chain(self, chain_id: int) -> frozenset[str]:
        return frozenset(item.address for item in self.contracts if item.chain_id == chain_id)


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Configuration file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationError(f"Invalid TOML in {path}: {exc}") from exc


def _as_bool(value: str | bool | None, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"Invalid boolean value: {value}")


def load_settings(config_path: str | Path | None = None) -> Settings:
    requested_value: str | Path = (
        config_path
        if config_path is not None
        else (os.getenv("WHITE_RADAR_CONFIG") or "config.toml")
    )
    requested = Path(requested_value).expanduser()
    path = requested.resolve()
    data = _read_toml(path)
    root = path.parent

    app_data = data.get("app", {})
    telegram_data = data.get("telegram", {})
    enrichment_data = data.get("enrichment", {})

    configured_db = os.getenv(
        "WHITE_RADAR_DB", str(app_data.get("database_path", "data/white-radar.sqlite3"))
    )
    database_path = Path(configured_db)
    if not database_path.is_absolute():
        database_path = root / database_path

    watchlist_path = Path(
        os.getenv(
            "WHITE_RADAR_WATCHLIST",
            str(app_data.get("watchlist_path", "watchlist.toml")),
        )
    )
    if not watchlist_path.is_absolute():
        watchlist_path = root / watchlist_path

    policy_path = Path(
        os.getenv(
            "WHITE_RADAR_POLICIES",
            str(app_data.get("policy_path", "policies.toml")),
        )
    )
    if not policy_path.is_absolute():
        policy_path = root / policy_path

    app = AppConfig(
        database_path=database_path,
        watchlist_path=watchlist_path,
        policy_path=policy_path,
        poll_interval_seconds=max(5, int(app_data.get("poll_interval_seconds", 20))),
        request_timeout_seconds=max(3, int(app_data.get("request_timeout_seconds", 20))),
        request_retries=max(1, min(8, int(app_data.get("request_retries", 3)))),
        incident_minimum_score=max(0, min(100, int(app_data.get("incident_minimum_score", 70)))),
        incident_sla_minutes=max(1, int(app_data.get("incident_sla_minutes", 30))),
        heartbeat_stale_after_seconds=max(
            30, int(app_data.get("heartbeat_stale_after_seconds", 120))
        ),
        log_level=str(app_data.get("log_level", "INFO")).upper(),
        dry_run=_as_bool(os.getenv("WHITE_RADAR_DRY_RUN"), bool(app_data.get("dry_run", True))),
    )
    telegram = TelegramConfig(
        enabled=bool(telegram_data.get("enabled", False)),
        minimum_score=max(0, min(100, int(telegram_data.get("minimum_score", 60)))),
        send_testnet_alerts=bool(telegram_data.get("send_testnet_alerts", False)),
    )
    enrichment = EnrichmentConfig(
        sourcify_enabled=bool(enrichment_data.get("sourcify_enabled", True)),
        etherscan_enabled=bool(enrichment_data.get("etherscan_enabled", True)),
    )

    chains: list[ChainConfig] = []
    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    for item in data.get("chains", []):
        pending_subscription = str(item.get("pending_subscription", "auto")).lower()
        if pending_subscription not in {"auto", "alchemy", "standard"}:
            raise ConfigurationError("pending_subscription must be one of: auto, alchemy, standard")
        chain = ChainConfig(
            name=str(item["name"]),
            display_name=str(item.get("display_name", item["name"])),
            chain_id=int(item["chain_id"]),
            enabled=bool(item.get("enabled", False)),
            is_testnet=bool(item.get("is_testnet", False)),
            rpc_http_env=str(item["rpc_http_env"]),
            rpc_ws_env=str(item.get("rpc_ws_env", "")),
            explorer_url=str(item["explorer_url"]).rstrip("/"),
            confirmations=max(0, int(item.get("confirmations", 3))),
            initial_lookback_blocks=max(1, int(item.get("initial_lookback_blocks", 3))),
            max_blocks_per_cycle=max(1, int(item.get("max_blocks_per_cycle", 12))),
            monitor_global_upgrades=bool(item.get("monitor_global_upgrades", False)),
            pending_subscription=pending_subscription,
            trace_internal_creations=bool(item.get("trace_internal_creations", False)),
        )
        if chain.chain_id in seen_ids or chain.name in seen_names:
            raise ConfigurationError(f"Duplicate chain configuration: {chain.name}")
        seen_ids.add(chain.chain_id)
        seen_names.add(chain.name)
        chains.append(chain)

    if not chains:
        raise ConfigurationError("At least one [[chains]] entry is required")
    return Settings(root, app, telegram, enrichment, tuple(chains))


def _validate_address(value: object, field: str) -> str:
    address = str(value).lower()
    if not ADDRESS_RE.fullmatch(address):
        raise ConfigurationError(f"Invalid {field}: {value}")
    return address


def load_watchlist(path: Path) -> Watchlist:
    if not path.exists():
        return Watchlist((), ())
    data = _read_toml(path)
    contracts: list[ContractWatch] = []
    deployers: list[DeployerWatch] = []

    for item in data.get("contracts", []):
        selectors = tuple(str(value).lower() for value in item.get("critical_selectors", []))
        if any(not SELECTOR_RE.fullmatch(value) for value in selectors):
            raise ConfigurationError(
                f"Invalid critical selector for {item.get('protocol', 'unknown protocol')}"
            )
        contracts.append(
            ContractWatch(
                chain_id=int(item["chain_id"]),
                address=_validate_address(item["address"], "contract address"),
                protocol=str(item["protocol"]),
                role=str(item.get("role", "contract")),
                bounty_url=str(item.get("bounty_url", "")),
                contact_uri=str(item.get("contact_uri", "")),
                critical_selectors=selectors,
            )
        )

    for item in data.get("deployers", []):
        deployers.append(
            DeployerWatch(
                chain_id=int(item["chain_id"]),
                address=_validate_address(item["address"], "deployer address"),
                label=str(item["label"]),
            )
        )

    contract_keys = {(item.chain_id, item.address) for item in contracts}
    deployer_keys = {(item.chain_id, item.address) for item in deployers}
    if len(contract_keys) != len(contracts):
        raise ConfigurationError("Duplicate contract in watchlist")
    if len(deployer_keys) != len(deployers):
        raise ConfigurationError("Duplicate deployer in watchlist")
    return Watchlist(tuple(contracts), tuple(deployers))


def load_dotenv(path: Path) -> None:
    """Load simple KEY=VALUE entries without overriding the process environment."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value
