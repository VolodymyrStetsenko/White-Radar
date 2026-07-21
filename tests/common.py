from __future__ import annotations

from pathlib import Path

from white_radar.config import AppConfig, EnrichmentConfig, Settings, TelegramConfig
from white_radar.models import ChainConfig, RadarEvent, Severity

ETHEREUM = ChainConfig(
    name="ethereum",
    display_name="Ethereum",
    chain_id=1,
    enabled=True,
    is_testnet=False,
    rpc_http_env="RPC_ETHEREUM_HTTP",
    rpc_ws_env="RPC_ETHEREUM_WS",
    explorer_url="https://etherscan.io",
    confirmations=2,
    initial_lookback_blocks=2,
    max_blocks_per_cycle=10,
    monitor_global_upgrades=False,
)


def settings_for(root: Path, *, telegram_enabled: bool = False) -> Settings:
    return Settings(
        root=root,
        app=AppConfig(
            database_path=root / "radar.sqlite3",
            watchlist_path=root / "watchlist.toml",
            policy_path=root / "policies.toml",
            poll_interval_seconds=20,
            request_timeout_seconds=2,
            request_retries=1,
            incident_minimum_score=70,
            incident_sla_minutes=30,
            heartbeat_stale_after_seconds=120,
            log_level="INFO",
            dry_run=True,
        ),
        telegram=TelegramConfig(
            enabled=telegram_enabled,
            minimum_score=60,
            send_testnet_alerts=False,
        ),
        enrichment=EnrichmentConfig(sourcify_enabled=False, etherscan_enabled=False),
        chains=(ETHEREUM,),
    )


def sample_event() -> RadarEvent:
    return RadarEvent(
        event_id="case-123",
        observed_at="2026-07-20T12:00:00+00:00",
        event_type="contract_deployment",
        title="New contract deployment",
        summary="Pool deployed on Ethereum.",
        chain="ethereum",
        chain_id=1,
        score=75,
        severity=Severity.HIGH,
        confidence=0.9,
        reasons=("Verified source metadata.", "Related deployment cluster detected."),
        recommended_action="Review the release evidence and protocol inventory.",
        subject_address="0x1111111111111111111111111111111111111111",
        deployer_address="0x2222222222222222222222222222222222222222",
        tx_hash="0x" + "33" * 32,
        block_number=20_000_000,
        evidence={"transaction": "https://etherscan.io/tx/0x33"},
        metadata={
            "contract_name": "Pool",
            "verification_source": "Sourcify",
            "bytecode_size": 12_345,
            "deployer_cluster_size": 3,
            "is_proxy": True,
            "implementation": "0x4444444444444444444444444444444444444444",
            "related_contracts": [
                {
                    "address": "0x5555555555555555555555555555555555555555",
                    "contract_name": "Verifier",
                    "block_number": 19_999_999,
                }
            ],
        },
    )
