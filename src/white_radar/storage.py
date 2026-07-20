from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Any

from white_radar.models import RadarEvent, utc_now

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS chain_state (
    chain_id INTEGER PRIMARY KEY,
    last_confirmed_block INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deployments (
    chain_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    deployer_address TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    contract_name TEXT,
    is_proxy INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (chain_id, address)
);

CREATE INDEX IF NOT EXISTS idx_deployments_deployer
ON deployments (chain_id, deployer_address, observed_at DESC);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    observed_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    chain TEXT NOT NULL,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    subject_address TEXT,
    tx_hash TEXT,
    block_number INTEGER,
    payload_json TEXT NOT NULL,
    alerted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_recent
ON events (observed_at DESC);
"""


class RadarStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    def get_cursor(self, chain_id: int) -> int | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT last_confirmed_block FROM chain_state WHERE chain_id = ?",
                (chain_id,),
            ).fetchone()
        return int(row[0]) if row else None

    def set_cursor(self, chain_id: int, block_number: int) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO chain_state(chain_id, last_confirmed_block, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(chain_id) DO UPDATE SET
                    last_confirmed_block = excluded.last_confirmed_block,
                    updated_at = excluded.updated_at
                """,
                (chain_id, block_number, utc_now()),
            )

    def add_deployment(
        self,
        *,
        chain_id: int,
        address: str,
        deployer_address: str,
        tx_hash: str,
        block_number: int,
        observed_at: str,
        contract_name: str | None,
        is_proxy: bool,
    ) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO deployments(
                    chain_id, address, deployer_address, tx_hash, block_number,
                    observed_at, contract_name, is_proxy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_id,
                    address.lower(),
                    deployer_address.lower(),
                    tx_hash.lower(),
                    block_number,
                    observed_at,
                    contract_name,
                    int(is_proxy),
                ),
            )
            return cursor.rowcount == 1

    def related_deployments(
        self,
        chain_id: int,
        deployer_address: str,
        *,
        hours: int = 24,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        since = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours)).isoformat()
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT address, tx_hash, block_number, observed_at, contract_name, is_proxy
                FROM deployments
                WHERE chain_id = ? AND deployer_address = ? AND observed_at >= ?
                ORDER BY block_number DESC
                LIMIT ?
                """,
                (chain_id, deployer_address.lower(), since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_event(self, event: RadarEvent) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO events(
                    event_id, observed_at, event_type, chain_id, chain, score, severity,
                    subject_address, tx_hash, block_number, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.observed_at,
                    event.event_type,
                    event.chain_id,
                    event.chain,
                    event.score,
                    event.severity.value,
                    event.subject_address,
                    event.tx_hash,
                    event.block_number,
                    event.to_json(),
                ),
            )
            return cursor.rowcount == 1

    def mark_alerted(self, event_id: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE events SET alerted_at = ? WHERE event_id = ?",
                (utc_now(), event_id),
            )

    def was_alerted(self, event_id: str) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT alerted_at FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return bool(row and row[0])

    def counts(self) -> dict[str, int]:
        with self.connect() as connection:
            events = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            deployments = int(connection.execute("SELECT COUNT(*) FROM deployments").fetchone()[0])
            alerts = int(
                connection.execute(
                    "SELECT COUNT(*) FROM events WHERE alerted_at IS NOT NULL"
                ).fetchone()[0]
            )
        return {"events": events, "deployments": deployments, "alerts": alerts}

    def cursors(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT chain_id, last_confirmed_block, updated_at FROM chain_state"
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_events(self, limit: int = 20) -> list[RadarEvent]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM events ORDER BY observed_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [RadarEvent.from_dict(json.loads(str(row[0]))) for row in rows]

    def pending_alerts(self, chain_id: int, limit: int = 100) -> list[RadarEvent]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM events
                WHERE chain_id = ? AND alerted_at IS NULL
                ORDER BY observed_at ASC, rowid ASC
                LIMIT ?
                """,
                (chain_id, limit),
            ).fetchall()
        return [RadarEvent.from_dict(json.loads(str(row[0]))) for row in rows]

    def export_jsonl(self, destination: Path) -> int:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM events ORDER BY observed_at ASC"
            ).fetchall()
        with destination.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(str(row[0]) + "\n")
        return len(rows)
