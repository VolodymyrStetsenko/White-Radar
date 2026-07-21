from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from white_radar.fingerprint import BytecodeFingerprint, simhash_similarity
from white_radar.models import (
    ContractMetadata,
    IncidentRecord,
    IncidentStatus,
    RadarEvent,
    Severity,
    stable_event_id,
    utc_now,
)

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

CREATE TABLE IF NOT EXISTS contract_profiles (
    chain_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    bytecode_sha256 TEXT NOT NULL,
    normalized_sha256 TEXT NOT NULL,
    simhash64 TEXT NOT NULL,
    bytecode_size INTEGER NOT NULL,
    normalized_size INTEGER NOT NULL,
    metadata_size INTEGER NOT NULL,
    verified INTEGER NOT NULL,
    verification_source TEXT,
    contract_name TEXT,
    is_proxy INTEGER NOT NULL,
    implementation TEXT,
    admin TEXT,
    beacon TEXT,
    first_seen_at TEXT NOT NULL,
    last_enriched_at TEXT NOT NULL,
    PRIMARY KEY (chain_id, address)
);

CREATE INDEX IF NOT EXISTS idx_profiles_normalized_hash
ON contract_profiles (chain_id, normalized_sha256);

CREATE TABLE IF NOT EXISTS identity_nodes (
    node_id TEXT PRIMARY KEY,
    chain_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT,
    metadata_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (chain_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_identity_nodes_value
ON identity_nodes (chain_id, value);

CREATE TABLE IF NOT EXISTS identity_edges (
    edge_id TEXT PRIMARY KEY,
    chain_id INTEGER NOT NULL,
    source_node_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (source_node_id) REFERENCES identity_nodes(node_id),
    FOREIGN KEY (target_node_id) REFERENCES identity_nodes(node_id)
);

CREATE INDEX IF NOT EXISTS idx_identity_edges_source
ON identity_edges (chain_id, source_node_id);

CREATE INDEX IF NOT EXISTS idx_identity_edges_target
ON identity_edges (chain_id, target_node_id);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    protocol TEXT,
    owner TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    due_at TEXT NOT NULL,
    acknowledged_at TEXT,
    closed_at TEXT,
    disposition TEXT,
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_status_due
ON incidents (status, due_at);

CREATE TABLE IF NOT EXISTS incident_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT,
    changed_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_history_case
ON incident_history (incident_id, changed_at);

CREATE TABLE IF NOT EXISTS service_heartbeats (
    service_name TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    details_json TEXT NOT NULL,
    last_error TEXT,
    PRIMARY KEY (service_name, chain_id)
);

CREATE TABLE IF NOT EXISTS abi_catalogs (
    chain_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    source TEXT NOT NULL,
    abi_sha256 TEXT NOT NULL,
    selectors_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (chain_id, address)
);

CREATE TABLE IF NOT EXISTS invariant_states (
    chain_id INTEGER NOT NULL,
    policy_address TEXT NOT NULL,
    invariant_name TEXT NOT NULL,
    status TEXT NOT NULL,
    observed_value TEXT,
    expected_value TEXT,
    block_number INTEGER NOT NULL,
    block_hash TEXT,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (chain_id, policy_address, invariant_name)
);

CREATE INDEX IF NOT EXISTS idx_invariant_states_status
ON invariant_states (status, checked_at);
"""

OPEN_INCIDENT_STATUSES = frozenset(
    {
        IncidentStatus.NEW,
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.MONITORING,
    }
)
INCIDENT_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NEW: frozenset(
        {
            IncidentStatus.ACKNOWLEDGED,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.FALSE_POSITIVE,
        }
    ),
    IncidentStatus.ACKNOWLEDGED: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.MONITORING,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        }
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.MONITORING,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        }
    ),
    IncidentStatus.MONITORING: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        }
    ),
    IncidentStatus.RESOLVED: frozenset(),
    IncidentStatus.FALSE_POSITIVE: frozenset(),
}


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

    @staticmethod
    def _incident_from_row(row: sqlite3.Row) -> IncidentRecord:
        return IncidentRecord(
            incident_id=str(row["incident_id"]),
            event_id=str(row["event_id"]),
            status=IncidentStatus(str(row["status"])),
            severity=Severity(str(row["severity"])),
            protocol=str(row["protocol"]) if row["protocol"] is not None else None,
            owner=str(row["owner"]) if row["owner"] is not None else None,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            due_at=str(row["due_at"]),
            acknowledged_at=(
                str(row["acknowledged_at"]) if row["acknowledged_at"] is not None else None
            ),
            closed_at=str(row["closed_at"]) if row["closed_at"] is not None else None,
            disposition=str(row["disposition"]) if row["disposition"] is not None else None,
        )

    def open_incident(
        self,
        event: RadarEvent,
        *,
        minimum_score: int,
        sla_minutes: int,
        protocol: str | None = None,
    ) -> IncidentRecord | None:
        """Idempotently promote a high-priority event into an auditable incident."""

        if event.score < max(0, min(100, minimum_score)):
            return None
        try:
            observed = dt.datetime.fromisoformat(event.observed_at)
        except ValueError:
            observed = dt.datetime.now(dt.UTC)
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=dt.UTC)
        created_at = observed.astimezone(dt.UTC).isoformat(timespec="seconds")
        due_at = (
            (observed + dt.timedelta(minutes=max(1, sla_minutes)))
            .astimezone(dt.UTC)
            .isoformat(timespec="seconds")
        )
        incident_id = stable_event_id("incident", event.event_id)
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO incidents(
                    incident_id, event_id, status, severity, protocol, created_at,
                    updated_at, due_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    event.event_id,
                    IncidentStatus.NEW.value,
                    event.severity.value,
                    protocol,
                    created_at,
                    created_at,
                    due_at,
                ),
            )
            if cursor.rowcount == 1:
                connection.execute(
                    """
                    INSERT INTO incident_history(
                        incident_id, from_status, to_status, actor, note, changed_at
                    ) VALUES (?, NULL, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        IncidentStatus.NEW.value,
                        "white-radar",
                        "Automatically opened from an explainable priority threshold.",
                        created_at,
                    ),
                )
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return self._incident_from_row(row) if row else None

    def incident_for_event(self, event_id: str) -> IncidentRecord | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE event_id = ?", (event_id,)
            ).fetchone()
        return self._incident_from_row(row) if row else None

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return self._incident_from_row(row) if row else None

    def list_incidents(
        self, *, status: IncidentStatus | None = None, limit: int = 50
    ) -> list[IncidentRecord]:
        query = "SELECT * FROM incidents"
        parameters: list[object] = []
        if status is not None:
            query += " WHERE status = ?"
            parameters.append(status.value)
        query += " ORDER BY due_at ASC, created_at DESC LIMIT ?"
        parameters.append(max(1, min(500, limit)))
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._incident_from_row(row) for row in rows]

    def transition_incident(
        self,
        incident_id: str,
        status: IncidentStatus,
        *,
        actor: str,
        note: str = "",
    ) -> IncidentRecord:
        normalized_actor = " ".join(actor.split())[:100]
        normalized_note = " ".join(note.split())[:2000]
        if not normalized_actor:
            raise ValueError("An incident transition requires an actor")
        now = utc_now()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if not row:
                raise ValueError(f"Unknown incident: {incident_id}")
            previous = IncidentStatus(str(row["status"]))
            if status not in INCIDENT_TRANSITIONS[previous]:
                raise ValueError(f"Invalid incident transition: {previous.value} -> {status.value}")
            acknowledged_at = (
                now
                if status
                in {
                    IncidentStatus.ACKNOWLEDGED,
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.MONITORING,
                }
                and row["acknowledged_at"] is None
                else row["acknowledged_at"]
            )
            closed_at = (
                now if status in {IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE} else None
            )
            disposition = normalized_note if closed_at and normalized_note else row["disposition"]
            owner = row["owner"] or normalized_actor
            connection.execute(
                """
                UPDATE incidents
                SET status = ?, owner = ?, updated_at = ?, acknowledged_at = ?,
                    closed_at = ?, disposition = ?
                WHERE incident_id = ?
                """,
                (
                    status.value,
                    owner,
                    now,
                    acknowledged_at,
                    closed_at,
                    disposition,
                    incident_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO incident_history(
                    incident_id, from_status, to_status, actor, note, changed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    previous.value,
                    status.value,
                    normalized_actor,
                    normalized_note or None,
                    now,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        if not updated:
            raise RuntimeError("Incident disappeared during transition")
        return self._incident_from_row(updated)

    def incident_history(self, incident_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT from_status, to_status, actor, note, changed_at
                FROM incident_history WHERE incident_id = ?
                ORDER BY history_id ASC
                """,
                (incident_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def incident_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in IncidentStatus}
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS total FROM incidents GROUP BY status"
            ).fetchall()
        for row in rows:
            counts[str(row["status"])] = int(row["total"])
        counts["open"] = sum(counts[status.value] for status in OPEN_INCIDENT_STATUSES)
        return counts

    def overdue_incidents(self, *, limit: int = 100) -> list[IncidentRecord]:
        placeholders = ",".join("?" for _ in OPEN_INCIDENT_STATUSES)
        ordered_statuses = sorted(OPEN_INCIDENT_STATUSES, key=lambda item: item.value)
        parameters: list[object] = [
            *(status.value for status in ordered_statuses),
            utc_now(),
            max(1, min(500, limit)),
        ]
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM incidents
                WHERE status IN ({placeholders}) AND due_at < ?
                ORDER BY due_at ASC LIMIT ?
                """,
                parameters,
            ).fetchall()
        return [self._incident_from_row(row) for row in rows]

    def record_heartbeat(
        self,
        *,
        service_name: str,
        chain_id: int,
        status: str = "ok",
        details: dict[str, Any] | None = None,
        last_error: str | None = None,
    ) -> None:
        normalized_service = " ".join(service_name.split())[:100]
        normalized_status = status.strip().lower()[:30]
        if not normalized_service or not normalized_status:
            raise ValueError("Heartbeat service and status are required")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO service_heartbeats(
                    service_name, chain_id, status, last_seen_at, details_json, last_error
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(service_name, chain_id) DO UPDATE SET
                    status = excluded.status,
                    last_seen_at = excluded.last_seen_at,
                    details_json = excluded.details_json,
                    last_error = excluded.last_error
                """,
                (
                    normalized_service,
                    chain_id,
                    normalized_status,
                    utc_now(),
                    json.dumps(details or {}, sort_keys=True, separators=(",", ":")),
                    (last_error or "")[:200] or None,
                ),
            )

    def get_abi_catalog(self, chain_id: int, address: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT source, abi_sha256, selectors_json, updated_at
                FROM abi_catalogs
                WHERE chain_id = ? AND address = ?
                """,
                (chain_id, address.lower()),
            ).fetchone()
        if not row:
            return None
        selectors = json.loads(str(row["selectors_json"]))
        if not isinstance(selectors, dict):
            return None
        return {
            "source": str(row["source"]),
            "abi_sha256": str(row["abi_sha256"]),
            "selectors": {str(key): str(value) for key, value in selectors.items()},
            "updated_at": str(row["updated_at"]),
        }

    def upsert_abi_catalog(
        self,
        *,
        chain_id: int,
        address: str,
        source: str,
        abi_sha256: str,
        selectors: dict[str, str],
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO abi_catalogs(
                    chain_id, address, source, abi_sha256, selectors_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, address) DO UPDATE SET
                    source = excluded.source,
                    abi_sha256 = excluded.abi_sha256,
                    selectors_json = excluded.selectors_json,
                    updated_at = excluded.updated_at
                """,
                (
                    chain_id,
                    address.lower(),
                    source,
                    abi_sha256,
                    json.dumps(selectors, sort_keys=True, separators=(",", ":")),
                    utc_now(),
                ),
            )

    def record_invariant_state(
        self,
        *,
        chain_id: int,
        policy_address: str,
        invariant_name: str,
        status: str,
        observed_value: str | None,
        expected_value: str | None,
        block_number: int,
        block_hash: str | None,
    ) -> dict[str, Any] | None:
        """Persist an invariant snapshot and return the previous state, if any."""

        with self.connect() as connection:
            previous = connection.execute(
                """
                SELECT status, observed_value, expected_value, block_number, block_hash, checked_at
                FROM invariant_states
                WHERE chain_id = ? AND policy_address = ? AND invariant_name = ?
                """,
                (chain_id, policy_address.lower(), invariant_name),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO invariant_states(
                    chain_id, policy_address, invariant_name, status, observed_value,
                    expected_value, block_number, block_hash, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, policy_address, invariant_name) DO UPDATE SET
                    status = excluded.status,
                    observed_value = excluded.observed_value,
                    expected_value = excluded.expected_value,
                    block_number = excluded.block_number,
                    block_hash = excluded.block_hash,
                    checked_at = excluded.checked_at
                """,
                (
                    chain_id,
                    policy_address.lower(),
                    invariant_name,
                    status,
                    observed_value,
                    expected_value,
                    block_number,
                    block_hash,
                    utc_now(),
                ),
            )
        return dict(previous) if previous else None

    def list_invariant_states(
        self, *, chain_id: int | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM invariant_states"
        parameters: list[object] = []
        if chain_id is not None:
            query += " WHERE chain_id = ?"
            parameters.append(chain_id)
        query += " ORDER BY checked_at DESC LIMIT ?"
        parameters.append(max(1, min(5000, limit)))
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def health_snapshot(
        self,
        *,
        stale_after_seconds: int,
        expected_services: set[tuple[str, int]] | None = None,
    ) -> dict[str, Any]:
        now = dt.datetime.now(dt.UTC)
        threshold = max(30, stale_after_seconds)
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT service_name, chain_id, status, last_seen_at, details_json, last_error
                FROM service_heartbeats ORDER BY service_name, chain_id
                """
            ).fetchall()
        services: list[dict[str, Any]] = []
        for row in rows:
            try:
                seen = dt.datetime.fromisoformat(str(row["last_seen_at"]))
                if seen.tzinfo is None:
                    seen = seen.replace(tzinfo=dt.UTC)
                age_seconds = max(0, int((now - seen.astimezone(dt.UTC)).total_seconds()))
            except ValueError:
                age_seconds = threshold + 1
            stale = age_seconds > threshold
            status = str(row["status"])
            services.append(
                {
                    "service_name": str(row["service_name"]),
                    "chain_id": int(row["chain_id"]),
                    "status": status,
                    "last_seen_at": str(row["last_seen_at"]),
                    "age_seconds": age_seconds,
                    "stale": stale,
                    "healthy": status == "ok" and not stale,
                    "details": json.loads(str(row["details_json"])),
                    "last_error": row["last_error"],
                }
            )
        observed = {(str(item["service_name"]), int(item["chain_id"])) for item in services}
        for service_name, chain_id in sorted((expected_services or set()) - observed):
            services.append(
                {
                    "service_name": service_name,
                    "chain_id": chain_id,
                    "status": "missing",
                    "last_seen_at": None,
                    "age_seconds": None,
                    "stale": True,
                    "healthy": False,
                    "details": {},
                    "last_error": "No heartbeat has been recorded.",
                }
            )
        services.sort(key=lambda item: (str(item["service_name"]), int(item["chain_id"])))
        return {
            "ok": bool(services) and all(bool(item["healthy"]) for item in services),
            "stale_after_seconds": threshold,
            "services": services,
        }

    def upsert_contract_profile(
        self,
        *,
        chain_id: int,
        address: str,
        fingerprint: BytecodeFingerprint,
        metadata: ContractMetadata,
        observed_at: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO contract_profiles(
                    chain_id, address, bytecode_sha256, normalized_sha256, simhash64,
                    bytecode_size, normalized_size, metadata_size, verified,
                    verification_source, contract_name, is_proxy, implementation,
                    admin, beacon, first_seen_at, last_enriched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, address) DO UPDATE SET
                    bytecode_sha256 = excluded.bytecode_sha256,
                    normalized_sha256 = excluded.normalized_sha256,
                    simhash64 = excluded.simhash64,
                    bytecode_size = excluded.bytecode_size,
                    normalized_size = excluded.normalized_size,
                    metadata_size = excluded.metadata_size,
                    verified = excluded.verified,
                    verification_source = excluded.verification_source,
                    contract_name = excluded.contract_name,
                    is_proxy = excluded.is_proxy,
                    implementation = excluded.implementation,
                    admin = excluded.admin,
                    beacon = excluded.beacon,
                    last_enriched_at = excluded.last_enriched_at
                """,
                (
                    chain_id,
                    address.lower(),
                    fingerprint.raw_sha256,
                    fingerprint.normalized_sha256,
                    fingerprint.simhash64,
                    fingerprint.bytecode_size,
                    fingerprint.normalized_size,
                    fingerprint.metadata_size,
                    int(metadata.verified),
                    metadata.verification_source,
                    metadata.contract_name,
                    int(metadata.is_proxy),
                    metadata.implementation,
                    metadata.admin,
                    metadata.beacon,
                    observed_at,
                    observed_at,
                ),
            )

    def similar_contracts(
        self,
        *,
        chain_id: int,
        address: str,
        fingerprint: BytecodeFingerprint,
        minimum_similarity: float = 0.84,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        lower_size = max(0, int(fingerprint.normalized_size * 0.7))
        upper_size = max(lower_size, int(fingerprint.normalized_size * 1.3) + 1)
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT address, normalized_sha256, simhash64, normalized_size,
                       contract_name, is_proxy, implementation, last_enriched_at
                FROM contract_profiles
                WHERE chain_id = ? AND address != ?
                  AND normalized_size BETWEEN ? AND ?
                ORDER BY last_enriched_at DESC
                LIMIT 2000
                """,
                (chain_id, address.lower(), lower_size, upper_size),
            ).fetchall()
        matches: list[dict[str, Any]] = []
        for row in rows:
            exact = str(row["normalized_sha256"]) == fingerprint.normalized_sha256
            similarity = (
                1.0 if exact else simhash_similarity(str(row["simhash64"]), fingerprint.simhash64)
            )
            if similarity < minimum_similarity:
                continue
            item = dict(row)
            item["exact_normalized_match"] = exact
            item["similarity"] = round(similarity, 4)
            matches.append(item)
        matches.sort(
            key=lambda item: (
                bool(item["exact_normalized_match"]),
                float(item["similarity"]),
                str(item["last_enriched_at"]),
            ),
            reverse=True,
        )
        return matches[:limit]

    def profiles_due_for_refresh(
        self,
        *,
        chain_id: int,
        min_age_minutes: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        threshold = (
            dt.datetime.now(dt.UTC) - dt.timedelta(minutes=max(0, min_age_minutes))
        ).isoformat()
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT cp.*, d.deployer_address, d.tx_hash, d.block_number
                FROM contract_profiles AS cp
                LEFT JOIN deployments AS d
                  ON d.chain_id = cp.chain_id AND d.address = cp.address
                WHERE cp.chain_id = ? AND cp.last_enriched_at <= ?
                ORDER BY cp.last_enriched_at ASC, cp.address ASC
                LIMIT ?
                """,
                (chain_id, threshold, max(1, min(500, limit))),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _identity_id(*parts: object) -> str:
        material = "|".join(str(part).lower() for part in parts)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

    def upsert_identity_node(
        self,
        *,
        chain_id: int,
        kind: str,
        value: str,
        label: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        normalized = value.lower()
        node_id = self._identity_id("node", chain_id, kind, normalized)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO identity_nodes(
                    node_id, chain_id, kind, value, label, metadata_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, kind, value) DO UPDATE SET
                    label = COALESCE(excluded.label, identity_nodes.label),
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    node_id,
                    chain_id,
                    kind,
                    normalized,
                    label,
                    json.dumps(metadata or {}, sort_keys=True, separators=(",", ":")),
                    utc_now(),
                ),
            )
        return node_id

    def upsert_identity_edge(
        self,
        *,
        chain_id: int,
        source_node_id: str,
        relation: str,
        target_node_id: str,
        evidence: dict[str, Any],
        observed_at: str,
    ) -> str:
        edge_id = self._identity_id("edge", chain_id, source_node_id, relation, target_node_id)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO identity_edges(
                    edge_id, chain_id, source_node_id, relation, target_node_id,
                    evidence_json, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(edge_id) DO UPDATE SET
                    evidence_json = excluded.evidence_json,
                    observed_at = excluded.observed_at
                """,
                (
                    edge_id,
                    chain_id,
                    source_node_id,
                    relation,
                    target_node_id,
                    json.dumps(evidence, sort_keys=True, separators=(",", ":")),
                    observed_at,
                ),
            )
        return edge_id

    def identity_neighborhood(
        self, *, chain_id: int, value: str, depth: int = 2
    ) -> dict[str, list[dict[str, Any]]]:
        with self.connect() as connection:
            seeds = connection.execute(
                "SELECT node_id FROM identity_nodes WHERE chain_id = ? AND value = ?",
                (chain_id, value.lower()),
            ).fetchall()
            frontier = {str(row[0]) for row in seeds}
            seen_nodes = set(frontier)
            seen_edges: dict[str, sqlite3.Row] = {}
            for _ in range(max(0, min(4, depth))):
                if not frontier:
                    break
                placeholders = ",".join("?" for _ in frontier)
                params: list[object] = [chain_id, *sorted(frontier), *sorted(frontier)]
                rows = connection.execute(
                    f"""
                    SELECT * FROM identity_edges
                    WHERE chain_id = ? AND (
                        source_node_id IN ({placeholders}) OR
                        target_node_id IN ({placeholders})
                    )
                    """,
                    params,
                ).fetchall()
                next_frontier: set[str] = set()
                for row in rows:
                    seen_edges[str(row["edge_id"])] = row
                    next_frontier.add(str(row["source_node_id"]))
                    next_frontier.add(str(row["target_node_id"]))
                next_frontier -= seen_nodes
                seen_nodes.update(next_frontier)
                frontier = next_frontier
            if seen_nodes:
                placeholders = ",".join("?" for _ in seen_nodes)
                node_rows = connection.execute(
                    f"SELECT * FROM identity_nodes WHERE node_id IN ({placeholders})",
                    sorted(seen_nodes),
                ).fetchall()
            else:
                node_rows = []
        nodes: list[dict[str, Any]] = []
        for row in node_rows:
            item = dict(row)
            item["metadata"] = json.loads(str(item.pop("metadata_json")))
            nodes.append(item)
        edges: list[dict[str, Any]] = []
        for row in seen_edges.values():
            item = dict(row)
            item["evidence"] = json.loads(str(item.pop("evidence_json")))
            edges.append(item)
        nodes.sort(key=lambda item: (str(item["kind"]), str(item["value"])))
        edges.sort(key=lambda item: str(item["edge_id"]))
        return {"nodes": nodes, "edges": edges}

    def events_since(self, *, hours: int, limit: int = 1000) -> list[RadarEvent]:
        since = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=max(1, hours))).isoformat()
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM events
                WHERE observed_at >= ?
                ORDER BY observed_at DESC, rowid DESC
                LIMIT ?
                """,
                (since, max(1, min(5000, limit))),
            ).fetchall()
        return [RadarEvent.from_dict(json.loads(str(row[0]))) for row in rows]

    def intelligence_counts(self) -> dict[str, int]:
        with self.connect() as connection:
            profiles = int(
                connection.execute("SELECT COUNT(*) FROM contract_profiles").fetchone()[0]
            )
            nodes = int(connection.execute("SELECT COUNT(*) FROM identity_nodes").fetchone()[0])
            edges = int(connection.execute("SELECT COUNT(*) FROM identity_edges").fetchone()[0])
            abi_catalogs = int(
                connection.execute("SELECT COUNT(*) FROM abi_catalogs").fetchone()[0]
            )
            invariants = int(
                connection.execute("SELECT COUNT(*) FROM invariant_states").fetchone()[0]
            )
        return {
            "profiles": profiles,
            "identity_nodes": nodes,
            "identity_edges": edges,
            "abi_catalogs": abi_catalogs,
            "invariant_states": invariants,
        }

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
