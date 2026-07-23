from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from tests.common import sample_event
from white_radar.fingerprint import fingerprint_bytecode
from white_radar.models import ContractMetadata, IncidentStatus, utc_now
from white_radar.storage import RadarStore


class StorageTests(unittest.TestCase):
    def test_events_and_deployments_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RadarStore(Path(directory) / "radar.sqlite3")
            store.initialize()
            event = sample_event()
            self.assertTrue(store.add_event(event))
            self.assertFalse(store.add_event(event))
            self.assertTrue(
                store.add_deployment(
                    chain_id=1,
                    address=event.subject_address or "",
                    deployer_address=event.deployer_address or "",
                    tx_hash=event.tx_hash or "",
                    block_number=event.block_number or 0,
                    observed_at=event.observed_at,
                    contract_name="Pool",
                    is_proxy=True,
                )
            )
            self.assertFalse(
                store.add_deployment(
                    chain_id=1,
                    address=event.subject_address or "",
                    deployer_address=event.deployer_address or "",
                    tx_hash=event.tx_hash or "",
                    block_number=event.block_number or 0,
                    observed_at=event.observed_at,
                    contract_name="Pool",
                    is_proxy=True,
                )
            )
            self.assertEqual(store.counts(), {"events": 1, "deployments": 1, "alerts": 0})

    def test_cursor_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RadarStore(root / "radar.sqlite3")
            store.initialize()
            store.set_cursor(1, 123)
            self.assertEqual(store.get_cursor(1), 123)
            store.add_event(sample_event())
            destination = root / "events.jsonl"
            self.assertEqual(store.export_jsonl(destination), 1)
            self.assertIn("case-123", destination.read_text(encoding="utf-8"))

    def test_profiles_similarity_identity_graph_and_digest_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RadarStore(Path(directory) / "radar.sqlite3")
            store.initialize()
            first = fingerprint_bytecode("0x" + "6001600055" * 100)
            second = fingerprint_bytecode("0x" + "6001600055" * 100)
            metadata = ContractMetadata(verified=True, contract_name="Pool")
            now = utc_now()
            store.upsert_contract_profile(
                chain_id=1,
                address="0x" + "11" * 20,
                fingerprint=first,
                metadata=metadata,
                observed_at=now,
            )
            matches = store.similar_contracts(
                chain_id=1,
                address="0x" + "22" * 20,
                fingerprint=second,
            )
            self.assertEqual(len(matches), 1)
            self.assertTrue(matches[0]["exact_normalized_match"])

            source = store.upsert_identity_node(chain_id=1, kind="deployer", value="0x" + "aa" * 20)
            target = store.upsert_identity_node(
                chain_id=1,
                kind="contract",
                value="0x" + "11" * 20,
                metadata={"verified": True},
            )
            edge = store.upsert_identity_edge(
                chain_id=1,
                source_node_id=source,
                relation="DEPLOYED",
                target_node_id=target,
                evidence={"transaction": "0x1"},
                observed_at=now,
            )
            self.assertEqual(
                store.upsert_identity_edge(
                    chain_id=1,
                    source_node_id=source,
                    relation="DEPLOYED",
                    target_node_id=target,
                    evidence={"transaction": "0x2"},
                    observed_at=now,
                ),
                edge,
            )
            graph = store.identity_neighborhood(chain_id=1, value="0x" + "11" * 20, depth=2)
            self.assertEqual(len(graph["nodes"]), 2)
            self.assertEqual(graph["edges"][0]["evidence"]["transaction"], "0x2")
            self.assertEqual(
                store.identity_neighborhood(chain_id=1, value="missing"), {"nodes": [], "edges": []}
            )

            event = dataclasses.replace(sample_event(), observed_at=now)
            store.add_event(event)
            self.assertEqual(store.events_since(hours=1), [event])
            self.assertEqual(
                store.intelligence_counts(),
                {
                    "profiles": 1,
                    "identity_nodes": 2,
                    "identity_edges": 1,
                    "abi_catalogs": 0,
                    "invariant_states": 0,
                    "pending_telemetry_observations": 0,
                    "pending_telemetry_buckets": 0,
                },
            )
            due = store.profiles_due_for_refresh(
                chain_id=1,
                min_age_minutes=0,
                limit=10,
            )
            self.assertEqual([item["address"] for item in due], ["0x" + "11" * 20])

    def test_incident_lifecycle_sla_and_service_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RadarStore(Path(directory) / "radar.sqlite3")
            store.initialize()
            event = sample_event()
            store.add_event(event)
            incident = store.open_incident(
                event,
                minimum_score=70,
                sla_minutes=15,
                protocol="Example",
            )
            self.assertIsNotNone(incident)
            assert incident is not None
            self.assertEqual(incident.status, IncidentStatus.NEW)
            self.assertEqual(store.open_incident(event, minimum_score=70, sla_minutes=15), incident)
            self.assertEqual(len(store.incident_history(incident.incident_id)), 1)
            self.assertEqual(len(store.overdue_incidents()), 1)

            acknowledged = store.transition_incident(
                incident.incident_id,
                IncidentStatus.ACKNOWLEDGED,
                actor="operator",
                note="Evidence review started.",
            )
            self.assertEqual(acknowledged.owner, "operator")
            resolved = store.transition_incident(
                incident.incident_id,
                IncidentStatus.RESOLVED,
                actor="operator",
                note="Expected release confirmed.",
            )
            self.assertIsNotNone(resolved.closed_at)
            self.assertEqual(store.incident_counts()["open"], 0)
            self.assertEqual(len(store.incident_history(incident.incident_id)), 3)
            with self.assertRaises(ValueError):
                store.transition_incident(
                    incident.incident_id,
                    IncidentStatus.INVESTIGATING,
                    actor="operator",
                )

            store.record_heartbeat(
                service_name="confirmed_scanner",
                chain_id=1,
                details={"chain": "ethereum"},
            )
            healthy = store.health_snapshot(stale_after_seconds=120)
            self.assertTrue(healthy["ok"])
            self.assertEqual(healthy["services"][0]["details"]["chain"], "ethereum")
            store.record_heartbeat(
                service_name="confirmed_scanner",
                chain_id=1,
                status="degraded",
                last_error="TimeoutError",
            )
            degraded = store.health_snapshot(stale_after_seconds=120)
            self.assertFalse(degraded["ok"])
            self.assertEqual(degraded["services"][0]["last_error"], "TimeoutError")

    def test_abi_catalog_and_invariant_state_are_upserted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RadarStore(Path(directory) / "radar.sqlite3")
            store.initialize()
            address = "0x" + "11" * 20
            store.upsert_abi_catalog(
                chain_id=1,
                address=address,
                source="Etherscan",
                abi_sha256="a" * 64,
                selectors={"0x18160ddd": "totalSupply()"},
            )
            catalog = store.get_abi_catalog(1, address)
            self.assertIsNotNone(catalog)
            assert catalog is not None
            self.assertEqual(catalog["selectors"]["0x18160ddd"], "totalSupply()")

            previous = store.record_invariant_state(
                chain_id=1,
                policy_address=address,
                invariant_name="Supply ceiling",
                status="ok",
                observed_value="100",
                expected_value="100",
                block_number=100,
                block_hash="0x" + "aa" * 32,
            )
            self.assertIsNone(previous)
            previous = store.record_invariant_state(
                chain_id=1,
                policy_address=address,
                invariant_name="Supply ceiling",
                status="violated",
                observed_value="101",
                expected_value="100",
                block_number=101,
                block_hash="0x" + "bb" * 32,
            )
            self.assertIsNotNone(previous)
            assert previous is not None
            self.assertEqual(previous["status"], "ok")
            self.assertEqual(store.list_invariant_states(chain_id=1)[0]["status"], "violated")
            self.assertEqual(store.intelligence_counts()["abi_catalogs"], 1)
            self.assertEqual(store.intelligence_counts()["invariant_states"], 1)


if __name__ == "__main__":
    unittest.main()
