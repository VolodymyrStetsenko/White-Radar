from __future__ import annotations

import unittest

from tests.common import ETHEREUM, sample_event
from white_radar.models import IncidentRecord, IncidentStatus
from white_radar.reporting import render_digest, render_incident_report


class ReportingTests(unittest.TestCase):
    def test_incident_report_contains_evidence_and_safety_boundary(self) -> None:
        graph = {
            "nodes": [{"node_id": "n1"}, {"node_id": "n2"}],
            "edges": [
                {
                    "source_node_id": "n1",
                    "relation": "DEPLOYED",
                    "target_node_id": "n2",
                }
            ],
        }
        report = render_incident_report(sample_event(), ETHEREUM, graph=graph)
        self.assertIn("# White Radar case case-123", report)
        self.assertIn("unverified security signal", report)
        self.assertIn("## Identity neighborhood", report)
        self.assertIn("Do not replay", report)
        self.assertIn("etherscan.io", report)

    def test_digest_summarizes_and_escapes_cases(self) -> None:
        event = sample_event()
        digest = render_digest([event], {"ethereum": ETHEREUM}, hours=24)
        self.assertIn("WHITE RADAR DIGEST", digest)
        self.assertIn("High 1", digest)
        self.assertIn("Ethereum: 1", digest)
        self.assertIn("case-123", digest)
        empty = render_digest([], {"ethereum": ETHEREUM}, hours=0)
        self.assertIn("No cases", empty)

    def test_report_and_digest_include_incident_workflow(self) -> None:
        event = sample_event()
        incident = IncidentRecord(
            incident_id="incident-1",
            event_id=event.event_id,
            status=IncidentStatus.NEW,
            severity=event.severity,
            protocol="Example",
            owner=None,
            created_at=event.observed_at,
            updated_at=event.observed_at,
            due_at="2026-07-20T12:15:00+00:00",
        )
        report = render_incident_report(event, ETHEREUM, incident=incident)
        self.assertIn("## Incident workflow", report)
        self.assertIn("incident-1", report)
        digest = render_digest(
            [event],
            {"ethereum": ETHEREUM},
            hours=24,
            incidents=[incident],
            overdue_incident_ids={incident.incident_id},
        )
        self.assertIn("Open 1 · Overdue 1", digest)


if __name__ == "__main__":
    unittest.main()
