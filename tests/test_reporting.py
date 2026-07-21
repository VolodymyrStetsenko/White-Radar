from __future__ import annotations

import unittest

from tests.common import ETHEREUM, sample_event
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


if __name__ == "__main__":
    unittest.main()
