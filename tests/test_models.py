from __future__ import annotations

import unittest

from tests.common import sample_event
from white_radar.models import RadarEvent, Severity, severity_for_score, stable_event_id


class ModelTests(unittest.TestCase):
    def test_severity_bands(self) -> None:
        self.assertEqual(severity_for_score(0), Severity.INFORMATIONAL)
        self.assertEqual(severity_for_score(30), Severity.LOW)
        self.assertEqual(severity_for_score(50), Severity.MEDIUM)
        self.assertEqual(severity_for_score(70), Severity.HIGH)
        self.assertEqual(severity_for_score(85), Severity.CRITICAL)

    def test_event_round_trip_and_stable_id(self) -> None:
        event = sample_event()
        self.assertEqual(RadarEvent.from_dict(event.to_dict()), event)
        self.assertEqual(stable_event_id("A", 1), stable_event_id("a", 1))


if __name__ == "__main__":
    unittest.main()
