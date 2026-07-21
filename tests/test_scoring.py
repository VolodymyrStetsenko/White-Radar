from __future__ import annotations

import unittest

from tests.common import ETHEREUM
from white_radar.models import ContractMetadata
from white_radar.scoring import score_deployment, score_pending, score_profile_change


class ScoringTests(unittest.TestCase):
    def test_explainable_priority_for_watched_proxy_cluster(self) -> None:
        result = score_deployment(
            chain=ETHEREUM,
            metadata=ContractMetadata(
                verified=True,
                verification_source="Sourcify",
                contract_name="Pool",
                is_proxy=True,
                implementation="0x" + "11" * 20,
            ),
            bytecode_size=15_000,
            cluster_size=6,
            watched_deployer_label="Example release deployer",
        )
        self.assertEqual(result.score, 100)
        self.assertGreaterEqual(len(result.reasons), 6)
        self.assertIn("authorized watchlist", " ".join(result.reasons))

    def test_pending_action_forbids_replay(self) -> None:
        result = score_pending(
            protocol="Example",
            critical_selector=True,
            native_value_wei=1,
        )
        self.assertGreaterEqual(result.score, 80)
        self.assertIn("Do not replay", result.recommended_action)
        self.assertIn("front-run", result.recommended_action)

    def test_runtime_profile_drift_is_high_priority(self) -> None:
        result = score_profile_change(
            changed_fields=frozenset({"bytecode_sha256", "implementation"}),
            watched_protocol="Example",
        )
        self.assertEqual(result.score, 100)
        self.assertGreaterEqual(result.confidence, 0.95)
        self.assertIn("runtime bytecode", " ".join(result.reasons))


if __name__ == "__main__":
    unittest.main()
