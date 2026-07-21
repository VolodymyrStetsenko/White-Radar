from __future__ import annotations

import dataclasses

from white_radar.models import ChainConfig, ContractMetadata, severity_for_score


@dataclasses.dataclass(frozen=True, slots=True)
class ScoreResult:
    score: int
    confidence: float
    reasons: tuple[str, ...]
    recommended_action: str


def score_deployment(
    *,
    chain: ChainConfig,
    metadata: ContractMetadata,
    bytecode_size: int,
    cluster_size: int,
    watched_deployer_label: str | None,
    exact_match_count: int = 0,
    similar_count: int = 0,
) -> ScoreResult:
    score = 10
    confidence = 0.55
    reasons = ["Top-level contract creation was confirmed in a finalized scan range."]

    if not chain.is_testnet:
        score += 10
        reasons.append("Deployment occurred on a production network.")
    if metadata.verified:
        score += 15
        confidence += 0.15
        reasons.append(f"Source metadata is verified via {metadata.verification_source}.")
    else:
        reasons.append("Source metadata is not verified yet; identity is lower confidence.")
    if metadata.contract_name:
        score += 5
        reasons.append(f"Explorer metadata identifies {metadata.contract_name}.")
    if metadata.is_proxy:
        score += 15
        confidence += 0.1
        reasons.append("EIP-1967 proxy state was detected and linked to its control plane.")
    if bytecode_size >= 10_000:
        score += 5
        reasons.append("Runtime bytecode is large enough to warrant structured review.")
    if cluster_size >= 2:
        score += 10
        reasons.append(
            f"The deployer created {cluster_size} related contracts in the last 24 hours."
        )
    if cluster_size >= 5:
        score += 10
        reasons.append("Deployment activity forms a high-volume release cluster.")
    if exact_match_count:
        score += 10
        reasons.append(
            f"Normalized runtime bytecode exactly matches {exact_match_count} known contract(s)."
        )
    elif similar_count:
        score += 5
        reasons.append(
            f"Runtime bytecode is structurally similar to {similar_count} known contract(s)."
        )
    if watched_deployer_label:
        score += 35
        confidence += 0.15
        reasons.append(f"The deployer is on the authorized watchlist: {watched_deployer_label}.")

    score = min(100, score)
    confidence = min(0.98, confidence)
    severity = severity_for_score(score)
    if watched_deployer_label or severity.value in {"high", "critical"}:
        action = (
            "Review the transaction, linked contracts, published scope, and release notes. "
            "Escalate privately only through the protocol's authorized security channel."
        )
    elif metadata.is_proxy or cluster_size >= 2:
        action = (
            "Correlate the deployment cluster with the project's official repository and "
            "published security scope before starting any deeper analysis."
        )
    else:
        action = "No immediate action. Retain as evidence and wait for additional identity signals."
    return ScoreResult(score, confidence, tuple(reasons), action)


def score_upgrade(*, watched_protocol: str | None, global_scan: bool) -> ScoreResult:
    score = 45 if global_scan else 55
    confidence = 0.9
    reasons = ["A standard proxy control-plane event was emitted on-chain."]
    if watched_protocol:
        score = 85
        reasons.append(f"The proxy belongs to the authorized watchlist: {watched_protocol}.")
        action = (
            "Immediately verify the implementation, release commit, storage-layout checks, "
            "and the protocol's approved incident procedure."
        )
    else:
        reasons.append("The proxy is not currently associated with an authorized watchlist entry.")
        action = "Retain the signal and identify the owner before any security research."
    return ScoreResult(score, confidence, tuple(reasons), action)


def score_pending(
    *,
    protocol: str,
    critical_selector: bool,
    native_value_wei: int,
) -> ScoreResult:
    score = 60
    confidence = 0.65
    reasons = [f"A pending transaction targets watched protocol {protocol}."]
    if critical_selector:
        score += 20
        confidence += 0.1
        reasons.append("The selector is marked critical by the protocol-specific watchlist.")
    if native_value_wei > 0:
        score += 5
        reasons.append("The transaction includes native asset value.")
    action = (
        "Observe and preserve evidence. Do not replay, replace, front-run, or otherwise "
        "broadcast a competing transaction. Use the authorized incident channel."
    )
    return ScoreResult(min(100, score), min(0.95, confidence), tuple(reasons), action)


def score_profile_change(
    *,
    changed_fields: frozenset[str],
    watched_protocol: str | None,
) -> ScoreResult:
    """Prioritize evidence-backed drift without claiming malicious intent."""

    score = 25
    confidence = 0.9
    reasons: list[str] = []
    control_plane = changed_fields & {"implementation", "admin", "beacon"}
    if "bytecode_sha256" in changed_fields or "normalized_sha256" in changed_fields:
        score = max(score, 90)
        confidence = 0.98
        reasons.append("The observed runtime bytecode fingerprint changed.")
    if control_plane:
        score = max(score, 80)
        reasons.append(
            "Proxy control-plane state changed: " + ", ".join(sorted(control_plane)) + "."
        )
    if "verified" in changed_fields:
        reasons.append("Explorer verification status changed after the initial observation.")
    if "contract_name" in changed_fields:
        reasons.append("The explorer-reported contract identity changed.")
    if watched_protocol:
        score = min(100, score + 10)
        reasons.append(f"The contract is in the authorized watchlist: {watched_protocol}.")
    if not reasons:
        reasons.append("Stored contract intelligence changed during scheduled re-enrichment.")
    action = (
        "Compare the new state with the protocol's approved release, governance, and incident "
        "records. Validate through independent public RPC and explorer sources, then use the "
        "authorized private security channel if the change is unexpected."
    )
    return ScoreResult(score, confidence, tuple(reasons), action)
