from __future__ import annotations

import dataclasses
from typing import Any

from white_radar.config import ADDRESS_RE


@dataclasses.dataclass(frozen=True, slots=True)
class InternalCreation:
    address: str
    creator: str
    creation_type: str
    depth: int


def internal_creations(trace: dict[str, Any]) -> tuple[InternalCreation, ...]:
    """Extract successful nested CREATE/CREATE2 frames from a callTracer tree."""

    found: list[InternalCreation] = []

    def visit(frame: object, depth: int) -> None:
        if not isinstance(frame, dict):
            return
        frame_type = str(frame.get("type") or "").upper()
        address = str(frame.get("to") or "").lower()
        creator = str(frame.get("from") or "").lower()
        if (
            depth > 0
            and frame_type in {"CREATE", "CREATE2"}
            and not frame.get("error")
            and ADDRESS_RE.fullmatch(address)
            and ADDRESS_RE.fullmatch(creator)
        ):
            found.append(InternalCreation(address, creator, frame_type, depth))
        for child in frame.get("calls") or []:
            visit(child, depth + 1)

    visit(trace, 0)
    # A malformed provider response may repeat a frame. Keep deterministic order.
    unique: dict[tuple[str, str, str], InternalCreation] = {}
    for item in found:
        unique.setdefault((item.address, item.creator, item.creation_type), item)
    return tuple(unique.values())
