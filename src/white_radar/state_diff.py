from __future__ import annotations

import dataclasses
import hashlib
import re
from typing import Any

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
MAX_STATE_ACCOUNTS = 512
MAX_STORAGE_CHANGES = 8_192
SOURCE = "debug_traceTransaction:prestateTracer:diffMode"


@dataclasses.dataclass(frozen=True, slots=True)
class StorageChange:
    slot: str
    before: str | None
    after: str | None

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class AccountStateChange:
    address: str
    change_type: str
    balance_before_wei: str | None
    balance_after_wei: str | None
    nonce_before: int | None
    nonce_after: int | None
    code_before_bytes: int | None
    code_after_bytes: int | None
    code_before_sha256: str | None
    code_after_sha256: str | None
    storage_changes: tuple[StorageChange, ...]

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class StateDiff:
    source: str
    accounts: tuple[AccountStateChange, ...]
    storage_change_count: int
    truncated: bool
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "accounts": [item.to_dict() for item in self.accounts],
            "storage_change_count": self.storage_change_count,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
        }


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _quantity(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


def _balance(value: object) -> str | None:
    parsed = _quantity(value)
    return str(parsed) if parsed is not None else None


def _code_evidence(value: object) -> tuple[int | None, str | None]:
    encoded = str(value or "")
    if not encoded.startswith("0x") or len(encoded) % 2:
        return None, None
    try:
        raw = bytes.fromhex(encoded[2:])
    except ValueError:
        return None, None
    return len(raw), hashlib.sha256(raw).hexdigest()


def _storage(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    remaining: int,
) -> tuple[tuple[StorageChange, ...], bool]:
    selected: list[StorageChange] = []
    truncated = False
    for slot in sorted(set(before) | set(after)):
        before_value = str(before[slot]) if slot in before else None
        after_value = str(after[slot]) if slot in after else None
        if before_value == after_value:
            continue
        if len(selected) >= remaining:
            truncated = True
            break
        selected.append(StorageChange(str(slot), before_value, after_value))
    return tuple(selected), truncated


def parse_state_diff(
    payload: dict[str, Any],
    *,
    max_accounts: int = MAX_STATE_ACCOUNTS,
    max_storage_changes: int = MAX_STORAGE_CHANGES,
) -> StateDiff:
    """Normalize Geth prestateTracer diff-mode output without inventing missing values."""

    raw_pre = _mapping(payload.get("pre"))
    raw_post = _mapping(payload.get("post"))
    pre = {
        str(address).lower(): value
        for address, value in raw_pre.items()
        if ADDRESS_RE.fullmatch(str(address))
    }
    post = {
        str(address).lower(): value
        for address, value in raw_post.items()
        if ADDRESS_RE.fullmatch(str(address))
    }
    addresses = sorted(set(pre) | set(post))
    account_limit = max(0, min(MAX_STATE_ACCOUNTS, max_accounts))
    storage_limit = max(0, min(MAX_STORAGE_CHANGES, max_storage_changes))
    warnings: list[str] = []
    truncated = len(addresses) > account_limit
    accounts: list[AccountStateChange] = []
    total_storage = 0
    for address in addresses[:account_limit]:
        before = _mapping(pre.get(address))
        after = _mapping(post.get(address))
        if address in pre and address not in post:
            change_type = "removed_from_post_state"
        elif address in post and address not in pre:
            change_type = "created_or_newly_materialized"
        else:
            change_type = "modified"
        before_code_bytes, before_code_sha256 = _code_evidence(before.get("code"))
        after_code_bytes, after_code_sha256 = _code_evidence(after.get("code"))
        storage_changes, storage_truncated = _storage(
            _mapping(before.get("storage")),
            _mapping(after.get("storage")),
            remaining=max(0, storage_limit - total_storage),
        )
        total_storage += len(storage_changes)
        truncated = truncated or storage_truncated
        accounts.append(
            AccountStateChange(
                address=address,
                change_type=change_type,
                balance_before_wei=_balance(before.get("balance")),
                balance_after_wei=_balance(after.get("balance")),
                nonce_before=_quantity(before.get("nonce")),
                nonce_after=_quantity(after.get("nonce")),
                code_before_bytes=before_code_bytes,
                code_after_bytes=after_code_bytes,
                code_before_sha256=before_code_sha256,
                code_after_sha256=after_code_sha256,
                storage_changes=storage_changes,
            )
        )
    if truncated:
        warnings.append(
            "State-diff evidence reached an account or storage bound; omitted values are not "
            "treated as unchanged."
        )
    return StateDiff(
        source=SOURCE,
        accounts=tuple(accounts),
        storage_change_count=total_storage,
        truncated=truncated,
        warnings=tuple(warnings),
    )
