from __future__ import annotations

import dataclasses
import hashlib


@dataclasses.dataclass(frozen=True, slots=True)
class BytecodeFingerprint:
    """Deterministic runtime-bytecode identity and a bounded similarity sketch."""

    raw_sha256: str
    normalized_sha256: str
    simhash64: str
    bytecode_size: int
    normalized_size: int
    metadata_size: int


def _decode_hex_bytecode(code: str) -> bytes:
    value = code.removeprefix("0x")
    if len(value) % 2:
        value = "0" + value
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def strip_solidity_metadata(bytecode: bytes) -> tuple[bytes, int]:
    """Conservatively remove a Solidity CBOR metadata trailer.

    Solidity stores the CBOR length in the final two bytes. We only remove a
    candidate that has a CBOR-map major type and at least one recognized
    metadata key. This is intentionally conservative: an unrecognized trailer
    is retained rather than risking a false equivalence.
    """

    if len(bytecode) < 4:
        return bytecode, 0
    metadata_length = int.from_bytes(bytecode[-2:], "big")
    total_length = metadata_length + 2
    if metadata_length <= 0 or total_length >= len(bytecode):
        return bytecode, 0
    metadata = bytecode[-total_length:-2]
    if not metadata or metadata[0] >> 5 != 5:
        return bytecode, 0
    known_keys = (b"ipfs", b"bzzr0", b"bzzr1", b"solc", b"experimental")
    if not any(key in metadata for key in known_keys):
        return bytecode, 0
    return bytecode[:-total_length], total_length


def _simhash64(bytecode: bytes) -> str:
    if not bytecode:
        return "0" * 16
    width = min(4, len(bytecode))
    token_count = max(1, len(bytecode) - width + 1)
    # Bound work for large runtimes while sampling across the entire program.
    step = max(1, token_count // 4096)
    weights = [0] * 64
    for offset in range(0, token_count, step):
        token = bytecode[offset : offset + width]
        digest = int.from_bytes(hashlib.blake2b(token, digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if digest & (1 << bit) else -1
    value = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            value |= 1 << bit
    return f"{value:016x}"


def fingerprint_bytecode(code: str) -> BytecodeFingerprint:
    raw = _decode_hex_bytecode(code)
    normalized, metadata_size = strip_solidity_metadata(raw)
    return BytecodeFingerprint(
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        normalized_sha256=hashlib.sha256(normalized).hexdigest(),
        simhash64=_simhash64(normalized),
        bytecode_size=len(raw),
        normalized_size=len(normalized),
        metadata_size=metadata_size,
    )


def simhash_similarity(left: str, right: str) -> float:
    if len(left) != 16 or len(right) != 16:
        return 0.0
    try:
        distance = (int(left, 16) ^ int(right, 16)).bit_count()
    except ValueError:
        return 0.0
    return max(0.0, 1.0 - distance / 64.0)
