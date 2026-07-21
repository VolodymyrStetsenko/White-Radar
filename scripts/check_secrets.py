#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "data", "build", "dist", "__pycache__"}
SKIP_FILES = {".env"}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".service",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
PATTERNS = {
    "GitHub token": re.compile(r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})"),
    "Telegram bot token": re.compile(r"\b\d{7,12}:[A-Za-z0-9_-]{30,}\b"),
    "assigned private key": re.compile(
        r"(?i)(?:private[_-]?key|signer[_-]?key)\s*[=:]\s*['\"]?0x[a-f0-9]{64}\b"
    ),
    "assigned secret": re.compile(
        r"(?i)(?:api[_-]?key|token|secret)\s*[=:]\s*['\"]?(?!YOUR_|CHANGEME|<)[A-Za-z0-9_./+-]{24,}"
    ),
}


def candidates() -> list[Path]:
    result: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.name in SKIP_FILES:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"Dockerfile", "Makefile"}:
            result.append(path)
    return result


def main() -> int:
    findings: list[str] = []
    for path in candidates():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if path.name.endswith(".example") or "YOUR_" in line or not line.strip():
                continue
            for label, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(f"{path.relative_to(ROOT)}:{line_number}: {label}")
    if findings:
        print("Potential secrets detected:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(f"Secret-pattern check passed ({len(candidates())} files scanned).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
