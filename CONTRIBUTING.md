# Contributing

White Radar currently uses a private-development model. Contact the maintainer before preparing a
substantial change.

## Engineering rules

- preserve the read-only RPC invariant;
- never add a signer, seed phrase, private key, raw-transaction builder, or broadcast method;
- keep secrets, operational watchlists, and runtime data out of commits;
- add deterministic tests for parsing, failover, pinned analysis, persistence, scoring, cursors,
  deduplication, and output formatting;
- preserve chain ID, block number/hash, policy digest, and data-source provenance in evidence;
- bound external documents, traces, graph traversal, retries, and batch sizes;
- update documentation and the changelog for operator-visible behavior;
- use official primary documentation for provider and protocol behavior.

## Checks

```bash
python -m unittest discover -s tests -v
python -m compileall -q src
python scripts/check_secrets.py
ruff check .
mypy src
pytest --cov=white_radar --cov-report=term-missing --cov-fail-under=80
```

## Commit hygiene

- keep each commit focused;
- explain the operational or security impact;
- do not include generated environments, databases, logs, or credentials;
- review `git diff --cached` before committing.
