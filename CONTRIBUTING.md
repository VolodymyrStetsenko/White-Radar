# Contributing

White Radar currently uses a private-development model. Contact the maintainer before preparing a
substantial change.

## Engineering rules

- preserve the read-only RPC invariant;
- never add a signer, seed phrase, private key, raw-transaction builder, or broadcast method;
- keep secrets, operational watchlists, and runtime data out of commits;
- add deterministic tests for scoring, cursor behavior, deduplication, and alert formatting;
- treat priority as triage, not proof of a vulnerability or malicious actor;
- update documentation and the changelog for operator-visible behavior;
- use official primary documentation for provider and protocol behavior.

## Checks

```bash
python -m unittest discover -s tests -v
python -m compileall -q src
python scripts/check_secrets.py
ruff check .
mypy src
pytest --cov=white_radar --cov-report=term-missing
```

## Commit hygiene

- keep each commit focused;
- explain the operational or security impact;
- do not include generated environments, databases, logs, or credentials;
- review `git diff --cached` before committing.
