# Threat model

## Protected assets

- RPC, explorer, Telegram, and repository credentials;
- protocol inventory, policy packs, and contact context;
- chain cursors and evidence integrity;
- incident history and alert confidentiality;
- monitoring availability and signal quality.

## Trust boundaries

| Boundary | Trusted assumption | Verification |
|---|---|---|
| Local process | Installed White Radar package and configuration | Commit/build provenance, tests, file permissions |
| RPC provider | May be incomplete, delayed, inconsistent, or unavailable | Chain ID, confirmations, fallback, evidence links |
| Explorer metadata | May be absent, stale, or inconsistent | Source label, digest, code/storage comparison |
| WebSocket stream | Partial provider observation | Confirmed-chain follow-up and heartbeat |
| Policy file | Operator-supplied baseline | Strict parser, bounded size, SHA-256 |
| SQLite host | Single administrative domain | WAL, backups, permissions, restore tests |
| Telegram | External delivery channel | Escaping, score gates, outbox/retry |

## Threats and controls

| Threat | Primary controls | Residual risk |
|---|---|---|
| State-changing RPC regression | Fixed method allowlist, no signing model, unit tests | Future code or dependency defect |
| Credential disclosure | Ignored runtime files, redaction, CI secret scan, external environment | Previously disclosed credentials require revocation |
| Provider outage | Ordered HTTP/WS fallbacks, reconnect backoff, heartbeats | Correlated provider or network outage |
| Provider data manipulation | Chain-ID validation, block hashes, confirmations, evidence links | One-provider view can omit or delay data |
| Reorganization | Confirmation delay, cursors, idempotent events | Deep reorg beyond configured window |
| Pending blind spot | Destination filtering plus confirmed follow-up | Private order flow and alternate builders |
| Simulation mismatch | Explicit pinned block and result hashes | Future ordering/state and provider implementation |
| Trace resource exhaustion | Inventory/score gates, frame/address caps, opt-in settings | Provider-specific cost and timeout |
| ABI poisoning/staleness | Verified source label, size/entry bounds, canonical digest | Explorer record may not match active proxy dispatch |
| Proxy-state ambiguity | Event plus storage snapshot, beacon resolution, code probe | Custom proxy layouts remain possible |
| Invariant misconfiguration | Typed schema, bounded calls, state transitions, policy digest | Incorrect expected values create misleading cases |
| Alert flood | Score threshold, transition-only invariants, inventory filter, bounded scans | Protocol thresholds require tuning |
| Telegram outage | Persistent outbox and retry | Delayed delivery |
| Database corruption | WAL, transactional writes, JSONL export, backup procedure | Single-host failure domain |
| Evidence tampering | Stable IDs, source hashes, incident history | Local database administrator remains trusted |
| Correlation overreach | Typed edges and provenance fields | Human interpretation error |
| Silent process failure | Workload heartbeats and non-zero health command | Complete host outage needs external monitoring |

## Detection assumptions

- Confirmed scanner output is based on the configured confirmation delay, not absolute finality.
- Pending output describes transactions visible to the selected provider.
- `eth_call` and traces describe one explicit state snapshot.
- ABI labels depend on verified metadata or local policy labels.
- Invariants represent protocol-specific assumptions supplied in policy.
- Priority aggregates signals for triage and is not itself a vulnerability classification.

## Resource limits

- bounded initial lookback and blocks per cycle;
- bounded policy and ABI document sizes;
- bounded ABI entry count and static argument count;
- bounded trace frames and touched addresses;
- bounded receipt logs, transfer records, entities, ABI destinations, and graph rendering;
- bounded graph traversal depth;
- bounded refresh and list command limits;
- bounded HTTP retries and reconnect backoff.

## Security regression gates

Every change that affects RPC, persistence, parsing, simulation, trace handling, or secret
boundaries must include deterministic tests. CI enforces lint, strict type checking, coverage,
bytecode compilation, and secret-pattern scanning.
