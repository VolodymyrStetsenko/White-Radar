# Engineering roadmap

## Delivered platform

- [x] read-only multi-chain JSON-RPC boundary with chain-ID validation;
- [x] confirmed-block scanners with confirmations, cursors, bounded ranges, and idempotency;
- [x] primary/fallback HTTP and WebSocket provider configuration;
- [x] top-level and inventory-scoped internal contract-deployment intelligence;
- [x] EIP-1967, beacon, implementation, UUPS, and upgrade-event analysis;
- [x] verified ABI selector catalogs and bounded static argument decoding;
- [x] watchlist-filtered pending transaction intelligence;
- [x] deterministic sender, selector, value, and SLA baselines;
- [x] state-pinned `eth_call` simulation and optional bounded call-graph tracing;
- [x] stateful protocol invariants with violation and recovery transitions;
- [x] runtime-code normalization, hashing, similarity families, and drift detection;
- [x] evidence-backed identity graph;
- [x] incident workflow, reports, Telegram cards, digests, JSONL export, and health checks;
- [x] Docker, hardened systemd units, CI, coverage gates, and secret scanning.

## Engineering priorities

### Signal precision

- [ ] event-log ABI decoding with indexed/non-indexed argument support;
- [ ] rolling statistical baselines for sender, selector, value, gas, and call-frequency changes;
- [ ] protocol-specific invariant templates for common proxy, vault, oracle, bridge, and governance
  interfaces;
- [ ] multi-signal incident correlation across pending, confirmed, invariant, proxy, and drift
  observations;
- [ ] reorg reconciliation records for deep or provider-inconsistent reorganizations.

### Protocol context

- [ ] signed policy-pack provenance and revision history;
- [ ] official repository, release manifest, governance, multisig, and security-contact adapters;
- [ ] bytecode-family labels sourced from verified deployment manifests;
- [ ] cross-chain protocol identity resolution with explicit evidence provenance;
- [ ] versioned interface catalogs for standard proxy, vault, token, oracle, and governance systems.

### Reliability and scale

- [ ] PostgreSQL storage backend with transactional cursor compatibility;
- [ ] durable enrichment and alert queues;
- [ ] Prometheus/OpenTelemetry metrics and multi-host service-level objectives;
- [ ] provider quorum reads for critical control-state and invariant checks;
- [ ] deterministic replay harness for recorded blocks and transaction fixtures;
- [ ] retention, partitioning, backup verification, and evidence-integrity tooling.

### Incident operations

- [ ] on-call, case-management, and disclosure-system adapters;
- [ ] configurable escalation matrices and acknowledgement policies;
- [ ] case bundles with manifests, hashes, timelines, and machine-readable evidence indexes;
- [ ] operator dashboards for chain health, signal volume, open incidents, and policy coverage;
- [ ] regression corpus derived from public incident postmortems and sanitized protocol fixtures.

## Design constraints

Future work must preserve deterministic evidence, bounded resource use, explicit chain/block
context, credential redaction, and the read-only RPC boundary.
