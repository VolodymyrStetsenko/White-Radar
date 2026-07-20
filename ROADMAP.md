# Roadmap

## 0.1 — Defensive mainnet foundation

- [x] read-only RPC method allowlist;
- [x] multi-chain confirmed-block scanners;
- [x] chain-ID validation and configurable confirmations;
- [x] deployment, verification, EIP-1967, and deployer-cluster enrichment;
- [x] watchlist/global proxy control-event monitoring;
- [x] watchlist-only pending observer;
- [x] explainable scores and professional Telegram cases;
- [x] SQLite cursors, deduplication, evidence, and alert outbox;
- [x] JSON logging, JSONL export, CI, Docker, and systemd packaging.

## 0.2 — Signal quality

- delayed re-enrichment for newly verified contracts;
- verified-source fingerprints and bytecode similarity clusters;
- protocol identity graph linking official repositories, domains, deployers, factories, proxies,
  implementations, multisigs, and bounty scope;
- configurable alert digests and per-protocol policies;
- trace-backed internal `CREATE`/`CREATE2` discovery where the provider supports it;
- PostgreSQL migration and background work queue.

## 0.3 — Authorized protocol defense

- protocol-supplied invariants and event baselines;
- fork-only transaction simulation with reproducible state snapshots;
- anomaly rules reviewed and signed by the protocol owner;
- incident case workflow with acknowledgement and escalation SLAs;
- integration adapters for official disclosure and on-call systems.

## Separate future responder

Any transaction-capable responder is outside the White Radar monitoring process. It may be designed
only for contracted protocols and must satisfy the review gates in the threat model. It will not be
implemented as a generic exploit copier, public mempool competitor, or autonomous asset custodian.
