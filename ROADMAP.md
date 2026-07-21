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

- [x] bounded delayed re-enrichment and material profile-drift cases;
- [x] Solidity-metadata-normalized runtime fingerprints and similarity clusters;
- [x] evidence-backed graph foundation for protocols, deployers, senders, contracts, proxies,
  implementations, admins, beacons, and bytecode relationships;
- [x] Markdown incident reports and configurable-window Telegram digests;
- [x] watchlist-scoped internal `CREATE`/`CREATE2` discovery where traces are available;
- [x] provider-aware filtered pending subscriptions on supported Alchemy networks;
- [ ] signed per-protocol policy packs and approved identity assertions;
- [ ] official repository, domain, multisig, and bounty-scope ingestion adapters;
- [ ] PostgreSQL migration and background work queue.

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
