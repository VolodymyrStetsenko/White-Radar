# Changelog

All notable changes are documented here.

## Unreleased

- expanded `white-radar investigate` from a one-transaction bundle into bounded backward/forward
  reconstruction from any confirmed seed transaction;
- added indexed Etherscan V2 normal, internal, ERC-20, ERC-721, and ERC-1155 history adapters with
  portable bounded JSON-RPC block/log fallback;
- added deterministic candidate ranking, multi-hop frontier expansion, cycle deduplication,
  discovery reasons, coverage counters, and source-specific warnings;
- added cross-transaction phases, chronology, entity aggregation, call/asset edges, and per-asset
  ledgers;
- added block-pinned token name, symbol, decimals, raw amounts, and exact display amounts;
- added explicitly unverified built-in selector hints when verified ABI evidence is unavailable;
- added per-call bounded calldata, decoded arguments, original byte length, SHA-256, truncation
  state, and historical runtime-code fingerprints for contract entities;
- added `transactions.csv`, cross-transaction JSON schema, richer Markdown reporting, searchable
  interactive address/transaction graphs, and GraphML provenance;
- added Monad mainnet configuration templates;
- repositioned White Radar around transaction-centric incident investigation and a quiet protocol
  guard;
- added `white-radar investigate` for confirmed transactions without a watchlist requirement;
- added bounded call-tree reconstruction with stable frame paths and graceful trace degradation;
- added native, ERC-20, ERC-721, ERC-1155 single, and ERC-1155 batch transfer reconstruction;
- added entities, evidence-backed relationships, two-phase timelines, and factual findings;
- added canonical JSON, CSV tables, Markdown, interactive HTML, GraphML, and SHA-256 case manifests;
- added proxy-aware implementation ABI fallback and legacy direct `implementation()` resolution;
- pinned investigation replay and proxy context to historical transaction state;
- converted low-evidence pending traffic and routine token calls into hourly telemetry aggregates;
- limited pending cases, identity edges, warning logs, and Telegram delivery to promoted evidence;
- added ordered HTTP and WebSocket RPC fallback configuration;
- added verified ABI catalogs, Ethereum selector derivation, and bounded static argument decoding;
- added state-pinned transaction simulation with optional bounded call-graph tracing;
- added EIP-1967/beacon/effective-implementation snapshots and UUPS compatibility checks;
- added typed protocol invariants with transition-only violation and recovery events;
- enriched pending, proxy-upgrade, Telegram, report, health, and status evidence;
- added dedicated ABI, simulation, proxy, invariant, storage, and RPC failover tests;
- rebuilt architecture, coverage, operations, policy, intelligence, Telegram, privacy, and threat
  documentation around the transaction-investigation product.

## 0.3.0 — 2026-07-21

- added bounded per-protocol policy packs for sender, selector, native-value, and SLA baselines;
- added explainable pending-policy findings with reproducible policy SHA-256 evidence;
- added automatic high-priority incident creation and an audited incident state machine;
- added acknowledgement deadlines, incident ownership, overdue queries, reports, and digest totals;
- added service heartbeats and a machine-readable health command for 24/7 operations;
- added a hardened systemd health timer and richer pending Telegram context;
- expanded tests, operations guidance, architecture, and threat modeling.

## 0.2.0 — 2026-07-21

- added Solidity-metadata-normalized runtime fingerprints and bytecode similarity clusters;
- added an evidence-backed on-chain identity graph and bounded neighborhood export;
- added provider-aware filtered Alchemy pending subscriptions where supported;
- added opt-in, watchlist-scoped `CREATE`/`CREATE2` discovery through call traces;
- added bounded scheduled profile re-enrichment and material drift cases;
- added Markdown incident reports and configurable-window Telegram digests;
- added hardened systemd units for pending observation, refresh timers, and digest timers;
- expanded tests, documentation, and the read-only defensive operating model.

## 0.1.0 — 2026-07-20

- introduced the White Radar modular package and CLI;
- added read-only RPC enforcement and chain-ID validation;
- added multi-chain confirmed deployment and proxy-event monitoring;
- added Sourcify, Etherscan V2, and EIP-1967 enrichment;
- added deployer correlation and explainable priority scoring;
- added watchlist-only pending transaction observation;
- added SQLite state, idempotent events, and a retryable Telegram outbox;
- added professional Telegram case rendering;
- added Docker, systemd, CI, tests, and operational/security documentation.
