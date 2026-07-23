# Engineering roadmap

## Product direction

WhiteRadar Incident is developed as a transaction-centric EVM incident investigator with a quiet,
protocol-specific guard. Investigation depth and evidence quality take priority over broad,
high-volume alert generation.

## Delivered investigation and reconstruction foundation

- [x] one-command investigation from a confirmed transaction hash without a watchlist requirement;
- [x] transaction, receipt, block, fee, and execution-status reconstruction;
- [x] bounded Geth `callTracer` call tree with stable frame paths;
- [x] native, ERC-20, ERC-721, ERC-1155 single, and bounded ERC-1155 batch transfer extraction;
- [x] entity roles, historical code classification, call edges, and asset-flow edges;
- [x] execution and receipt-log timeline phases with explicit evidence references;
- [x] verified ABI selector resolution and proxy-implementation fallback;
- [x] EIP-1967, beacon, UUPS, and legacy `implementation()` proxy context;
- [x] historical read-only replay at transaction block minus one;
- [x] canonical JSON, CSV tables, Markdown report, interactive HTML graph, GraphML, and SHA-256
  manifest;
- [x] graceful degradation when trace, explorer, or archival replay data is unavailable;
- [x] routine mempool token calls aggregated as telemetry instead of per-transaction cases;
- [x] policy- and critical-selector-based pending promotion;
- [x] read-only multi-chain RPC boundary, chain-ID validation, provider failover, and secret scanning.
- [x] bounded backward/forward expansion from any confirmed seed transaction;
- [x] indexed normal/internal/ERC-20/ERC-721/ERC-1155 history with bounded JSON-RPC fallback;
- [x] deterministic candidate ranking, per-hop discovery reasons, source provenance, and coverage
  counters;
- [x] cross-transaction chronology, transaction/address graph, call edges, and per-asset flow
  ledger;
- [x] transaction/address/cycle deduplication with hard block, hop, address, history, and transaction
  limits;
- [x] block-pinned ERC-20 name, symbol, decimals, raw amount, and exact display amount;
- [x] verified ABI confidence plus explicitly unverified built-in selector hints;
- [x] self-contained graph search, node/relation filters, zoom/pan, fit, evidence details, and
  portable GraphML;
- [x] Ethereum, Base, Arbitrum, OP Mainnet, Polygon, Sepolia, and Monad configuration templates.
- [x] committed-versus-reverted call-tree and asset-flow semantics;
- [x] compact seed-plus-one-hop core candidate path alongside the complete bounded graph;
- [x] high-fanout hub detection, bounded expansion, and explicit suppression accounting.

## Highest-priority investigation work

### Bounded multi-transaction fund flow

- [x] expand forward and backward from seed entities inside explicit block, depth, and
  transaction-count limits;
- [x] combine normal transactions, internal value transfers, and standard token transfers into one
  cross-transaction graph;
- [x] maintain per-hop provenance and raw integer asset accounting without implying ownership or
  intent;
- [x] detect and bound high-volume hub fan-out without hiding retained evidentiary transfers;
- [ ] attach source-backed exchange, router, and service classifications to detected hubs;
- [ ] checkpoint long investigations and resume deterministically;
- [x] export a cross-transaction graph and per-asset flow ledger;
- [ ] export analyst-selected branch slices and conservation summaries.

### Richer transaction evidence

- [x] optional bounded `prestateTracer` diff-mode account and storage-change extraction;
- [x] verified event-ABI decoding for indexed and non-indexed values beyond transfer standards;
- [x] token symbol and decimals pinned to the investigation block;
- [ ] ERC-721/1155 collection metadata pinned to the investigation block;
- [ ] custom-error and revert-data decoding from verified interfaces;
- [ ] mapping between trace-emitted logs and their internal call frames when the provider supports
  log-aware tracing;
- [ ] create-address derivation and CREATE2 salt/init-code evidence.

### Cross-domain continuation

- [ ] evidence-backed bridge deposit and withdrawal pairing;
- [ ] explicit chain-transition nodes and message identifiers;
- [ ] configurable continuation across Ethereum, Base, Arbitrum, OP Mainnet, Polygon, and other
  supported EVM chains;
- [ ] source-specific confidence and unresolved-bridge records.

### Entity intelligence

- [ ] pluggable public label sources with source, timestamp, and confidence fields;
- [ ] protocol, multisig, bridge, exchange, router, relayer, and service classification;
- [ ] local analyst labels with append-only revision history;
- [ ] code-family and deployer-cluster context attached to investigation entities;
- [ ] explicit conflict handling when sources disagree.

## Quiet guard precision

- [ ] rolling selector, sender, value, gas, and call-frequency baselines;
- [ ] protocol-specific invariant templates for proxies, vaults, bridges, oracles, and governance;
- [ ] multi-signal promotion across pending, confirmed, invariant, proxy, and runtime-drift evidence;
- [ ] stateful suppression windows and explainable alert grouping;
- [ ] reorg reconciliation for promoted observations;
- [ ] Telegram case links that reference generated evidence bundles rather than raw traffic.

## Investigation operations

- [ ] case registry with analyst notes, tags, ownership, and append-only disposition history;
- [ ] comparison of two transaction cases or two protocol-state snapshots;
- [ ] signed export manifests and optional external timestamping;
- [ ] reproducible investigation recipes containing chain, seed, limits, providers, and source
  digests;
- [ ] searchable local index across calls, selectors, contracts, transfers, and findings;
- [ ] operator dashboard for investigation progress, source gaps, and evidence coverage.

## Reliability and scale

- [ ] deterministic replay corpus from public transactions and sanitized protocol fixtures;
- [ ] provider capability discovery for trace, archival state, batch calls, and log limits;
- [ ] quorum reads for critical receipt, block, proxy, and state-diff evidence;
- [ ] durable work queue and PostgreSQL backend for multi-host investigation workers;
- [ ] Prometheus/OpenTelemetry metrics, resource budgets, and service-level objectives;
- [ ] retention, encrypted backup verification, and evidence-integrity audits.

## Engineering constraints

All future work must preserve:

- read-only RPC semantics and the absence of signing or broadcasting paths;
- deterministic evidence references and explicit chain/block context;
- bounded resource use and operator-controlled investigation expansion;
- credential redaction and repository secret scanning;
- source attribution, uncertainty, and graceful degradation;
- a strict distinction between observed evidence, derived findings, and analyst conclusions.
