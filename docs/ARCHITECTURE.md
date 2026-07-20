# Architecture

## Design goals

White Radar is designed around five invariants:

1. monitoring is read-only;
2. every case is reproducible from stored public evidence;
3. chain progress is restart-safe and reorg-aware through configurable confirmations;
4. alert delivery cannot block or corrupt chain ingestion;
5. a score must explain why the signal was surfaced.

## Components

| Component | Responsibility | Trust boundary |
|---|---|---|
| `JsonRpcClient` | Bounded EVM reads and chain-ID validation | Untrusted RPC response |
| `ChainScanner` | Confirmed ranges, deployments, proxy events | Public chain data |
| `ContractEnricher` | Sourcify, Etherscan V2, EIP-1967 metadata | Third-party metadata |
| `watch_pending_transactions` | Watchlist-only pending metadata | Partial provider mempool |
| Scoring | Deterministic priority and reasons | Configuration quality |
| `RadarStore` | Cursors, correlations, cases, alert outbox | Local filesystem |
| `TelegramNotifier` | Human-readable triage delivery | Telegram API |

## Confirmed-block pipeline

1. Read `eth_chainId` and reject a mismatched endpoint.
2. Read the head and subtract the chain-specific confirmation delay.
3. Resume from the SQLite cursor or a bounded initial lookback.
4. Fetch full block transactions.
5. Select successful top-level creations (`to == null` plus a successful receipt).
6. Read runtime code and EIP-1967 storage.
7. Query verification metadata without downloading or executing source code.
8. Insert the deployment idempotently.
9. Query the deployer's 24-hour contract cluster.
10. Build and persist a normalized case.
11. Advance the cursor only after the block succeeds.
12. Deliver eligible alerts from the retryable outbox.

## Reorg model

The scanner intentionally trails the head by `confirmations`. Values differ by chain because block
production and settlement characteristics differ. A cursor represents the last successfully
processed confirmed block, not the latest observed head.

This reduces routine short reorg risk but does not provide finality proofs. Protocol-specific
operators should tune confirmations and, where required, add L1 settlement awareness for rollups.

## Correlation model

The initial graph uses an explainable relationship: contracts created by the same top-level
deployer within 24 hours. Related cases include address, transaction, block, contract name, and
proxy status. Future graph edges are documented in the roadmap and must preserve source evidence.

## Pending pipeline

The pending observer:

- requires an explicit chain and non-empty authorized watchlist;
- subscribes to `newPendingTransactions` over WebSocket;
- fetches transaction metadata through the read-only HTTP client;
- discards transactions whose destination is outside the watchlist;
- stores the selector and calldata length, never full calldata;
- never constructs, signs, replaces, or submits a transaction.

## Failure isolation

- RPC errors stop only the affected chain cycle.
- Chain cursors are never advanced past a failed block.
- Duplicate events are eliminated by stable IDs and database constraints.
- Telegram failures leave events unalerted in SQLite for later retry.
- Credentials are referenced by environment-variable name and never serialized into events.

## Scaling path

SQLite deliberately keeps the first deployment inspectable and inexpensive. The horizontal path is
PostgreSQL for durable state, a queue for enrichment work, per-chain scanners, and a separate alert
dispatcher. That migration should occur only after real workload measurements justify it.
