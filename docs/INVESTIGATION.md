# Transaction incident reconstruction

## Purpose

White Radar reconstructs a bounded candidate incident chain from one confirmed EVM transaction
hash. The seed can be an entry, middle, or exit transaction. The engine searches before and after
the seed, identifies evidence-linked candidates, performs a complete per-transaction
reconstruction for each selected candidate, and exports one reviewable evidence bundle.

The result supports incident triage, asset-flow review, protocol postmortems, suspicious
transaction analysis, regression fixtures, and analyst handoff. It records observed evidence and
candidate linkage separately. It does not infer intent or claim that public-chain activity proves
human identity or common control.

## Command

```bash
white-radar investigate \
  --chain ethereum \
  --tx-hash 0xCONFIRMED_SEED_TRANSACTION_HASH
```

The seed does not need to exist in `watchlist.toml`. The selected chain must exist in
`config.toml`, and its HTTP RPC environment variable must be configured.

```bash
white-radar investigate \
  --chain ethereum \
  --tx-hash 0xCONFIRMED_SEED_TRANSACTION_HASH \
  --backward-blocks 2000 \
  --forward-blocks 4000 \
  --max-hops 4 \
  --max-transactions 250 \
  --max-addresses 128 \
  --history-source auto \
  --output evidence/case-name
```

Use `--overwrite` to replace only White Radar's known files in an existing destination. Use
`--single-transaction` when expansion is not required.

## Reconstruction semantics

White Radar labels each reconstructed transaction as one of four phases:

- `pre_seed`: confirmed in a block before the seed;
- `same_block`: linked transaction in the seed block;
- `seed`: the operator-supplied transaction;
- `post_seed`: confirmed after the seed.

These phases describe ledger order, not attack stages or intent. A transaction is included only
when a configured history source links it to a frontier address and the candidate survives the
bounded deterministic ranking process. Every included candidate records its hop, relevance score,
and machine-readable discovery reasons.

## Pipeline

### 1. Seed reconstruction

The engine validates chain identity, transaction and receipt hashes, block identity, and
confirmation. It then reconstructs:

- transaction, receipt, block, status, fee, and timestamp;
- nested `CALL`, `STATICCALL`, `DELEGATECALL`, `CALLCODE`, `CREATE`, and `CREATE2` frames when a
  Geth-compatible `callTracer` is available;
- native value plus ERC-20, ERC-721, ERC-1155 single, and bounded ERC-1155 batch movement;
- verified function signatures and bounded static argument values;
- every retained receipt event plus verified-ABI decoding of indexed and non-indexed arguments;
- explicit unverified selector hints when no verified ABI is available;
- bounded pre/post balance, nonce, code, and contract-storage changes from Geth
  `prestateTracer` diff mode when supported;
- EIP-1967 implementation, admin, beacon, UUPS, and legacy `implementation()` context;
- historical code classification and protocol-inventory labels;
- a read-only historical replay at block minus one when enabled.

### 2. Frontier construction

The first history frontier contains the seed origin and observed non-zero transfer endpoints. If
the seed contains no transfer endpoint, the top-level destination is used. Token contracts and the
zero address are not automatically interpreted as controlled entities.

### 3. Bounded history discovery

The requested block window is:

```text
[seed block - backward blocks, min(chain head, seed block + forward blocks)]
```

The default `auto` source uses Etherscan API V2 when `ETHERSCAN_API_KEY` is configured and falls
back to portable Ethereum JSON-RPC when indexed history is unavailable.

Indexed discovery can combine:

- normal account transactions;
- internal native-value records;
- ERC-20 transfer records;
- ERC-721 transfer records;
- ERC-1155 transfer records.

The RPC fallback scans full blocks for normal transactions and bounded `eth_getLogs` queries for
standard transfer topics. It is portable but does not expose all internal value records and is
more expensive for large block windows.

### 4. Candidate selection

Candidate scoring is deterministic. It prioritizes internal and token-transfer evidence over a
normal address touch, adds weight for non-zero value, recognizes inbound evidence before the seed
and outbound evidence after the seed, and prefers candidates close to the seed block.

The score is a linkage ranking, not a severity or guilt score. The exact source address, record
type, direction, transaction hash, and source adapter remain in the case evidence.

### 5. Related transaction reconstruction

Selected candidates run through the same transaction, receipt, block, trace, event, state-diff,
ABI, proxy, entity, and transfer pipeline as the seed. Failures do not discard the case: they are
counted and recorded as warnings.

New transfer counterparties can enter the next frontier until one of these controls is reached:

- maximum hops;
- maximum reconstructed transactions;
- maximum queried addresses;
- maximum history records per address;
- requested block window.

Transactions and addresses are deduplicated, which prevents graph cycles from causing unbounded
reprocessing.

### 6. Aggregation and export

All successfully reconstructed transactions are ordered by block, transaction index, and hash.
White Radar aggregates address roles, transaction membership, calls, transfers, proxy snapshots,
findings, timelines, and evidence-referenced graph edges. It then writes a deterministic bundle
and SHA-256 manifest.

## Function and ABI evidence

Verified ABI metadata is requested through Etherscan API V2 and pinned by a canonical ABI digest.
When a proxy target does not expose the selector, the effective implementation ABI is checked.

If verified metadata is unavailable, White Radar can label a bounded catalog of common token,
proxy, ownership, and role selectors. These labels are explicitly marked
`built-in selector hint (unverified)` with `candidate` confidence. They never replace verified ABI
evidence.

Decoded static arguments include addresses, Booleans, integers, and fixed bytes. Dynamic inputs
are marked rather than copied without ABI-safe decoding.

Verified event ABI entries are matched by the full event-signature topic. Static indexed values
are decoded from their topics, while indexed arrays, tuples, strings, and dynamic bytes remain
topic hashes because Solidity does not place their original values in the log. Non-indexed static
values, strings, and bytes are decoded from bounded event data. Unresolved logs remain in
`events.csv` with raw topics, bounded data, byte length, and SHA-256; White Radar does not invent
an event name.

## State-change evidence

When supported by the provider, White Radar requests Geth `prestateTracer` with `diffMode=true`.
The normalized result records changed accounts and storage slots with pre/post values. Created
accounts may appear only in `post`; removed accounts may appear only in `pre`. Missing fields are
kept as unavailable rather than interpreted as zero or unchanged.

State evidence is bounded to 512 accounts and 8,192 changed storage slots per transaction. If a
bound is reached, the case records truncation and does not claim omitted slots were unchanged.
Use `--no-state-diff` when a provider rejects this tracer or when a lower-cost investigation is
required.

## Token metadata and accounting

For observed ERC-20 contracts, `name()`, `symbol()`, and `decimals()` are queried with `eth_call` at
the transaction block. Both raw integer amounts and exact decimal display amounts are retained.
Integer arithmetic is used throughout; display conversion does not use floating point.

ERC-721 token identifiers and ERC-1155 identifiers/amounts remain separate. Zero-address
endpoints are preserved so mint and burn events remain visible.

An asset-flow edge proves that a standard event or native-value call was observed in a specific
transaction. It does not prove beneficial ownership or that two addresses are operated by the
same person.

## Proxy and contract context

Proxy inspection is pinned to the relevant transaction block and can resolve:

- EIP-1967 implementation and admin slots;
- EIP-1967 beacon plus beacon implementation;
- legacy or custom direct `implementation()` responses;
- effective implementation runtime code and normalized fingerprint;
- UUPS `proxiableUUID()` compatibility.

The report lists proxy context per transaction. Unavailable archive state or unsupported RPC
methods are recorded as evidence gaps.

## Timeline model

The cross-transaction timeline first orders transactions by confirmed ledger position. Inside each
transaction it preserves three evidence phases:

1. execution-frame pre-order from the call trace;
2. emitted-event order from receipt `logIndex`;
3. asset-flow order from receipt `logIndex`, plus trace paths for native value.

Standard `callTracer` output does not map every receipt log to an exact internal frame. White Radar
therefore does not invent a total order that its sources cannot prove.

## Bundle artifacts

| Artifact | Contents |
|---|---|
| `case.json` | Canonical schema, limits, coverage, contexts, complete source cases, entities, edges, timeline, and warnings |
| `report.md` | Executive summary, scope, candidate phases, chronology, asset ledger, selector inventory, proxy context, entities, and gaps |
| `transactions.csv` | One row per reconstructed transaction with phase, hop, score, and discovery reasons |
| `calls.csv` | One row per execution frame with selector, signature, source, confidence, and error evidence |
| `events.csv` | One row per receipt event with topics, payload evidence, verified ABI source, and decoded arguments |
| `transfers.csv` | Typed asset flow with token metadata, raw amount, display amount, token ID, and evidence reference |
| `state_changes.csv` | Changed account balances, nonces, and code evidence before and after execution |
| `storage_changes.csv` | Changed contract storage slots with explicit pre/post values |
| `entities.csv` | Address kind, label, roles, first/last block, and transaction membership |
| `relationships.csv` | Call and asset-flow edges with source transaction and evidence reference |
| `timeline.csv` | Cross-transaction ledger order and per-transaction event order |
| `graph.html` | Self-contained interactive graph with search, filters, zoom/pan, fit, legend, and evidence sidebar |
| `graph.graphml` | Portable graph for Gephi, Cytoscape, and compatible tools |
| `manifest.json` | Relative paths, byte sizes, SHA-256 digests, chain, seed, and generation time |

The HTML graph contains both transaction and address nodes. Edges distinguish transaction
participation, calls, and asset movement. It is a navigation surface; canonical evidence remains
in JSON and CSV.

## Coverage record

Every case records:

- requested start and end block;
- observed chain head;
- addresses queried;
- history records considered;
- candidate transactions;
- successful and failed reconstructions;
- address and transaction limit state;
- history source adapters;
- trace availability for each transaction;
- source-specific warnings.

The boundary classification is `bounded_candidate_chain`. This wording is deliberate: one seed
cannot prove that no related transaction exists outside the selected window, behind a bridge,
inside a centralized service, or in unavailable provider data.

## Resource controls

| Resource | Default | Hard maximum |
|---|---:|---:|
| Blocks before seed | 256 | 100,000 |
| Blocks after seed | 512 | 100,000 |
| Expansion hops | 3 | 8 |
| Reconstructed transactions | 100 | 2,000 |
| Frontier addresses | 64 | 2,000 |
| History records per address | 200 | 5,000 |
| Call frames per transaction | 2,000 | 2,000 |
| Calldata retained per call frame | 16,384 bytes | 16,384 bytes |
| Receipt logs per transaction | 5,000 | 5,000 |
| Transfers per transaction | 20,000 | 20,000 |
| ERC-1155 items per batch | 256 | 256 |
| ABI destinations per transaction | 32 | 32 |
| Event ABI addresses per transaction | 32 | 32 |
| Event data retained per log | 16,384 bytes | 16,384 bytes |
| State accounts per transaction | 512 | 512 |
| State storage changes per transaction | 8,192 | 8,192 |
| Token metadata contracts per run | 64 | 512 |

The interactive report applies display caps for usability. Canonical JSON and CSV retain the full
bounded reconstruction. If a call input exceeds the calldata cap, its original byte length and
full-input SHA-256 remain in the case.

## Provider compatibility

Minimum operation requires standard transaction, receipt, block, code, storage, log, and
`eth_call` methods. Exact internal execution requires Geth-compatible
`debug_traceTransaction`/`callTracer`. Pre/post state evidence requires a provider that supports
Geth `prestateTracer` diff mode. Indexed cross-transaction history and verified function/event ABI
evidence benefit from Etherscan V2 support for the selected chain.

When a trace, ABI, archive state, proxy probe, token metadata call, or indexed history action is
unavailable, the engine preserves available evidence and records the gap. It never silently
converts missing evidence into a successful conclusion.

## Interpretation boundary

White Radar can reconstruct a strong, auditable candidate chain within its configured evidence
boundary. It cannot guarantee a literal first-to-last narrative when relevant activity is
off-chain, cross-chain without a supported bridge adapter, hidden behind a service's internal
ledger, outside the requested window, or unavailable from the configured providers.

Analyst conclusions should cite transaction hashes, blocks, calls, logs, source adapters, and
bundle hashes. Candidate relevance, address co-occurrence, or transfer direction alone must not be
presented as proof of identity, ownership, or intent.
