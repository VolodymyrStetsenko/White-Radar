# Transaction incident investigation

## Purpose

The White Radar Incident Investigator reconstructs one confirmed EVM transaction into a bounded,
portable, and reproducible evidence case. It is designed for post-incident triage, suspicious
transaction review, protocol-change validation, public postmortem research, and regression fixture
construction.

The investigator reports observed execution and asset flow. It does not infer malicious intent
from a transfer, selector, deep call graph, or proxy pattern alone.

## Command

```bash
white-radar investigate \
  --chain ethereum \
  --tx-hash 0xCONFIRMED_TRANSACTION_HASH
```

The transaction does not need to be in `watchlist.toml`. The selected chain must exist in
`config.toml`, and its HTTP endpoint environment variable must be populated.

```bash
white-radar investigate \
  --chain ethereum \
  --tx-hash 0xCONFIRMED_TRANSACTION_HASH \
  --output evidence/case-name \
  --overwrite
```

Provider-specific controls:

- `--no-trace` disables `debug_traceTransaction`;
- `--no-replay` disables the historical `eth_call` at transaction block minus one.

## Reconstruction pipeline

1. Validate the transaction hash format.
2. Validate `eth_chainId` against the selected chain configuration.
3. Read `eth_getTransactionByHash` and verify the returned hash.
4. Read `eth_getTransactionReceipt` and verify the receipt hash.
5. Require a confirmed block number, read the containing block, and reject inconsistent block
   numbers or hashes before combining evidence.
6. Inspect the transaction target for EIP-1967, beacon, UUPS, and direct
   `implementation()` proxy context.
7. Request Geth-compatible `callTracer` output through `debug_traceTransaction`.
8. Flatten the call tree into stable paths such as `0`, `0.1`, and `0.1.2`.
9. Resolve verified function selectors for a bounded set of call destinations.
10. Decode standard token transfer logs and native value-bearing call frames.
11. Classify addresses into evidence-backed roles and query historical runtime code.
12. Build call and transfer relationships, findings, and timeline records.
13. Re-run the transaction as a read-only `eth_call` at block minus one when enabled.
14. Write the case artifacts and SHA-256 manifest.

## Evidence provenance

| Evidence | Primary source | Evidence reference |
|---|---|---|
| Transaction fields | `eth_getTransactionByHash` | `transaction` |
| Outcome and gas | `eth_getTransactionReceipt` | `receipt` |
| Log order and topics | Receipt logs | `log:<logIndex>` |
| Internal execution | `debug_traceTransaction` with `callTracer` | `call:<path>` |
| Block identity and time | `eth_getBlockByNumber` | block number and hash |
| Historical runtime code | `eth_getCode` at the transaction block | entity record |
| Proxy control state | `eth_getStorageAt` and bounded `eth_call` | `proxy_snapshot` |
| Function signatures | Etherscan API V2 verified ABI | ABI source and SHA-256 |
| Historical replay | `eth_call` at transaction block minus one | `historical_replay` |

Receipt and trace evidence describe the mined transaction. Historical replay is corroborating
evidence. A replay can differ because a provider lacks archival state, a node applies different
call defaults, or the original transaction depended on execution context not reproduced by
`eth_call`.

## Call model

Every trace frame records:

- stable path and depth;
- `CALL`, `STATICCALL`, `DELEGATECALL`, `CALLCODE`, `CREATE`, or `CREATE2` type;
- sender and recipient when supplied by the tracer;
- native value, gas limit, and gas used;
- four-byte selector;
- verified function signature and ABI source when resolved;
- execution error and bounded revert reason when supplied by the tracer.

The investigator caps the graph at 2,000 call frames. Truncation is explicit in `case.json` and
`report.md`.

## Asset-flow model

### Native value

Native-value edges come from value-bearing call frames. When tracing is unavailable, the
investigator retains the top-level transaction value as a fallback.

### ERC-20

An ERC-20 transfer is identified by the standard
`Transfer(address,address,uint256)` topic with indexed sender and recipient and a 32-byte amount in
the data field.

### ERC-721

An ERC-721 transfer uses the same event signature but includes an indexed token identifier as the
fourth topic. White Radar records amount `1` and the token ID separately.

### ERC-1155

`TransferSingle` records one token ID and amount. `TransferBatch` dynamically encodes arrays of IDs
and amounts; White Radar validates offsets and lengths and caps a batch at 256 items.

Zero-address endpoints are retained so that mint and burn flows remain visible.

The complete transfer inventory is capped at 20,000 records. A cap or malformed standard event is
recorded as a source limitation rather than silently presented as complete evidence. Native value
is attributed only to call types that move balances; inherited `DELEGATECALL` value is retained in
the execution frame but is not counted as a second asset transfer.

## Entity and relationship model

Entities are unique addresses observed as one or more of:

- transaction origin or target;
- call sender or recipient;
- created contract;
- asset sender, recipient, operator, or token contract;
- configured protocol inventory contract.

Kinds are inferred from historical runtime code and structural evidence. A label is added only when
the local inventory supplies one; an unlabeled address remains unlabeled.

Entity extraction is capped at 1,000 unique addresses. The interactive HTML renders at most 250
nodes and 1,000 edges; the canonical JSON and tabular exports retain the full bounded inventory.

Relationships contain their evidence reference:

- execution edges use their call type;
- native, ERC-20, ERC-721, and ERC-1155 transfers use typed transfer edges;
- asset address and raw integer amount remain separate fields.

No relationship is created merely because two addresses appear in the same case.

## Timeline semantics

The bundle intentionally uses two phases:

1. `execution` is the pre-order call-trace sequence;
2. `asset_flow` is ordered by receipt `logIndex`, with trace paths for native value.

Standard `callTracer` output does not map every receipt log to its exact internal frame. White Radar
therefore does not claim a false total ordering between all calls and all emitted logs. Both phases
preserve their strongest available ordering and evidence references.

## Proxy-aware ABI resolution

The root target is checked at the transaction block. White Radar resolves:

- EIP-1967 implementation and admin slots;
- EIP-1967 beacon and beacon `implementation()`;
- direct `implementation()` for legacy or custom proxies;
- effective implementation runtime code and normalized fingerprint;
- UUPS `proxiableUUID()` compatibility.

If the proxy ABI does not contain the root selector, the investigator attempts the verified ABI of
the effective implementation. The reported source is marked as implementation-derived.

## Bundle integrity

`manifest.json` contains, for every artifact:

- relative path;
- byte size;
- SHA-256 digest.

To verify an artifact independently:

```bash
sha256sum evidence/CASE/case.json
```

Compare the output with the matching manifest entry. The manifest does not hash itself.

## Interpreting findings

Findings are factual indexes into the evidence, for example:

- a reverted transaction or internal frame;
- delegated execution;
- contract creation;
- observed token or native-value flow;
- resolved proxy execution context.

They are not vulnerability scores. A `DELEGATECALL`, token transfer, or contract creation is common
in legitimate EVM execution. Investigation conclusions require protocol-specific context,
authorization records, expected state transitions, and independent validation.

## Provider compatibility

The minimum endpoint needs standard Ethereum JSON-RPC transaction, receipt, block, code, storage,
and call methods. Exact internal execution requires a provider that exposes Geth-compatible
`debug_traceTransaction` with `callTracer`.

When tracing is unavailable, the case remains usable but cannot prove internal call paths or every
native-value hop. The report records that limitation without converting it into a failed case.

## Bounded resource use

| Resource | Bound |
|---|---:|
| Call frames | 2,000 |
| Receipt logs | 5,000 |
| Asset transfers | 20,000 |
| ERC-1155 items per batch | 256 |
| Entities | 1,000 |
| Historical code lookups | 128 |
| ABI destinations | 32 |
| HTML graph nodes / edges | 250 / 1,000 |
| ERC-1155 batch items | 256 |
| Interactive graph nodes | 250 |
| Interactive graph edges | 1,000 |

The canonical JSON and CSV artifacts preserve the full bounded case even when the interactive graph
uses a smaller rendering cap.

## Current boundary

One seed transaction reconstructs all calls, standard transfers, and relationships inside that
transaction. It does not yet enumerate every subsequent transaction made by every involved address.
Bounded forward and backward transaction expansion, bridge continuation, entity-label adapters,
and cross-transaction fund-flow accounting are separate roadmap items.
