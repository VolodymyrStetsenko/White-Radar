# Security intelligence

White Radar builds reproducible technical context from confirmed chain state, provider
observations, verified metadata, and local protocol configuration.

## Runtime fingerprints

For each discovered contract, White Radar stores:

- SHA-256 of complete runtime bytecode;
- SHA-256 after conservative removal of a recognized Solidity CBOR metadata trailer;
- a bounded 64-bit SimHash of runtime bytecode shingles;
- raw, normalized, and metadata byte sizes.

Exact normalized hashes group builds that differ only in recognized metadata. SimHash provides a
separate approximate-similarity signal. Both measurements retain their method and evidence.

## Verified interface intelligence

`AbiResolver` obtains verified ABI metadata through Etherscan API V2 and builds a local selector
catalog. It:

- computes Ethereum Keccak-256 locally;
- canonicalizes tuple signatures;
- preserves selector collisions as multiple signatures;
- limits documents to two megabytes and 2,000 entries;
- stores the canonical ABI SHA-256 and selector map;
- decodes only bounded static arguments;
- marks dynamic arguments without copying their value.

```bash
white-radar abi \
  --chain ethereum \
  --address 0x1111111111111111111111111111111111111111
```

The selector catalog enriches pending cases with function identity and a source/digest trail.

## State-pinned runtime intelligence

`simulate` reproduces a selected call against an explicit block:

```bash
white-radar simulate \
  --chain ethereum \
  --tx-hash 0xTRANSACTION_HASH \
  --block 21000000 \
  --trace
```

The output records:

- execution status;
- pinned block number/hash;
- transaction fingerprint;
- return-data byte length and SHA-256;
- bounded trace statistics;
- explainable runtime findings.

The trace summary reports call count, depth, delegated/static calls, runtime creation, destructive
frames, value-bearing calls, reverted frames, truncation, and a bounded touched-address set.

## Proxy intelligence

The proxy snapshot resolves:

- EIP-1967 implementation, admin, and beacon slots;
- beacon implementation through `implementation()`;
- effective implementation;
- implementation code size and normalized SHA-256;
- UUPS `proxiableUUID()` compatibility;
- unresolved implementation, missing code, and multiple-control-plane findings.

```bash
white-radar inspect-proxy \
  --chain ethereum \
  --address 0x1111111111111111111111111111111111111111
```

Confirmed upgrade events include the resulting snapshot, not only the emitted log.

## Protocol state intelligence

Policy invariants make contract-specific assumptions machine-checkable. Each check is a typed
read-only call evaluated at a confirmation-safe block. The engine stores the current state and
creates events only on violation/error/recovery transitions.

Examples of observable invariants include:

- a pause flag equals an expected operating state;
- an implementation or controller address equals a known value;
- a supply, debt, reserve, or limit stays within a configured bound;
- a control address remains non-zero;
- a bytes32 domain/configuration identifier remains unchanged.

## Identity graph

Graph nodes include protocol, contract, deployer, account, implementation, admin, beacon, and
bytecode identity. Edges contain the evidence that produced each relationship.

```bash
white-radar graph \
  --chain ethereum \
  --address 0x1111111111111111111111111111111111111111 \
  --depth 2
```

Traversal is bounded from zero to four hops. The graph expresses technical relationships and
provenance; it does not convert shared infrastructure or code similarity into real-world identity.

## Re-enrichment and drift

```bash
white-radar refresh-profiles \
  --chain ethereum \
  --limit 25 \
  --min-age-minutes 10
```

The oldest eligible profiles are checked first. Material changes in runtime code, verification,
implementation, admin, or beacon state produce a `contract_profile_changed` event with previous
and current observations.

## Incident reports

```bash
white-radar report --event-id CASE_ID --output evidence/CASE_ID.md
```

A report contains:

- classification and timestamps;
- chain, block, transaction, and address evidence;
- scoring reasons and finding codes;
- ABI, simulation, invariant, proxy, and runtime context;
- graph neighborhood;
- incident state, SLA, owner, and transition history;
- an investigation checklist and evidence index.

Reports are deterministic views of stored evidence and can be regenerated after incident-state
updates.
