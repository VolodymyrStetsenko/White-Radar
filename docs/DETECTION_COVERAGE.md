# Detection coverage

WhiteRadar Incident is a transaction incident investigator with a quiet protocol guard. Coverage is
expressed as reconstructable evidence and configured signals, not as a claim that one signal proves
a vulnerability.

The matrix aligns current capabilities with the
[OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/) 2026
categories and the incident-management objectives in
[NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).

## Coverage matrix

| Risk family | Observable White Radar signals | Coverage level |
|---|---|---|
| Access control | Sender outside baseline, critical selector, admin-slot change, invariant transition, implementation change | Strong for configured control paths |
| Business logic | Protocol invariants, selector/value baselines, simulation outcome, call depth/value flow, confirmed drift | Protocol-specific |
| Price oracle manipulation | Oracle-address inventory, update-selector labels, sender/value baselines, oracle invariants, multi-call trace context | Requires oracle policies |
| Flash-loan-facilitated attacks | Deep/multi-call runtime graph, multiple value-bearing frames, unusual selector/sender/value combination | Contextual only |
| Input validation | ABI function identity, bounded static argument decoding, policy thresholds, simulation revert/success | Partial |
| Unchecked external calls | Reverted trace frames, external-call graph, downstream state invariant changes | Partial |
| Arithmetic errors | Numeric invariants, return-value ceilings/floors, state drift across confirmed blocks | Requires protocol invariants |
| Reentrancy | Nested call/delegatecall graph and unusual depth | Heuristic |
| Overflow/underflow | Numeric invariant transitions and abnormal decoded values | Requires protocol invariants |
| Proxy and upgradeability | EIP-1967 implementation/admin/beacon state, upgrade logs, effective code hash, missing code, UUPS probe, multiple control planes | Strong |

## Signal families

### Transaction reconstruction

- confirmed transaction, receipt, containing block, status, gas, and fee evidence;
- bounded pre-seed, same-block, seed, and post-seed transaction discovery;
- indexed normal/internal/token history with portable block/log fallback;
- deterministic discovery reasons, source provenance, and coverage counters;
- bounded exact mined call tree when `callTracer` is available;
- native, ERC-20, ERC-721, and ERC-1155 asset movement;
- block-pinned ERC-20 metadata, raw amounts, and exact display amounts;
- entity roles and evidence-backed call/transfer relationships;
- proxy implementation context and verified selector identity;
- searchable cross-transaction graphs and portable case bundles with evidence references and
  integrity hashes.

### Control-plane monitoring

- implementation, admin, and beacon event logs;
- EIP-1967 slot snapshots;
- effective implementation code presence and fingerprint;
- UUPS compatibility;
- critical governance and administrative selectors;
- known-sender and native-value baselines.

### Runtime monitoring

- state-pinned execution success or revert;
- call count and maximum depth;
- delegated and static calls;
- runtime contract creation;
- destructive execution frames;
- value-bearing call count;
- reverted-frame count;
- bounded touched-address set.

### State monitoring

- typed `eth_call` invariants;
- numeric ceilings and floors;
- address equality/change checks;
- Boolean operating-state checks;
- invariant error state and recovery;
- runtime code and verification drift.

### Deployment and identity monitoring

- top-level deployments;
- optional internal `CREATE`/`CREATE2`;
- same-deployer release clusters;
- exact normalized-code families;
- bounded code-similarity relationships;
- proxy implementation/admin/beacon relationships;
- promoted pending sender-to-contract relationships; routine calls remain aggregate telemetry.

## Incident workflow mapping

| Incident function | White Radar implementation |
|---|---|
| Preparation | Chain configuration, protocol inventory, policy baselines, invariants, contacts, service units |
| Detection | Confirmed scanner, pending observer, proxy logs/state, simulation, traces, drift, invariant transitions |
| Analysis | Transaction reconstruction, ABI labels, asset-flow and entity graphs, evidence bundles |
| Response coordination | Incident SLA, owner, audited state transitions, Telegram cases and digests |
| Recovery monitoring | Invariant recovery, profile refresh, confirmed follow-up, health checks |
| Improvement | JSONL exports, incident history, policy digest, regression tests |

## Known blind spots

- Provider pending streams do not include all private order flow.
- Runtime simulation does not know future block ordering or future state.
- Generic observation cannot infer a protocol's intended economic invariant.
- ABI metadata can be absent, stale, or inconsistent with proxy dispatch.
- Trace APIs can be unavailable or provider-specific.
- Off-chain compromise, social engineering, leaked signers, and governance operations require
  external telemetry.
- Cross-chain messages require source/destination correlation that is not yet implemented.
- Bounded expansion cannot prove that no relevant transaction exists outside its block, hop,
  address, transaction, or provider-data limits.
- Centralized-service internal ledgers, unsupported bridges, privacy systems, and unavailable
  archive/index data can interrupt an on-chain candidate chain.
- Contract-level signals cannot identify the real-world controller of an address.

Coverage should therefore be evaluated per protocol as a set of configured data sources,
invariants, interfaces, and response paths.
