# Security intelligence

White Radar converts public EVM observations and explicit operator scope into reproducible technical
relationships. It is an incident-triage aid, not an attribution engine or vulnerability oracle.

## Runtime fingerprints

For each discovered contract, White Radar stores:

- SHA-256 of the complete runtime bytecode;
- SHA-256 after conservative removal of a recognized Solidity CBOR metadata trailer;
- a bounded 64-bit SimHash calculated from runtime bytecode shingles;
- raw, normalized, and metadata byte sizes.

The normalized hash helps group builds that differ only in recognized Solidity metadata. SimHash
supports approximate clustering and is intentionally labeled as similarity. Neither mechanism proves
that two contracts have the same owner, source code, purpose, or security properties.

## Identity graph

Current node types include protocol, contract, deployer, and account. Current relationship types
include deployment, watchlist membership, observed pending calls, proxy implementation, proxy
admin, beacon, and bytecode similarity.

Every edge contains machine-readable evidence. A graph neighborhood can be exported with:

```bash
white-radar graph \
  --chain ethereum \
  --address 0x1111111111111111111111111111111111111111 \
  --depth 2
```

Depth is bounded from zero to four. Treat the result as a technical evidence map. Do not infer a
person's identity or accuse an address owner from shared infrastructure, bytecode, or transaction
proximity alone.

## Re-enrichment and drift

Explorer verification commonly appears after deployment. Proxy control state may also change over
time. A bounded refresh compares stored and current observations. Material differences are recorded
with previous/current values and independent explorer links.

```bash
white-radar refresh-profiles \
  --chain ethereum \
  --limit 25 \
  --min-age-minutes 10
```

The command processes the oldest eligible profiles first. Size the limit and timer cadence to RPC,
Sourcify, and explorer quotas.

## Incident reports

`white-radar report` renders one stored case as Markdown with classification, evidence, technical
context, graph relationships, a recommended response, and an authorization checklist. It avoids
claims of malicious intent and requires human validation.

```bash
white-radar report --event-id CASE_ID --output evidence/CASE_ID.md
```

Reports may contain operational addresses and scope metadata. Store real reports outside any public
repository and follow the applicable disclosure agreement.
