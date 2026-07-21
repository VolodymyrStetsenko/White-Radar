# Threat model

## Protected assets

- RPC, explorer, GitHub, and Telegram credentials;
- operational watchlists and client identities;
- chain cursors and evidence integrity;
- alert confidentiality and availability;
- the operator's reputation and legal scope.

## Threats and controls

| Threat | Primary controls | Residual risk |
|---|---|---|
| Accidental transaction broadcast | Fixed RPC allowlist; no signer or private-key setting; tests | Dependency or future-code regression |
| Secret committed to Git | `.gitignore`; examples contain empty values; CI pattern scan | Previously exposed secrets still require rotation |
| Malicious/misconfigured RPC | Chain-ID check; confirmations; evidence links | RPC can omit or delay data |
| Reorg duplicates or gaps | Confirmation delay; cursors; stable event IDs | Deep reorg beyond configured delay |
| Telegram outage | SQLite alert outbox and retry | Delayed human response |
| Alert flooding | Bounded scans; minimum score; testnet gate; watchlist pending filter | Scoring still needs operational tuning |
| False vulnerability inference | Alerts say priority, not exploitability; explainable reasons | Human interpretation error |
| Public repository intelligence leak | Operational config/watchlist/data are ignored | Architecture remains public |
| Database corruption | WAL mode; transactional writes; JSONL export | Single-node storage remains a failure domain |
| Provider mempool blind spots | Explicit limitation and confirmed-chain follow-up | No provider sees the entire network |
| Trace API cost or unavailability | Disabled by default; watchlist-only calls; bounded confirmed ranges | Provider-specific limits |
| False bytecode-family inference | Exact hash separated from heuristic SimHash; evidence retained | Similarity is not common ownership |
| Stale explorer or proxy metadata | Bounded scheduled re-enrichment and drift cases | Refresh cadence and third-party lag |
| Graph over-attribution | Typed evidence edges and explicit non-attribution policy | Human interpretation error |
| Misconfigured policy baseline | Strict parsing, file digest, explainable rules, human review | Stale owner-supplied data |
| Silent process failure | Periodic heartbeats, stale threshold, non-zero health check | Host outage needs external monitoring |
| Incident status tampering | Controlled state machine and append-only transition records | Local database administrator remains trusted |

## Non-goals

White Radar does not claim to:

- detect every exploit;
- prove malicious intent from a transaction;
- provide complete internal-call coverage outside enabled watchlist-scoped traces;
- guarantee real-time delivery;
- authorize security research;
- execute a rescue or recover assets.
- infer malicious intent solely from a policy deviation.

## Security review gates

Any future component that can sign or submit transactions must be a separate service and requires:

- written protocol authorization;
- a dedicated legal review;
- hardware-backed keys and role separation;
- multi-party approval;
- transaction policy simulation;
- value and gas limits;
- an immutable audit trail;
- independent code review and adversarial testing;
- an emergency stop and post-incident reconciliation process.
