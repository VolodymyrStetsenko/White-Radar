# Monitoring and Research Sources

No single feed provides complete, correct, and immediate coverage of every security incident.
The operating model is therefore a layered source stack: rapid alerts for discovery, primary evidence for verification, and independent research for corroboration.

## 1. Rapid incident discovery

Use these sources as early-warning leads. Treat every alert as unverified until it is tied to primary evidence.

| Source | Primary use | Limitation |
|---|---|---|
| [BlockSec / Phalcon](https://blocksec.com/phalcon/explorer) | Recent incident transactions, execution traces, fund flow, state changes, simulation | Coverage and labels are tool-provided and still require independent verification |
| [Cyvers](https://cyvers.ai/) | Real-time threat alerts, abnormal transaction and address activity, cross-chain monitoring | Commercial detection claims are not a substitute for transaction-level reconstruction |
| [Hypernative](https://www.hypernative.io/) | Real-time monitoring and pre-incident threat detection | Most operational detail is customer-facing rather than a complete public incident archive |
| [SlowMist Hacked](https://hacked.slowmist.io/) | Searchable historical incident archive and loss statistics | Entries vary in technical depth and should be checked against primary sources |
| [Rekt News](https://rekt.news/) | Fast incident awareness, narrative post-mortems, historical leaderboard | Editorial summaries are secondary sources |
| [CertiK Skynet Reports](https://www.certik.com/resources) | Incident statistics, periodic threat reports, selected analyses | Periodic reporting is slower than real-time alerting |

For speed, follow the official alert channels and RSS, email, Telegram, or X feeds offered by these organisations. Do not rely on one social account or reposting channel.

## 2. Primary technical evidence

Primary evidence outranks summaries and social posts.

- canonical block explorer transaction, receipt, logs, and verified source;
- trace-capable JSON-RPC output;
- protocol or vendor incident advisory;
- pinned repository revision and deployment configuration;
- signed governance proposal, multisig action, or upgrade record;
- affected team's post-mortem;
- court, regulator, or law-enforcement document where relevant and public.

## 3. Transaction analysis and reproduction

| Tool | Use |
|---|---|
| [Tenderly](https://tenderly.co/) | Replay, debugger, call trace, state changes, source-level inspection, simulation, and shareable investigation views |
| [Phalcon Explorer](https://blocksec.com/phalcon/explorer) | Invocation flow, fund flow, balance changes, state changes, labels, debugger, and simulation |
| [Etherscan](https://etherscan.io/) and chain-specific explorers | Canonical transaction lookup, verified source, events, token movement, contract metadata |
| [Blockscout](https://www.blockscout.com/) | Open-source explorer coverage for many EVM networks and APIs |
| [Foundry](https://book.getfoundry.sh/) | Fork-based reproduction, traces, tests, invariant checks, and scripted evidence generation |
| [Dune](https://dune.com/) | Reproducible queries and aggregate timelines; not a replacement for execution traces |
| [MetaSleuth](https://metasleuth.io/) | Cross-address and asset-flow exploration with labels |

### Tenderly minimum workflow

1. Open the confirmed transaction hash in Tenderly.
2. Inspect the full call trace before reading conclusions from third parties.
3. Record balance, event, and state changes.
4. Map the relevant call to verified source code and the deployed implementation.
5. Re-simulate at the original block context.
6. Change one condition at a time to test the proposed root cause or mitigation.
7. Save the shareable simulation and document every changed parameter.
8. Confirm the result independently with RPC traces or a Foundry fork when the conclusion is material.

## 4. Authoritative and independent post-mortems

Use several classes of source:

- the affected protocol or company;
- the first security team that published transaction-level evidence;
- an independent security firm with a different data pipeline;
- a specialist incident archive;
- a later regulator, court, or law-enforcement record when available.

Useful recurring publishers include BlockSec, SlowMist, CertiK, Immunefi, Chainalysis, Halborn, Trail of Bits, OpenZeppelin, and independent researchers. Authority depends on the evidence in a specific report, not only the publisher's brand.

## 5. AI security incident watch

AI incidents require a different evidence model because model behavior, prompts, tool permissions, logs, datasets, and infrastructure are often not public.

| Source | Primary use |
|---|---|
| [AI Incident Database](https://incidentdatabase.ai/) | Broad catalog of real-world AI harms and near harms, with incident reports and notifications |
| [MITRE ATLAS](https://atlas.mitre.org/) | AI attack techniques, mitigations, and public case studies |
| [MITRE AI Incident Sharing](https://ai-incidents.mitre.org/) | Structured, anonymized operational AI incident sharing |
| [OWASP GenAI Security Project](https://genai.owasp.org/) | Incident-response guidance, exploit round-ups, agentic risks, and threat-intelligence resources |
| [Protect AI Sightline](https://sightline.protectai.com/) | AI/ML supply-chain vulnerabilities and maintainer-curated remediation |
| Vendor security advisories | Primary disclosure from model, platform, cloud, or application providers |

An AI incident should not be forced into an on-chain transaction template. A future AI case archive should preserve prompts, model and tool versions, permissions, system logs, evaluation configuration, affected data, reproduction conditions, and disclosure boundaries.

## 6. Verification rule

Before publishing a central claim, require at least one primary artifact and one of the following:

- independent reproduction;
- a second technically independent evidence source;
- an authoritative acknowledgement that exposes enough detail to inspect the claim.

If that standard is not met, label the claim as reported, inferred, or unresolved.
