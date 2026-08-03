# Incident Research

Evidence-led reconstructions of security incidents affecting on-chain systems.

This archive is intentionally separate from [Security Reviews](https://github.com/VolodymyrStetsenko/SECURITY-REVIEW):

- **security reviews** assess a defined system and revision;
- **incident research** reconstructs an event that occurred, the evidence available after it, the likely failure path, the impact, and the remaining uncertainty.

A case is not published here until it meets the minimum evidence standard in
[`METHODOLOGY.md`](METHODOLOGY.md).

## Published cases

| Case | System | Date | Status | Report |
|---|---|---:|---|---|
| _No case published yet_ | — | — | — | — |

The empty index is deliberate. Preliminary notes, rumours, alert posts, and unverified attribution are not presented as completed investigations.

## Required case structure

Each published case should contain:

```text
cases/<yyyy-mm-dd>-<case-name>/
├── README.md
├── executive-summary.md
├── timeline.csv
├── transactions.csv
├── calls.csv
├── transfers.csv
├── entities.csv
├── relationships.csv
├── root-cause.md
├── prevention.md
├── sources.md
├── limitations.md
└── manifest.json
```

Where a source or network does not expose a required artifact, the omission must be stated explicitly rather than silently treated as absence of activity.

## Case status

- **Preliminary** — evidence collection is incomplete; conclusions may change.
- **Reproduced** — the relevant failure path has been recreated in an authorised environment.
- **Corroborated** — independent evidence sources support the central reconstruction.
- **Final** — the public report, limitations, and integrity manifest have been reviewed and frozen.
- **Updated** — material post-publication evidence changed the case record.

## Publication principles

1. Separate observed evidence from analytical inference.
2. Pin code, blocks, transactions, and external sources where possible.
3. Publish unresolved gaps and contradictory evidence.
4. Do not infer identity, intent, or common control from public-ledger proximity alone.
5. Do not publish operational details that would create unnecessary risk to affected systems or users.
6. Correct the record visibly when stronger evidence becomes available.

See [`SOURCES.md`](SOURCES.md) for the monitoring and research source stack.
