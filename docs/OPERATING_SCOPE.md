# Operating scope

White Radar investigation starts from any confirmed transaction hash and does not require protocol
inventory. The quiet guard uses an explicit inventory to control where continuous high-cost
analysis is applied and how promoted findings are routed.

## Inventory record

Each contract record can define:

- chain ID and contract address;
- protocol and component role;
- critical selectors;
- security contact URI;
- program or security-policy URI.

Each deployer record can define:

- chain ID and address;
- release or infrastructure label.

The inventory drives pending destination filtering, manual protocol simulation, internal creation
tracing, optional investigation labels, persistent protocol graph relationships, and report contact
context.

## Policy record

A policy can add:

- known transaction senders;
- expected and critical selectors;
- a native-value ceiling;
- selector labels;
- acknowledgement SLA;
- typed protocol invariants.

Policy files are bounded, validated, hashed, and excluded from source control by default.

## Evidence boundaries

White Radar distinguishes three classes of input:

| Class | Examples | Persistence |
|---|---|---|
| On-chain evidence | Blocks, receipts, logs, code, storage, call results | Normalized fields and hashes |
| Provider observation | Pending messages, trace responses | Bounded metadata and summaries |
| Operator context | Protocol labels, contacts, policy baselines | Local inventory and policy records |

Reports preserve this distinction so provider visibility, operator context, and confirmed-chain
facts are not silently merged into one claim.

Routine pending observations are stored in aggregate telemetry buckets. Only protocol-specific
evidence promotes them into normalized events, identity relationships, incidents, or Telegram
cards.

## Repository boundaries

The source repository contains the engine, schemas, sanitized examples, tests, and deployment
templates. Operational files remain local:

- `.env`;
- `watchlist.toml`;
- `policies.toml`;
- SQLite databases and WAL files;
- logs, reports, and evidence exports.

Generated transaction case bundles under `evidence/` are operational artifacts and are ignored by
source control.

See [Repository privacy](REPOSITORY_PRIVACY.md) for the recommended public/private split.
