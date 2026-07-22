# Telegram alerts

White Radar renders evidence-first Telegram cards for promoted guard cases. Transaction
investigation itself writes a local evidence bundle and does not require Telegram.

## Case fields

Depending on event type and available evidence, a card can include:

- event title, priority, severity, and confidence;
- network, chain ID, block, transaction, contract, and observed actor;
- protocol/component label;
- verified contract name and metadata source;
- runtime bytecode size and proxy state;
- sender, selector, verified function signature, native value, and fee fields;
- policy baseline state and finding codes;
- simulation status and pinned block;
- trace call count, depth, delegated calls, and creations;
- invariant name, status, and observed value;
- effective proxy implementation;
- related deployment cluster;
- score reasons, next analysis action, and stable case ID;
- direct transaction and contract explorer links.

All dynamic text is HTML-escaped before delivery.

## Delivery controls

`minimum_score` controls case delivery. Routine pending token traffic is not an event: it remains in
hourly aggregate telemetry and cannot produce an individual Telegram card.

```toml
[telegram]
enabled = true
minimum_score = 60
send_testnet_alerts = false
```

```dotenv
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
WHITE_RADAR_DRY_RUN=true
```

Preview the newest case:

```bash
white-radar preview-alert
```

Set `WHITE_RADAR_DRY_RUN=false` when delivery is ready.

## Alert outbox

Eligible events are persisted before delivery. A Telegram failure leaves the event unalerted so a
later scanner cycle can retry it. This prevents delivery availability from controlling chain
cursor progress.

## Digests

```bash
white-radar digest --hours 24
white-radar digest --hours 1 --send
```

The digest contains:

- case counts by severity;
- network and event-type totals;
- open and overdue incident counts;
- highest-priority case summaries.
- aggregate pending telemetry totals and the busiest protocol/selector groups.

Printing is the default. `--send` requires Telegram enabled, credentials present, and dry-run
disabled.

## Operational verification

1. Run one confirmed scan and one invariant cycle.
2. Inspect `white-radar events`.
3. Render `white-radar preview-alert`.
4. Tune `minimum_score` and testnet delivery.
5. Send one manual digest.
6. Enable the digest timer.
