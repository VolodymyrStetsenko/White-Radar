# Telegram alerts

The original low-context format is replaced by an evidence-first case card.

## Case fields

- product and event title;
- priority score, severity band, and confidence;
- network, chain ID, block, contract, and deployer;
- verified name and verification source;
- runtime bytecode size;
- EIP-1967 proxy and implementation details;
- number of related contracts from the same deployer in 24 hours;
- up to five related contract labels and blocks;
- explainable score reasons;
- a safe recommended action;
- stable case ID;
- transaction, contract, and authorized-scope buttons.

## Noise controls

`minimum_score` controls Telegram delivery, not evidence collection. Lower-scored cases remain in
SQLite for search and export. Testnet alerts are independently disabled by default.

Pending alerts are generated only for explicitly watchlisted destinations. A selector match is a
protocol-configured triage signal, not proof of an attack.

## Digests

`white-radar digest --hours 24` renders a compact summary of case counts by severity, network, and
signal type plus the highest-priority cases. Printing is the default. `--send` is an explicit action
and still respects Telegram configuration and dry-run mode.

## Safe rollout

1. Keep `WHITE_RADAR_DRY_RUN=true`.
2. Run confirmed scanners for several cycles.
3. Inspect `white-radar events` and `white-radar preview-alert`.
4. Tune the watchlist and `minimum_score`.
5. Use a private Telegram chat or channel.
6. Set `WHITE_RADAR_DRY_RUN=false` only after review.
