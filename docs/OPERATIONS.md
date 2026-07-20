# Operations

## Local service

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
white-radar init
white-radar doctor --online
white-radar run-once --chain ethereum
```

Keep `WHITE_RADAR_DRY_RUN=true` until event scoring and alert previews have been reviewed.

## Mainnet rollout checklist

- [ ] use a dedicated provider key with only the required products;
- [ ] verify every endpoint with `doctor --online`;
- [ ] keep all signer/private-key material outside this host;
- [ ] store `.env`, `watchlist.toml`, and `data/` outside the public repository;
- [ ] start with one chain and a small confirmed range;
- [ ] inspect event volume and RPC usage for 24 hours;
- [ ] tune confirmations and `max_blocks_per_cycle`;
- [ ] add only authorized watchlist records;
- [ ] preview Telegram cases before enabling delivery;
- [ ] back up the SQLite database and periodically export JSONL evidence;
- [ ] configure host monitoring for process restarts, disk space, and clock drift.

## Docker Compose

```bash
cp .env.example .env
cp config.example.toml config.toml
cp watchlist.example.toml watchlist.toml
mkdir -p data

docker compose build
docker compose run --rm white-radar doctor --online
docker compose up -d
docker compose logs -f white-radar
```

The container runs as a non-root user, drops Linux capabilities, uses a read-only root filesystem,
and writes only to the mounted `data/` directory.

## systemd

The example unit assumes:

- repository: `/opt/white-radar`;
- virtual environment: `/opt/white-radar/.venv`;
- secrets: `/etc/white-radar/white-radar.env`;
- configuration: `/etc/white-radar/config.toml`;
- watchlist: `/etc/white-radar/watchlist.toml`;
- data: `/var/lib/white-radar`;
- service account: `white-radar`.

Review and adjust paths before installation. The service unit applies filesystem, privilege, kernel,
device, and network-family restrictions. It permits outbound IPv4/IPv6 because RPC, explorer, and
Telegram APIs are required.

## Backups

For a consistent live SQLite backup, use SQLite's backup command or stop the service before copying
the database. Copying only the main file while WAL writes are active may be incomplete.

Also export portable evidence:

```bash
white-radar export evidence/events-$(date -u +%Y%m%dT%H%M%SZ).jsonl
```

## Recovery

1. Stop the service.
2. Restore the database and verify ownership/permissions.
3. Run `white-radar status`.
4. Run `white-radar doctor --online`.
5. Start one `run-once` cycle and inspect its block range.
6. Resume the daemon.

Do not manually move a cursor forward to hide a failed range. If a provider cannot serve the range,
switch to a compatible endpoint or restore from the last known-good backup.

## Key rotation

Rotate a credential immediately if it was included in an archive, pasted into a public issue,
committed, logged, or otherwise disclosed. Update the environment file and restart the service.
Never rely on deleting Git history as the only remediation.

## Pending observer

Run pending monitoring as a separate process so it cannot starve confirmed-block ingestion:

```bash
white-radar watch-pending --chain ethereum
```

Use a provider plan that explicitly supports the chosen subscription. The observer automatically
reconnects with bounded exponential backoff, but provider-level gaps remain possible.
