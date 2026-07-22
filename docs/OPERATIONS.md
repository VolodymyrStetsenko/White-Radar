# Operations

## Workload topology

A complete single-host deployment separates one on-demand workflow and five service workloads:

| Workload | Process | Cadence |
|---|---|---|
| Transaction reconstruction | `white-radar investigate` | On demand per confirmed seed transaction |
| Confirmed ingestion | `white-radar daemon` | Continuous |
| Quiet protocol guard | `white-radar watch-pending --chain NAME` | Continuous per selected chain |
| Profile refresh | `white-radar refresh-profiles` | Scheduled |
| Digest | `white-radar digest` | Scheduled |
| Health verification | `white-radar health` | Scheduled and externally observed |

Service workloads share the same configuration and SQLite database. Investigation bundles are
written under `evidence/` or an explicit output directory. WAL mode supports the expected
single-host concurrency. Do not run multiple confirmed scanners for the same chain/database.

## Local installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

white-radar init
white-radar doctor
white-radar doctor --online
```

The online doctor checks every configured HTTP endpoint independently and confirms its chain ID
without printing endpoint values.

Run a bounded end-to-end cycle:

```bash
white-radar run-once --chain ethereum
white-radar check-invariants --chain ethereum
white-radar refresh-profiles --chain ethereum --limit 10 --min-age-minutes 0
white-radar status
white-radar preview-alert
```

Create one bounded cross-transaction bundle independently of the inventory:

```bash
white-radar investigate \
  --chain ethereum \
  --tx-hash 0xCONFIRMED_TRANSACTION_HASH \
  --backward-blocks 256 \
  --forward-blocks 512 \
  --max-hops 3 \
  --max-transactions 100 \
  --history-source auto
```

For large search windows, configure `ETHERSCAN_API_KEY` so indexed address history is used. The
portable RPC fallback scans bounded blocks and standard transfer logs and can consume substantial
provider capacity. Use `--single-transaction` for an isolated execution bundle.

Run continuous workloads in separate terminals:

```bash
white-radar daemon --chain ethereum
```

```bash
white-radar watch-pending --chain ethereum
```

## Configuration deployment

Keep runtime configuration outside the application checkout in production:

- environment: `/etc/white-radar/white-radar.env`;
- application configuration: `/etc/white-radar/config.toml`;
- protocol inventory: `/etc/white-radar/watchlist.toml`;
- policy pack: `/etc/white-radar/policies.toml`;
- database: `/var/lib/white-radar/white-radar.sqlite3`.

Set file permissions so the service account can read configuration and write only the data
directory.

## RPC redundancy

Configure an ordered provider set through environment-variable names:

```toml
rpc_http_env = "RPC_ETHEREUM_HTTP"
rpc_http_fallback_envs = ["RPC_ETHEREUM_HTTP_SECONDARY"]
rpc_ws_env = "RPC_ETHEREUM_WS"
rpc_ws_fallback_envs = ["RPC_ETHEREUM_WS_SECONDARY"]
```

Use independent provider infrastructure when outage correlation matters. `doctor --online`
validates every present HTTP endpoint. Runtime HTTP calls rotate on transport/method failures;
pending observers rotate WebSocket endpoints after disconnects.

The heartbeat payload exposes endpoint index and endpoint count, never endpoint URLs.

## Analysis controls

```toml
[analysis]
abi_resolution_enabled = true
pending_simulation_enabled = true
pending_simulation_minimum_score = 70
trace_call_enabled = false
invariant_checks_enabled = true
```

Operational impact:

| Setting | RPC/external cost |
|---|---|
| `abi_resolution_enabled` | Explorer request on uncached investigation or promoted-guard contracts |
| `pending_simulation_enabled` | One `eth_call` for selected pending cases |
| `trace_call_enabled` | One provider-specific `debug_traceCall` for selected cases |
| `invariant_checks_enabled` | One `eth_call` per configured invariant per scanner cycle |
| `trace_internal_creations` | One `debug_traceTransaction` per eligible confirmed transaction |

Start with bounded inventory and thresholds, record provider consumption, then tune the cadence and
limits.

## systemd

The provided units assume:

- checkout: `/opt/white-radar`;
- virtual environment: `/opt/white-radar/.venv`;
- service account: `white-radar`;
- external configuration and data paths described above.

Install and enable the full workload set:

```bash
sudo cp deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload

sudo systemctl enable --now white-radar.service
sudo systemctl enable --now white-radar-pending@ethereum.service
sudo systemctl enable --now white-radar-refresh@ethereum.timer
sudo systemctl enable --now white-radar-health.timer
```

Enable Telegram digests after a successful manual send:

```bash
white-radar --config /etc/white-radar/config.toml digest --hours 1 --send
sudo systemctl enable --now white-radar-digest.timer
```

Inspect services:

```bash
systemctl status white-radar.service
systemctl status white-radar-pending@ethereum.service
systemctl list-timers 'white-radar*'
journalctl -u white-radar.service -f
```

The units use a dedicated account, an empty capability set, a read-only application/configuration
filesystem, restricted address families, private temporary/device namespaces, and a single writable
data path.

## Docker Compose

```bash
cp .env.example .env
cp config.example.toml config.toml
cp watchlist.example.toml watchlist.toml
cp policies.example.toml policies.toml
mkdir -p data

docker compose build
docker compose run --rm white-radar doctor --online
docker compose up -d white-radar
```

The Compose service runs the confirmed scanner. Run additional one-off commands in the same
container image:

```bash
docker compose run --rm white-radar check-invariants --chain ethereum
docker compose run --rm white-radar inspect-proxy \
  --chain ethereum \
  --address 0x1111111111111111111111111111111111111111
```

For a complete continuous multi-process topology, systemd is the included orchestrator.

## Telegram activation

Keep `WHITE_RADAR_DRY_RUN=true` while verifying rendering:

```bash
white-radar events --limit 20
white-radar preview-alert
white-radar digest --hours 24
```

Then set:

```dotenv
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
WHITE_RADAR_DRY_RUN=false
```

Confirm one manual delivery before enabling the digest timer.

## Health and external monitoring

```bash
white-radar status
white-radar health
white-radar health --stale-after 180
```

`health` exits non-zero for missing, stale, or degraded expected services. The local timer detects
stale application heartbeats; an external host monitor must detect a complete machine, network, or
timer failure.

Recommended external checks:

- systemd unit state and restart count;
- `white-radar health` exit status;
- database filesystem capacity and inode availability;
- NTP/clock synchronization;
- provider quota and error rate;
- Telegram delivery failures;
- age and verification status of the latest backup.

## Evidence export

```bash
white-radar events --limit 100
white-radar export evidence/events-$(date -u +%Y%m%dT%H%M%SZ).jsonl
white-radar report --event-id CASE_ID --output evidence/CASE_ID.md
white-radar graph --chain ethereum --address 0xADDRESS --depth 2
```

Evidence exports and reports can contain operational addresses and protocol context. Store them in
the designated evidence location, not in the source tree.

## Backups

Use the SQLite backup API/CLI or stop all White Radar writers before copying the database. Copying
only the main database file while WAL activity is present can omit committed pages.

A backup procedure should record:

- database checksum;
- creation timestamp;
- application commit;
- configuration and policy digests;
- restore-test status.

## Recovery

1. Stop confirmed, pending, and scheduled write workloads.
2. Restore the database and verify service-account ownership.
3. Run `white-radar status`.
4. Run `white-radar doctor --online`.
5. Run one bounded confirmed cycle.
6. Inspect cursors, health, events, and incident counts.
7. Restart the continuous workloads.

Do not advance a cursor manually past an unreadable range. Switch providers or restore the last
verified backup, then reprocess the range idempotently.

## Credential rotation

When rotating a provider, explorer, Telegram, or GitHub credential:

1. issue the replacement;
2. update only the external environment/secret store;
3. restart affected services;
4. run online doctor and a delivery test as applicable;
5. revoke the previous credential;
6. verify logs and repository history with the secret scanner.

Repository history deletion is not a substitute for credential revocation.

## Capacity planning

Measure before changing limits:

- blocks and transactions processed per cycle;
- pending messages selected per minute;
- `eth_call` and trace requests per case;
- invariants per scanner cycle;
- explorer cache hit rate;
- SQLite growth and WAL checkpoint behavior;
- alert count by score and event type;
- false-positive disposition rate;
- time from observation to acknowledgement.

For multi-host ingestion or sustained high write concurrency, move to the database/queue topology
described in the roadmap.
