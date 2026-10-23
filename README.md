# cisco-g0-monitor

Watches every Cisco IOS / IOS-XE router in your inventory and alerts by **email (queued through TrackIT `logbulkmail`, the same way the Teltonika SMS Console sends its alerts)** and optionally **Microsoft Teams / Slack** when:

| Event | Severity | When |
|---|---|---|
| `INTERNET_DOWN` | critical | Pings sourced from G0/0 fail on *all* targets for 2 checks in a row (or G0/0 is down / has no IP) |
| `INTERNET_RESTORED` | ok | Pings succeed again for 2 checks; includes downtime |
| `INTERNET_STILL_DOWN` | critical | Reminder every 60 min while down |
| `SUBNET_CHANGED` | warning | G0/0 network differs from the last known one (e.g. `203.0.113.0/29 → 198.51.100.4/30`); new subnet becomes the baseline |
| `SUBNET_MISMATCH` | critical | Device has `expected_subnet` pinned and G0/0 is outside it |
| `ADDRESS_LOST` / `ADDRESS_RESTORED` | critical / ok | G0/0 has no IP (e.g. DHCP lease lost) |
| `IP_CHANGED` | info | IP changed inside the same subnet (logged; alert only if enabled) |
| `DEVICE_UNREACHABLE` / `DEVICE_REACHABLE` | critical / ok | SSH to the router fails 2x in a row (internet state is left as "unknown", not "down") |

All events from one cycle are sent as **one** email / card, so a regional outage doesn't flood the inbox.

## How each check works

Every `interval_seconds` (default 5 min), for each router in parallel, over SSH:

1. `show ip interface GigabitEthernet0/0` → line status, IP/prefix, subnet, static vs DHCP
2. `ping [vrf X] 8.8.8.8 source GigabitEthernet0/0 repeat 5 timeout 2` → success %. If the first target passes, the rest are skipped; internet is OK if **any** target reaches `min_success_percent` (60%).

Sourcing the ping from G0/0 tests that interface's internet path, not just "the router can reach the internet some other way".

State is kept in a Docker volume (`/data/state.json`), so restarts don't re-alert or forget the baseline subnet. Every event is also appended to `/data/events.jsonl`.

## Quick start

```bash
cp .env.example .env                                   # router login, TrackIT DB, alert recipient
cp config/devices.yaml.example  config/devices.yaml    # your routers
cp config/settings.yaml.example config/settings.yaml   # interval, thresholds, which channels are on

docker compose build
docker compose run --rm cisco-g0-monitor --test-alert           # queues a test email in TrackIT logbulkmail
docker compose run --rm cisco-g0-monitor --check rtr-hq-01      # test one router, prints raw result
docker compose up -d
docker compose logs -f
docker compose exec cisco-g0-monitor python -m monitor.main --status   # status table
```

The first cycle learns each router's G0/0 subnet as its baseline (no alert). From then on, changes are alerted.

## How email is sent (TrackIT, same as Teltonika)

The monitor does not talk to a mail server. Like `trackitDeviceFaultAlert.ts` in the Teltonika SMS Console, it inserts one row per recipient into TrackIT's `logbulkmail` table and TrackIT's mailer sends it:

| Column | Value |
|---|---|
| `dates`, `times` | `CURDATE()`, `CURTIME()` |
| `sendto` | each address in `CISCO_ALERT_RECIPIENT` |
| `mailsubject` | e.g. `Cisco G0/0 alert: INTERNET DOWN on rtr-143 (GigabitEthernet0/0) [AC5AAA66C2]` |
| `mailcontent` | HTML table: Device, Host, Severity, Details, Detected, plus a `<!-- CISCO-G0-MONITOR-REPORT-… -->` marker |
| `mailstatus` / `mailtype` | `Queue in Database` / `Email` |
| `cc`, `attachment` | `0`, `0` |
| `spoofas` / `spoofname` | `CISCO_ALERT_FROM` (blank = recipient) / `Cisco G0/0 Monitor` |
| `priority` | `1` |

- **No duplicates:** the subject ends with a report ID that is a hash of the events. A row with the same `sendto` + `mailsubject` is never inserted twice, and the SELECT + INSERT run in one transaction.
- **TrackIT DB down:** the report is kept in `/data/trackit_outbox.json` and retried every cycle until it is inserted. `--status` shows how many are waiting.
- **DB account:** needs only `SELECT, INSERT` on `logbulkmail`:
  ```sql
  CREATE USER 'cisco_monitor'@'<docker-host-ip>' IDENTIFIED BY '<password>';
  GRANT SELECT, INSERT ON trackitlive.logbulkmail TO 'cisco_monitor'@'<docker-host-ip>';
  ```
  Or reuse the `TRACKIT_DB_*` values from the Teltonika console's `.env`.
- `TRACKIT_DB_HOST` must be the MariaDB server's IP, **not** `127.0.0.1` (inside Docker that is the container). If MariaDB runs on the same machine as Docker, use `host.docker.internal`, and make sure MariaDB listens on that interface (`bind-address`) and allows that user from the Docker network.

Direct SMTP is still available (`notify.email.enabled: true`) but is off by default.

## Inventory (`config/devices.yaml`)

```yaml
defaults:
  device_type: cisco_ios          # or cisco_xe
  username: ${CISCO_USERNAME}
  password: ${CISCO_PASSWORD}
  secret: ${CISCO_ENABLE_SECRET}
  interface: GigabitEthernet0/0
  ping_targets: [8.8.8.8, 1.1.1.1]
devices:
  - { name: rtr-hq-01,      host: 10.10.0.1 }
  - { name: rtr-branch-mdn, host: 10.30.0.1, interface: GigabitEthernet0/0/0, vrf: INTERNET }
  - { name: rtr-dc-01,      host: 10.40.0.1, expected_subnet: 203.0.113.0/29 }
```

Any field can be overridden per device (credentials, interface name, VRF, ping targets). `enabled: false` skips a device. After editing, `docker compose restart`.

## Router-side setup

Create a dedicated login. The account must be able to run `show ip interface` and `ping ... source`:

```
username netmon privilege 15 algorithm-type scrypt secret <strong-password>
ip ssh version 2
line vty 0 4
 transport input ssh
 login local
```

Least-privilege alternative (verify with `--check` on one router first):

```
privilege exec level 5 show ip interface
privilege exec level 5 ping
username netmon privilege 5 algorithm-type scrypt secret <strong-password>
```

## Teams webhook

Teams → channel → **⋯ → Workflows → "Post to a channel when a webhook request is received"** → copy the URL into `TEAMS_WEBHOOK_URL`. Alerts arrive as Adaptive Cards. (Older "Incoming Webhook" connector URLs also accept this format.)

## Things to know

- **Where to run it:** the Docker host must reach each router's management IP over SSH (TCP 22) via a path that **doesn't depend on that router's G0/0** (LAN, MPLS, VPN from HQ). Otherwise an internet outage looks like "device unreachable".
- **ICMP must be allowed out G0/0.** If an ISP or an outbound ACL blocks ICMP to 8.8.8.8, change `ping_targets` to something reachable (ISP gateway, a host you own).
- **Flapping links:** raise `thresholds.failure` to alert later, or lower `interval_seconds` for faster detection (e.g. 60s × 2 failures ≈ 2 min).
- **Large fleets:** with 5 pings × 2s timeout, a fully down router takes ~25s to check. `max_workers: 10` handles ~100 routers in a 5-min interval; raise it for more.

## Project layout

```
monitor/
  collector.py   SSH (Netmiko) + run commands
  parsers.py     parse `show ip interface` and ping output
  engine.py      state machine: thresholds, baselines, events (pure logic, unit-tested)
  notifier.py    dispatch to TrackIT / SMTP / Teams / Slack
  trackit.py     TrackIT logbulkmail queue (+ retry outbox)
  state.py       state.json, events.jsonl, heartbeat
  main.py        loop + CLI (--once, --check, --status, --test-alert)
  healthcheck.py Docker HEALTHCHECK
tests/           pytest suite with simulated IOS / IOS-XE output
```

Run tests: `pip install -r requirements.txt pytest && python -m pytest -q`
