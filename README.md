# cisco-g0-monitor

Watches every Cisco IOS / IOS-XE router in your inventory, diagnoses faults with Claude, proposes fixes you approve with one command, and alerts by **email (queued through TrackIT `logbulkmail`, the same way the Teltonika SMS Console sends its alerts)** and optionally **Microsoft Teams / Slack** when:

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

## AI diagnosis (Stage 1 of the agent)

When an alert fires, the monitor investigates before it emails you:

1. Logs back in to each affected router and runs a **fixed, read-only** command set
   (`show version | include uptime`, `show ip interface`, `show interfaces`, `show ip route 0.0.0.0`,
   `show dhcp lease`, `show ip arp`, ping to the learned default gateway and to 8.8.8.8 / google.com
   sourced from G0/0, a short `traceroute`, and the last 40 lines of `show logging`).
   Nothing in `monitor/diagnose.py` can change configuration; the allow-list is asserted at import time.
2. Redacts anything that looks like a password, secret, key or SNMP community.
3. Sends the whole cycle (the alerts, every router's latest check incl. the healthy ones, and the
   diagnostics) to Claude **once** and asks for a structured diagnosis.
4. Puts the diagnosis at the top of the TrackIT email / Teams card / Slack message:
   summary, likely cause, evidence quoted from the router output, recommended actions, confidence.

Example:

> **AI diagnosis** (high confidence, scope: upstream)
> All four routers lost internet at once; their G0/0 links are up but the upstream modem at 192.168.1.1 does not answer.
> **Likely cause:** Upstream modem / ISP outage
> **Recommended actions:** 1. Power-cycle the modem at 192.168.1.1  2. If still down after 5 min, call the ISP

Settings (`config/settings.yaml` → `ai:`), key in `.env` as `ANTHROPIC_API_KEY`:

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Turn the whole feature off with `false` |
| `model` | `claude-sonnet-5-5` | `claude-haiku-5-5` is cheaper, `claude-opus-5-5` stronger |
| `max_per_hour` | `6` | Hard cap on API calls; beyond it alerts go out without a diagnosis |
| `diagnose_reminders` | `false` | Also diagnose the hourly "still down" reminders |
| `timeout_seconds` | `90` | API timeout; the alert is sent without diagnosis if exceeded |

Guarantees: the alert is **always** sent, with or without a diagnosis - API errors, missing key, SSH failures
during diagnostics and the hourly cap all degrade to a plain alert. Diagnosis only runs for
`INTERNET_DOWN`, `SUBNET_CHANGED`, `SUBNET_MISMATCH`, `ADDRESS_LOST` and `DEVICE_UNREACHABLE`;
nothing is sent to the API while everything is healthy. Each diagnosis (with the raw diagnostics) is
appended to `/data/diagnoses.jsonl` for later review.

Cost: a diagnosis is roughly 5-15k input tokens and ~300 output tokens, i.e. a few cents on Sonnet.

Try it without waiting for an outage:

```bash
docker compose run --rm cisco-g0-monitor --diagnose rtr-143          # one router
docker compose run --rm cisco-g0-monitor --diagnose rtr-143,rtr-145  # some
docker compose run --rm cisco-g0-monitor --diagnose all              # whole fleet, one diagnosis
```

## Memory and trends (Stage 2 of the agent)

Everything the monitor sees is kept in `/data/history.db` (SQLite, 90 days by default):
every check with latency, every event, every outage with start/end/duration, every AI diagnosis
and a daily redacted config snapshot per router. Four things are built on it:

**1. History in every diagnosis.** On an alert, Claude also gets each router's last 30 days:
outage count, times of day, durations, previous diagnoses, latency trend and config changes.
So it can say *"4th outage this month on rtr-145, always 02:00-03:00, ~35 min; this is a pattern,
not a one-off - ask the ISP about a maintenance window"* instead of diagnosing from scratch.

**2. Trend warnings before a link fails** (no AI involved, rules over the history):

| Event | Rule (defaults) |
|---|---|
| `LATENCY_DEGRADED` | 24h median round-trip >= 2x the previous week's median and >= 20 ms higher |
| `PACKET_LOSS` | average ping success over 24h below 90% while the link is "up" |
| `FLAPPING` | 3 or more outages in 24h |

Each fires at most once per router per day and goes through the normal alert channels.

**3. Daily config backup with diff.** Once a day (`backup.hour`, 03:00 by default) every router's
`show running-config` is pulled, passwords/keys/communities are redacted, volatile lines are
stripped and the result is stored. If it differs from the previous snapshot you get a
`CONFIG_CHANGED` alert with the unified diff - the usual explanation for "the subnet changed".

**4. Weekly report** (Monday 08:00 by default): per-router uptime, outages, downtime, longest
outage, latency vs last week, ping success and config changes, with a short narrative and
recommendations from Claude (one API call a week; the table is sent even if that fails).

Commands:

```bash
docker compose run --rm cisco-g0-monitor --history all     # incidents, uptime, latency per router
docker compose run --rm cisco-g0-monitor --backup          # back up configs now, print any diffs
docker compose run --rm cisco-g0-monitor --report          # send the weekly report now
```

Inspect the database directly: `docker compose exec cisco-g0-monitor python -c "import sqlite3;print(sqlite3.connect('/data/history.db').execute('select device,kind,started_at,duration_s from incidents order by id desc limit 10').fetchall())"`

## Fixing things with your approval (Stage 3 of the agent)

When the diagnosis points at a specific router (not the modem/ISP), Claude may propose **one** fix
from a fixed catalogue. The alert then carries a "Proposed fix" box with a 4-letter ID, the exact
commands, the expected impact, and the approve command:

```
docker compose run --rm cisco-g0-monitor --approve BTHW
```

| Action | Commands | Impact | Proposed when |
|---|---|---|---|
| `clear_arp_nat` | `clear arp-cache interface G0/0`, `clear ip nat translation *` | none | link up with a lease, but the gateway does not answer (stale ARP, e.g. after a modem swap) |
| `renew_dhcp` | `release dhcp G0/0`, `renew dhcp G0/0` | ~10 s | link up but no / stale / wrong-subnet lease, modem answers ARP |
| `bounce_interface` | `interface G0/0` → `shutdown`, 5 s, `no shutdown` | ~30-40 s | interface down/down or wedged, errors climbing, or renew already failed |

What happens on `--approve`:

1. The router is re-checked. If it already recovered, nothing runs (`not_needed`).
2. The commands run exactly as shown. `bounce_interface` always sends `no shutdown`, even if the
   session drops mid-way. Nothing ever writes to startup-config.
3. After a settle time the router is checked again and a result email goes out: **Fix BTHW WORKED**
   (before/after) or **DID NOT WORK** with the next step (escalate).
4. Everything is recorded in `history.db` (`proposals` table): who approved, when, command output,
   before/after state.

Guard rails: nothing runs without `--approve`; one pending proposal per router; proposals expire after
`actions.expire_hours`; a proposal is dropped automatically if the router recovers on its own; the same
action on the same router at most once per `actions.cooldown_hours`; at most `actions.max_per_day`
executed actions per day; never proposed for routers that are unreachable over SSH or for fleet-wide
(upstream) outages; the catalogue is the only thing that can run - Claude picks from it, it cannot
invent commands.

```bash
docker compose run --rm cisco-g0-monitor --proposals      # list proposals and outcomes
docker compose run --rm cisco-g0-monitor --reject BTHW
```

Set `actions.enabled: false` to go back to diagnose-only.

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
  diagnose.py    Stage 1 AI: read-only diagnostics + Claude diagnosis
  history.py     Stage 2: SQLite memory (checks, events, incidents, diagnoses, configs)
  trends.py      Stage 2: latency / packet-loss / flapping warnings
  backup.py      Stage 2: daily running-config backup + diff
  report.py      Stage 2: weekly report
  actions.py     Stage 3: fix catalogue, proposals, approved execution with verification
  state.py       state.json, events.jsonl, heartbeat
  main.py        loop + CLI (--once, --check, --status, --test-alert, --diagnose, --history, --backup, --report, --proposals, --approve, --reject)
  healthcheck.py Docker HEALTHCHECK
tests/           pytest suite with simulated IOS / IOS-XE output
```

Run tests: `pip install -r requirements.txt pytest && python -m pytest -q`
