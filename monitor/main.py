"""cisco-g0-monitor: watch G0/0 internet reachability and subnet changes on Cisco routers.

Usage:
  python -m monitor.main                 # run forever (Docker default)
  python -m monitor.main --once          # one cycle, then exit
  python -m monitor.main --check rtr-01  # debug one device, print raw result, no state/alerts
  python -m monitor.main --status        # print last known status table
  python -m monitor.main --test-alert    # send a test message to every enabled channel
  python -m monitor.main --diagnose all  # read-only diagnostics + AI diagnosis now
  python -m monitor.main --history all   # incident history, uptime, latency trend
  python -m monitor.main --backup        # back up running-configs now, report diffs
  python -m monitor.main --report        # send the weekly report now
  python -m monitor.main --audit all     # security audit of running-configs, emails the report
  python -m monitor.main --audit-fix rtr-143   # remediation script for one router
  python -m monitor.main --accept all "SHA-1 methods only" --reason "1921 IOS limitation"
  python -m monitor.main --proposals     # list proposed fixes
  python -m monitor.main --approve A7K3  # run a proposed fix after re-checking the fault
  python -m monitor.main --reject A7K3
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from . import actions, backup, posture, report, trends
from .collector import _default_connect, check_device
from .diagnose import diagnose_cycle
from .history import History
from .config import load_devices, load_settings
from .engine import INFO, Event, evaluate
from .notifier import Notifier
from .state import StateStore

log = logging.getLogger("monitor")
_stop = threading.Event()


def run_cycle(devices, settings, store: StateStore, notifier: Notifier, connect=_default_connect,
              now_fn=lambda: datetime.now().astimezone(), ai_client=None, hist: History = None) -> list:
    active = [d for d in devices if d.enabled]
    hist = hist or History(os.path.join(store.dir, "history.db"))
    states = store.load()
    results = {}
    with ThreadPoolExecutor(max_workers=max(1, int(settings["max_workers"]))) as pool:
        futures = {pool.submit(check_device, d, settings, connect): d for d in active}
        for fut in as_completed(futures):
            results[futures[fut].name] = fut.result()

    now = now_fn()
    all_events = []
    new_states = {}
    for d in active:
        r = results[d.name]
        st, events = evaluate(states.get(d.name), r, d, settings, now)
        new_states[d.name] = st
        all_events.extend(events)
        if not r.reachable:
            log.warning("%-20s %-15s UNREACHABLE  %s", d.name, d.host, r.error)
        else:
            log.info("%-20s %-15s %s=%s (%s) %s/%s internet=%s ping=%s%s",
                     d.name, d.host, d.interface, r.ip or "-", r.network or "-",
                     r.intf_status, r.intf_protocol,
                     {True: "OK", False: "FAIL", None: "?"}[r.internet_ok],
                     r.ping or "-", f"  [{r.error}]" if r.error else "")
    store.save(new_states)  # devices removed from inventory drop out of state here

    # Stage 2: trend warnings from history (latency creeping up, packet loss, flapping)
    try:
        all_events += trends.detect(hist, active, new_states, settings, now)
    except Exception:  # noqa: BLE001
        log.exception("Trend detection failed")

    # Stage 2: daily config backup (runs inside the cycle after the configured hour, once per day)
    if backup.is_due(hist, settings, now):
        raw_configs: dict = {}
        facts: dict = {}
        try:
            all_events += backup.run(active, settings, hist, now, connect=connect, raw_out=raw_configs, facts_out=facts)
        except Exception:  # noqa: BLE001
            log.exception("Config backup failed")
        # Stage 4: security audit of today's configs (report only when something changed)
        if raw_configs and settings.get("audit", {}).get("enabled", True):
            try:
                posture.run_audit(hist, settings, raw_configs, active, now, notifier=notifier, client=ai_client, facts=facts)
            except Exception:  # noqa: BLE001
                log.exception("Security audit failed")
        raw_configs.clear()

    # Stage 3: expire old proposals / drop ones whose router recovered by itself
    try:
        all_events += actions.housekeeping(hist, new_states, now)
    except Exception:  # noqa: BLE001
        log.exception("Proposal housekeeping failed")

    for e in all_events:
        log.log(logging.WARNING if e.severity in ("critical", "warning") else logging.INFO,
                "EVENT %s%s: %s - %s", e.kind, "" if e.notify else " (not notified)", e.title, e.detail)

    # Stage 1 AI: investigate alert-worthy events before notifying (never blocks the alert on failure)
    diagnosis = diagnose_cycle(all_events, active, results, new_states, settings, store.dir, now,
                               connect=connect, client=ai_client, history=hist)

    store.append_events(all_events)
    try:
        hist.record_cycle(results, all_events, now, diagnosis)
    except Exception:  # noqa: BLE001
        log.exception("Could not write history")
    notifier.send(all_events, diagnosis)

    # Stage 2: weekly report
    if report.is_due(hist, settings, now):
        try:
            report.run(hist, active, settings, now, notifier, client=ai_client)
        except Exception:  # noqa: BLE001
            log.exception("Weekly report failed")
    if now.hour == 4 and now.minute < 10:
        hist.prune(now, int(settings.get("history", {}).get("retention_days", 90)))
    store.heartbeat()
    return all_events


def cmd_diagnose(target: str, devices, settings, store: StateStore) -> int:
    """On-demand diagnosis: `--diagnose rtr-143`, `--diagnose rtr-143,rtr-145` or `--diagnose all`.

    Checks the chosen routers, collects the read-only diagnostics on all of them in parallel,
    and asks Claude ONCE for a fleet-level assessment - the same path a real alert takes.
    """
    from concurrent.futures import ThreadPoolExecutor

    from .diagnose import ask_claude, build_messages, collect

    enabled = [d for d in devices if d.enabled]
    if target.strip().lower() == "all":
        chosen = enabled
    else:
        names = [n.strip() for n in target.split(",") if n.strip()]
        unknown = [n for n in names if n not in {d.name for d in devices}]
        if unknown:
            print(f"Unknown device(s): {', '.join(unknown)}. Known: {', '.join(d.name for d in devices)}")
            return 1
        chosen = [d for d in devices if d.name in names]
    if not settings.get("ai", {}).get("enabled"):
        print("ai.enabled is false in settings.yaml")
        return 1

    now = datetime.now().astimezone()
    print(f"Checking {len(chosen)} router(s): {', '.join(d.name for d in chosen)}")
    with ThreadPoolExecutor(max_workers=max(1, int(settings["max_workers"]))) as pool:
        results = dict(zip([d.name for d in chosen], pool.map(lambda d: check_device(d, settings), chosen)))
    for d in chosen:
        r = results[d.name]
        print(f"  {d.name:16} {d.interface}={r.ip or '-':20} internet_ok={r.internet_ok} reachable={r.reachable} {r.error or ''}")

    print(f"Collecting read-only diagnostics on {len(chosen)} router(s) in parallel (30-90s)...")
    diags = collect(chosen, settings)
    for d in chosen:
        dd = diags[d.name]
        if dd.collected:
            print(f"  {d.name:16} {len(dd.outputs)} commands, gateway={dd.gateway or '?'}, {dd.seconds}s")
        else:
            print(f"  {d.name:16} diagnostics FAILED: {dd.error} (tcp port open: {dd.tcp_port_open})")

    events = []
    for d in chosen:
        r = results[d.name]
        if not r.reachable:
            kind, sev, detail = "DEVICE_UNREACHABLE", "critical", r.error or "SSH failed"
        elif r.internet_ok is False:
            kind, sev, detail = "INTERNET_DOWN", "critical", r.reason or "ping failed"
        else:
            kind, sev, detail = "MANUAL_CHECK", "info", ("No problem detected by the monitor; assess this router's "
                                                        "WAN link health and anything worth watching.")
        title = f"{'Manual diagnosis requested for' if kind == 'MANUAL_CHECK' else kind + ' on'} {d.name}"
        events.append(Event(d.name, d.host, kind, sev, title, detail, now.isoformat(timespec="seconds")))

    hist = History(os.path.join(store.dir, "history.db"))
    hist_ctx = {d.name: hist.summary_for(d.name, now, 30) for d in devices}
    msgs = build_messages(events, devices, results, store.load(), diags, now, hist_ctx)
    print(f"Asking {settings['ai']['model']} for one fleet-level diagnosis (with {len(hist_ctx)} routers' history)...")
    try:
        diag = ask_claude(msgs, settings["ai"])
    except Exception as e:  # noqa: BLE001
        print(f"\nClaude request failed: {type(e).__name__}: {e}")
        print("During live monitoring this would be logged and the alert sent without a diagnosis.")
        return 2
    print()
    print(diag.as_text())
    print(f"\n[{diag.model}: {diag.input_tokens} in / {diag.output_tokens} out tokens, {diag.seconds}s]")
    return 0


def cmd_actions(args, devices, settings, store: StateStore, notifier: Notifier) -> int:
    hist = History(os.path.join(store.dir, "history.db"))
    now = datetime.now().astimezone()
    if args.proposals:
        rows = actions.list_recent(hist)
        if not rows:
            print("No proposals yet.")
            return 0
        print(f"{'ID':5} {'CREATED':17} {'DEVICE':14} {'ACTION':18} {'STATUS':11} RESULT / REASON")
        for r in rows:
            print(f"{r['id']:5} {r['created_at'][:16].replace('T', ' '):17} {r['device']:14} {r['action']:18} "
                  f"{r['status']:11} {(r['result'] or r['reason'] or '')[:70]}")
        return 0
    if args.reject:
        try:
            p = actions.reject(hist, args.reject, now, who=os.environ.get("USERNAME") or os.environ.get("USER") or "operator")
        except ValueError as e:
            print(e)
            return 1
        print(f"Proposal {p['id']} rejected ({p['action']} on {p['device']}).")
        return 0
    pid = args.approve
    p = actions.get(hist, pid)
    if not p:
        print(f"No proposal {pid!r}. Use --proposals to list them.")
        return 1
    dev = next((d for d in devices if d.name == p["device"]), None)
    act = actions.ACTIONS.get(p["action"])
    if not dev or not act:
        print(f"Proposal {pid} refers to an unknown device/action.")
        return 1
    print(f"Proposal {p['id']}: {act.label.format(intf=dev.interface)} on {dev.name} ({dev.host})")
    print(f"  Status: {p['status']}   Expires: {p['expires_at'][:16].replace('T', ' ')}")
    print(f"  Why:    {p['reason']}")
    print(f"  Impact: {act.impact}")
    print("  Commands: " + " ; ".join(actions.render_commands(act, dev)))
    print("Re-checking the router, then running the fix...")
    try:
        p, ev = actions.execute(hist, settings, devices, pid, who=os.environ.get("USERNAME") or os.environ.get("USER") or "operator")
    except ValueError as e:
        print(e)
        return 1
    print()
    print(f"{ev.title}\n{ev.detail}")
    hist.record_cycle({}, [ev], now)
    notifier.send([ev])
    return 0 if p["status"] in ("succeeded", "not_needed") else 2


def cmd_audit(args, devices, settings, store: StateStore, notifier: Notifier) -> int:
    from .audit import fix_script, Finding
    hist = History(os.path.join(store.dir, "history.db"))
    now = datetime.now().astimezone()
    if args.audit_fix:
        rows = posture.open_findings(hist, args.audit_fix)
        if not rows:
            print(f"No open findings for {args.audit_fix!r} (run --audit first, or the router is clean).")
            return 0
        fs = [Finding(r["rule"], r["severity"], r["title"], r["detail"], r["fix"], r["evidence"], r["device"]) for r in rows]
        print(fix_script(fs, args.audit_fix))
        return 0
    if args.accept:
        rows = posture.accept(hist, args.accept[0], args.accept[1], args.reason or "accepted by operator", now)
        for r in rows:
            print(f"accepted  {r['device']:14} {r['title']}")
        print(f"{len(rows)} finding(s) accepted" + ("" if rows else f" - nothing open matches {args.accept[1]!r}"))
        return 0
    if args.unaccept:
        n = posture.unaccept(hist, args.unaccept[0], args.unaccept[1])
        print(f"{n} finding(s) re-opened")
        return 0
    if args.config_diff:
        rows = hist.conn.execute("SELECT device, ts, added, removed, diff FROM configs WHERE diff IS NOT NULL "
                                 "ORDER BY id DESC LIMIT ?", (int(args.config_diff),)).fetchall()
        for r in rows:
            print(f"=== {r['device']} {r['ts'][:16].replace('T', ' ')}  +{r['added']}/-{r['removed']} ===\n{r['diff']}\n")
        print("no config changes recorded" if not rows else "")
        return 0
    chosen = [d for d in devices if d.enabled] if args.audit == "all" else [d for d in devices if d.name in args.audit.split(",")]
    if not chosen:
        print(f"Unknown device(s) {args.audit!r}. Known: {', '.join(d.name for d in devices)}")
        return 1
    print(f"Pulling running-config from {len(chosen)} router(s)...")
    raw: dict = {}
    facts: dict = {}
    backup.run(chosen, settings, hist, now, force=True, raw_out=raw, facts_out=facts)   # also stores today's snapshot/diff
    missing = [d.name for d in chosen if d.name not in raw]
    if missing:
        print(f"Could not fetch: {', '.join(missing)}")
    if not raw:
        return 1
    res = posture.run_audit(hist, settings, raw, chosen, now, notifier=notifier, force_report=True, facts=facts)
    raw.clear()
    for name, fs in res["findings"].items():
        print(f"\n=== {name}: score {res['score'][name]}/100, {len(fs)} finding(s) ===")
        for f in fs:
            tag = "NEW" if f in res["new"] else "   "
            print(f"  {tag} [{f.severity.upper():8}] {f.title}")
    if res["resolved"]:
        print("\nResolved since last audit:")
        for f in res["resolved"]:
            print(f"  [{f.severity.upper():8}] {f.device}: {f.title}")
    print(f"\nReport sent via: {', '.join(notifier.channels()) or 'nothing (no channels enabled)'}. "
          f"Use --audit-fix <router> for a remediation script.")
    return 0


def cmd_history(target: str, devices, store: StateStore, days: int = 30) -> int:
    hist = History(os.path.join(store.dir, "history.db"))
    now = datetime.now().astimezone()
    names = [d.name for d in devices] if target == "all" else [target]
    for name in names:
        s = hist.summary_for(name, now, days)
        print(f"=== {name} - last {days} days ===")
        print(f"  uptime {s['uptime_percent']}%   incidents {s['incidents']}   downtime {s['total_downtime']}   "
              f"ping ok 24h {s['ping_success_last_24h_percent']}%   latency 24h {s['latency_ms']['avg_last_24h']} ms "
              f"(prev 7d {s['latency_ms']['avg_prev_7d']} ms)")
        if s["incidents_by_hour_of_day"]:
            print("  outages by hour:", ", ".join(f"{h:02d}:00 x{n}" for h, n in s["incidents_by_hour_of_day"].items()))
        for i in s["recent_incidents"]:
            print(f"  {i['started']}  {i['kind']:20} {i['duration']:>8}  {i['diagnosis'] or ''}")
        if s["config"]:
            print(f"  config: last backup {s['config']['last_backup']}, {s['config']['lines']} lines, "
                  f"{len(s['config']['recent_changes'])} change(s) in window")
        print()
    return 0


def print_status(store: StateStore) -> None:
    states = store.load()
    if not states:
        print("No state yet - the monitor has not completed a cycle.")
        return
    hdr = f"{'DEVICE':20} {'SSH':5} {'INTERNET':9} {'G0/0 IP':20} {'SUBNET':20} {'LAST CHECK':25}"
    print(hdr)
    print("-" * len(hdr))
    for name, s in sorted(states.items()):
        r = s.get("last_result") or {}
        ssh = {True: "ok", False: "DOWN", None: "?"}[s.get("reachable")]
        print(f"{name:20} {ssh:5} {s.get('internet', '?').upper():9} {str(r.get('ip') or '-'):20} "
              f"{str(s.get('baseline_network') or '-'):20} {str(s.get('last_check') or '-'):25}")
    pending = os.path.join(store.dir, "trackit_outbox.json")
    if os.path.exists(pending):
        with open(pending, encoding="utf-8") as f:
            print(f"\n{len(json.load(f))} TrackIT email report(s) waiting for the database - retried every cycle.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Cisco G0/0 internet + subnet-change monitor")
    p.add_argument("--settings", default="/config/settings.yaml")
    p.add_argument("--devices", default="/config/devices.yaml")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--once", action="store_true", help="run one cycle and exit")
    g.add_argument("--check", metavar="DEVICE", help="check one device and print the raw result")
    g.add_argument("--status", action="store_true", help="print last known status and exit")
    g.add_argument("--test-alert", action="store_true", help="send a test alert and exit")
    g.add_argument("--diagnose", metavar="DEVICE|all", help="read-only diagnostics + AI diagnosis now: a name, a comma-separated list, or all")
    g.add_argument("--history", metavar="DEVICE|all", help="print incident history and trends from history.db")
    g.add_argument("--backup", action="store_true", help="back up all running-configs now and report changes")
    g.add_argument("--report", action="store_true", help="build and send the weekly report now")
    g.add_argument("--audit", metavar="DEVICE|all", help="pull running-configs now and run the security audit (sends the report)")
    g.add_argument("--audit-fix", metavar="DEVICE", help="print a remediation script for a router's open findings")
    g.add_argument("--config-diff", metavar="N", nargs="?", const="4", help="show the last N recorded config changes with their diff")
    g.add_argument("--accept", nargs=2, metavar=("DEVICE|all", "TITLE-TEXT"), help="accept open findings whose title contains TITLE-TEXT (known limitation); use with --reason")
    g.add_argument("--unaccept", nargs=2, metavar=("DEVICE|all", "TITLE-TEXT"), help="undo --accept")
    p.add_argument("--reason", default="", help="why a finding is accepted (with --accept)")
    g.add_argument("--approve", metavar="ID", help="approve and run a proposed fix (ID from the alert email)")
    g.add_argument("--reject", metavar="ID", help="reject a proposed fix")
    g.add_argument("--proposals", action="store_true", help="list recent proposed fixes and their status")
    args = p.parse_args(argv)

    settings = load_settings(args.settings)
    logging.basicConfig(level=getattr(logging, str(settings["log_level"]).upper(), logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(message)s")
    # paramiko logs full tracebacks from its own thread on SSH failures; our check result already
    # carries the error, so only show paramiko's output when log_level is DEBUG.
    debug = str(settings["log_level"]).upper() == "DEBUG"
    logging.getLogger("paramiko").setLevel(logging.DEBUG if debug else logging.CRITICAL)
    logging.getLogger("netmiko").setLevel(logging.WARNING)
    for noisy in ("anthropic", "httpx", "httpx2", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    store = StateStore(settings["state_dir"])
    notifier = Notifier(settings["notify"], state_dir=settings["state_dir"])

    if args.status:
        print_status(store)
        return 0

    if args.test_alert:
        if not notifier.channels():
            print("No notification channels are enabled in settings.yaml")
            return 1
        notifier.send([Event("test-device", "192.0.2.1", "TEST", INFO, "Test alert - monitor is wired up",
                             "If you can read this, notifications from cisco-g0-monitor work.",
                             datetime.now().astimezone().isoformat(timespec="seconds"))])
        return 0

    devices = load_devices(args.devices)

    if args.diagnose:
        return cmd_diagnose(args.diagnose, devices, settings, store)
    if args.history:
        return cmd_history(args.history, devices, store)
    if args.backup:
        hist = History(os.path.join(store.dir, "history.db"))
        evs = backup.run([d for d in devices if d.enabled], settings, hist, datetime.now().astimezone(), force=True)
        for e in evs:
            print(f"{e.kind}: {e.title}\n{e.detail}\n")
        changed = sum(e.kind == "CONFIG_CHANGED" for e in evs)
        first = sum(e.kind == "CONFIG_BACKUP" for e in evs)
        print(f"{changed} config change(s), {first} first snapshot(s) stored" if evs else "All configs unchanged")
        hist.record_cycle({}, evs, datetime.now().astimezone())
        notifier.send(evs)
        return 0
    if args.approve or args.reject or args.proposals:
        return cmd_actions(args, devices, settings, store, notifier)
    if args.audit or args.audit_fix or args.config_diff or args.accept or args.unaccept:
        return cmd_audit(args, devices, settings, store, notifier)
    if args.report:
        hist = History(os.path.join(store.dir, "history.db"))
        out = report.run(hist, [d for d in devices if d.enabled], settings, datetime.now().astimezone(), notifier)
        print(out["text"])
        return 0

    if args.check:
        dev = next((d for d in devices if d.name == args.check), None)
        if not dev:
            print(f"Unknown device {args.check!r}. Known: {', '.join(d.name for d in devices)}")
            return 1
        print(json.dumps(check_device(dev, settings).to_dict(), indent=2))
        return 0

    log.info("Monitoring %d device(s) every %ss; alert channels: %s",
             sum(d.enabled for d in devices), settings["interval_seconds"],
             ", ".join(notifier.channels()) or "none (log only)")

    if args.once:
        run_cycle(devices, settings, store, notifier)
        return 0

    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    signal.signal(signal.SIGINT, lambda *_: _stop.set())
    interval = int(settings["interval_seconds"])
    while not _stop.is_set():
        started = time.monotonic()
        try:
            run_cycle(devices, settings, store, notifier)
        except Exception:  # noqa: BLE001 - keep the loop alive
            log.exception("Cycle failed")
        _stop.wait(max(5, interval - (time.monotonic() - started)))
    log.info("Stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
