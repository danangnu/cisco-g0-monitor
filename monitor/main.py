"""cisco-g0-monitor: watch G0/0 internet reachability and subnet changes on Cisco routers.

Usage:
  python -m monitor.main                 # run forever (Docker default)
  python -m monitor.main --once          # one cycle, then exit
  python -m monitor.main --check rtr-01  # debug one device, print raw result, no state/alerts
  python -m monitor.main --status        # print last known status table
  python -m monitor.main --test-alert    # send a test message to every enabled channel
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

from .collector import _default_connect, check_device
from .diagnose import diagnose_cycle
from .config import load_devices, load_settings
from .engine import INFO, Event, evaluate
from .notifier import Notifier
from .state import StateStore

log = logging.getLogger("monitor")
_stop = threading.Event()


def run_cycle(devices, settings, store: StateStore, notifier: Notifier, connect=_default_connect,
              now_fn=lambda: datetime.now().astimezone(), ai_client=None) -> list:
    active = [d for d in devices if d.enabled]
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
    for e in all_events:
        log.log(logging.WARNING if e.severity in ("critical", "warning") else logging.INFO,
                "EVENT %s: %s - %s", e.kind, e.title, e.detail)

    store.save(new_states)  # devices removed from inventory drop out of state here

    # Stage 1 AI: investigate alert-worthy events before notifying (never blocks the alert on failure)
    diagnosis = diagnose_cycle(all_events, active, results, new_states, settings, store.dir, now,
                               connect=connect, client=ai_client)

    store.append_events(all_events)
    notifier.send(all_events, diagnosis)
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

    msgs = build_messages(events, devices, results, store.load(), diags, now)
    print(f"Asking {settings['ai']['model']} for one fleet-level diagnosis...")
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
