"""Stage 3: remediation with human approval.

Flow
  1. During diagnosis Claude may propose ONE action from the catalogue below for ONE router.
  2. The monitor validates it (known action, known device, applicable to the alert, no cooldown,
     no other pending proposal for that device), stores it with a short ID and an expiry, and
     puts a "Proposed fix" box in the alert with the approve command.
  3. A human runs `--approve <ID>`. The monitor re-checks that the fault still exists, runs the
     fixed command sequence, waits, re-checks, and emails the before/after result.
  4. Nothing in this module ever runs without that approval, and the only commands that can run
     are the literal templates in ACTIONS (only the interface name is substituted).

Design rules
  - No `write memory`: nothing here changes the saved configuration.
  - `bounce_interface` always brings the interface back up, even if the process is interrupted.
  - One pending proposal per router; a proposal expires after `actions.expire_hours`.
  - The same action on the same router at most once per `actions.cooldown_hours`.
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional

from .collector import _default_connect, check_device
from .config import Device
from .engine import CRITICAL, INFO, OK, WARNING, Event
from .history import History

log = logging.getLogger(__name__)

DEFAULTS = {"enabled": True, "expire_hours": 4, "cooldown_hours": 6, "max_per_day": 4}


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    risk: str                      # low | medium
    impact: str                    # what the user will notice
    applies_to: tuple              # alert kinds this makes sense for
    exec_cmds: tuple = ()          # privileged-exec commands, run in order
    config_cmds: tuple = ()        # config-mode lines, sent as one block
    restore_cmds: tuple = ()       # config-mode lines ALWAYS sent afterwards (even on error)
    pause_seconds: int = 0         # wait between config_cmds and restore_cmds
    settle_seconds: int = 15       # wait before verifying
    when: str = ""                 # guidance for Claude


ACTIONS: dict[str, Action] = {
    "clear_arp_nat": Action(
        id="clear_arp_nat", label="Clear ARP cache on {intf} and NAT translations", risk="low",
        impact="No outage; existing NAT sessions are re-created on the next packet.",
        applies_to=("INTERNET_DOWN", "PACKET_LOSS"),
        exec_cmds=("clear arp-cache interface {intf}", "clear ip nat translation *"),
        settle_seconds=10,
        when="The interface is up/up with a valid lease but the gateway does not answer (stale ARP entry for the "
             "modem, e.g. after a modem swap), or NAT appears stuck while the gateway itself pings.",
    ),
    "renew_dhcp": Action(
        id="renew_dhcp", label="Release and renew the DHCP lease on {intf}", risk="low",
        impact="About 10 seconds without internet on this router while the lease is renewed.",
        applies_to=("INTERNET_DOWN", "ADDRESS_LOST", "SUBNET_MISMATCH"),
        exec_cmds=("release dhcp {intf}", "renew dhcp {intf}"),
        settle_seconds=20,
        when="The interface is up/up but has no address, a stale/expired lease, or an address on the wrong subnet "
             "(e.g. APIPA 169.254.x.x or the modem's old subnet after a re-provision) and the modem answers ARP.",
    ),
    "bounce_interface": Action(
        id="bounce_interface", label="Bounce {intf} (shutdown, wait 5 s, no shutdown)", risk="medium",
        impact="About 30-40 seconds without internet on this router; renegotiates link and DHCP with the modem.",
        applies_to=("INTERNET_DOWN", "ADDRESS_LOST"),
        config_cmds=("interface {intf}", "shutdown"),
        restore_cmds=("interface {intf}", "no shutdown"),
        pause_seconds=5, settle_seconds=40,
        when="The interface or line protocol is down/down or flapping with a modem that is otherwise reachable, "
             "input errors are climbing, or renew_dhcp already failed. Do not propose for an upstream/ISP outage.",
    ),
}
assert all(not any(w in " ".join(a.exec_cmds + a.config_cmds + a.restore_cmds)
                   for w in ("write", "copy", "reload", "erase", "delete", "format"))
           for a in ACTIONS.values())
STATES_OPEN = ("pending",)
STATES_DONE = ("approved", "rejected", "expired", "superseded", "succeeded", "failed", "not_needed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, device TEXT NOT NULL, host TEXT,
  action TEXT NOT NULL, alert_kind TEXT, reason TEXT, status TEXT NOT NULL, decided_at TEXT, decided_by TEXT,
  executed_at TEXT, before_state TEXT, after_state TEXT, output TEXT, result TEXT);
CREATE INDEX IF NOT EXISTS proposals_dev ON proposals(device, status);
"""


def _cfg(settings: dict) -> dict:
    return {**DEFAULTS, **(settings.get("actions") or {})}


def ensure_schema(hist: History) -> None:
    hist.conn.executescript(SCHEMA)


def describe_for_prompt() -> list[dict]:
    return [{"action": a.id, "label": a.label, "risk": a.risk, "impact": a.impact,
             "applies_to_alert_kinds": list(a.applies_to), "propose_when": a.when} for a in ACTIONS.values()]


def _new_id(hist: History) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I confusion when read off a phone
    while True:
        pid = "".join(secrets.choice(alphabet) for _ in range(4))
        if not hist.conn.execute("SELECT 1 FROM proposals WHERE id=?", (pid,)).fetchone():
            return pid


def propose(hist: History, settings: dict, devices: list[Device], suggestion: Optional[dict], events: list,
            now: datetime) -> Optional[dict]:
    """Validate Claude's suggestion and store it. Returns the proposal dict or None (with the reason logged)."""
    cfg = _cfg(settings)
    if not cfg["enabled"] or not suggestion:
        return None
    ensure_schema(hist)
    action = ACTIONS.get(str(suggestion.get("action", "")))
    dev = next((d for d in devices if d.name == suggestion.get("device")), None)
    if not action or not dev:
        log.info("Proposal ignored: unknown action/device %s", suggestion)
        return None
    kinds = {e.kind for e in events if e.device == dev.name}
    if not kinds & set(action.applies_to):
        log.info("Proposal ignored: %s does not apply to %s on %s", action.id, sorted(kinds), dev.name)
        return None
    if hist.conn.execute("SELECT 1 FROM proposals WHERE device=? AND status='pending'", (dev.name,)).fetchone():
        log.info("Proposal ignored: %s already has a pending proposal", dev.name)
        return None
    cool = (now - timedelta(hours=float(cfg["cooldown_hours"]))).isoformat(timespec="seconds")
    if hist.conn.execute("SELECT 1 FROM proposals WHERE device=? AND action=? AND executed_at >= ?",
                         (dev.name, action.id, cool)).fetchone():
        log.info("Proposal ignored: %s on %s ran within the cooldown window", action.id, dev.name)
        return None
    day = (now - timedelta(days=1)).isoformat(timespec="seconds")
    n = hist.conn.execute("SELECT COUNT(*) FROM proposals WHERE executed_at >= ?", (day,)).fetchone()[0]
    if n >= int(cfg["max_per_day"]):
        log.info("Proposal ignored: %d actions already executed in the last 24h", n)
        return None

    pid = _new_id(hist)
    row = {
        "id": pid, "created_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + timedelta(hours=float(cfg["expire_hours"]))).isoformat(timespec="seconds"),
        "device": dev.name, "host": dev.host, "action": action.id,
        "alert_kind": next(iter(kinds & set(action.applies_to))),
        "reason": str(suggestion.get("reason", ""))[:600], "status": "pending",
    }
    with hist.conn:
        hist.conn.execute("INSERT INTO proposals (id,created_at,expires_at,device,host,action,alert_kind,reason,status)"
                          " VALUES (:id,:created_at,:expires_at,:device,:host,:action,:alert_kind,:reason,:status)", row)
    row.update(label=action.label.format(intf=dev.interface), risk=action.risk, impact=action.impact,
               commands=render_commands(action, dev))
    log.warning("PROPOSAL %s: %s on %s - approve with --approve %s (expires %s)", pid, row["label"], dev.name, pid,
                row["expires_at"][11:16])
    return row


def render_commands(action: Action, dev: Device) -> list[str]:
    seq = [c.format(intf=dev.interface) for c in action.exec_cmds]
    if action.config_cmds:
        seq += ["configure terminal"] + [c.format(intf=dev.interface) for c in action.config_cmds]
        if action.pause_seconds:
            seq.append(f"(wait {action.pause_seconds} s)")
        seq += [c.format(intf=dev.interface) for c in action.restore_cmds] + ["end"]
    return seq


def get(hist: History, pid: str) -> Optional[dict]:
    ensure_schema(hist)
    row = hist.conn.execute("SELECT * FROM proposals WHERE id=?", (pid.upper(),)).fetchone()
    return dict(row) if row else None


def list_recent(hist: History, limit: int = 20) -> list[dict]:
    ensure_schema(hist)
    return [dict(r) for r in hist.conn.execute("SELECT * FROM proposals ORDER BY created_at DESC LIMIT ?", (limit,))]


def _set(hist: History, pid: str, **fields) -> None:
    with hist.conn:
        hist.conn.execute("UPDATE proposals SET " + ", ".join(f"{k}=:{k}" for k in fields) + " WHERE id=:id",
                          {**fields, "id": pid})


def housekeeping(hist: History, states: dict, now: datetime) -> list[Event]:
    """Expire old proposals; mark ones whose router recovered on its own as superseded."""
    ensure_schema(hist)
    events: list[Event] = []
    ts = now.isoformat(timespec="seconds")
    for r in hist.conn.execute("SELECT * FROM proposals WHERE status='pending'").fetchall():
        st = states.get(r["device"]) or {}
        if r["expires_at"] <= ts:
            _set(hist, r["id"], status="expired", decided_at=ts, decided_by="timeout")
            log.info("Proposal %s expired", r["id"])
        elif st.get("internet") == "up" and not st.get("addr_lost") and r["alert_kind"] in ("INTERNET_DOWN", "ADDRESS_LOST"):
            _set(hist, r["id"], status="superseded", decided_at=ts, decided_by="recovered")
            events.append(Event(r["device"], r["host"] or "", "PROPOSAL_SUPERSEDED", INFO,
                                f"Proposed fix {r['id']} no longer needed on {r['device']}",
                                f"{r['device']} recovered on its own; {ACTIONS[r['action']].label} will not be run.",
                                ts, notify=False))
    return events


def reject(hist: History, pid: str, now: datetime, who: str = "operator") -> dict:
    p = get(hist, pid)
    if not p:
        raise ValueError(f"No proposal {pid}")
    if p["status"] != "pending":
        raise ValueError(f"Proposal {pid} is {p['status']}, not pending")
    _set(hist, p["id"], status="rejected", decided_at=now.isoformat(timespec="seconds"), decided_by=who)
    return get(hist, pid)


def _state_snapshot(r) -> dict:
    return {"reachable": r.reachable, "intf": f"{r.intf_status}/{r.intf_protocol}", "ip": r.ip,
            "internet_ok": r.internet_ok, "ping": r.ping, "reason": r.reason or r.error}


def execute(hist: History, settings: dict, devices: list[Device], pid: str, now_fn: Callable = None,
            connect: Optional[Callable] = None, sleep: Callable = time.sleep, who: str = "operator") -> tuple[dict, Event]:
    """Approve and run a proposal. Returns (proposal row, result event to notify)."""
    now_fn = now_fn or (lambda: datetime.now().astimezone())
    connect = connect or _default_connect
    now = now_fn()
    ts = now.isoformat(timespec="seconds")
    p = get(hist, pid)
    if not p:
        raise ValueError(f"No proposal {pid}")
    if p["status"] != "pending":
        raise ValueError(f"Proposal {pid} is {p['status']}, not pending")
    if p["expires_at"] <= ts:
        _set(hist, p["id"], status="expired", decided_at=ts, decided_by="timeout")
        raise ValueError(f"Proposal {pid} expired at {p['expires_at'][11:16]}; wait for a new alert")
    dev = next((d for d in devices if d.name == p["device"]), None)
    if not dev:
        raise ValueError(f"Device {p['device']} is no longer in the inventory")
    action = ACTIONS[p["action"]]
    label = action.label.format(intf=dev.interface)
    _set(hist, p["id"], status="approved", decided_at=ts, decided_by=who)

    # 1. Is the fault still there? Never act on a router that has already recovered.
    before = check_device(dev, settings, connect)
    _set(hist, p["id"], before_state=json.dumps(_state_snapshot(before)))
    still_broken = (not before.reachable) or before.internet_ok is False or (before.reachable and not before.ip)
    if not before.reachable:
        _set(hist, p["id"], status="failed", result="router unreachable over SSH; nothing was run")
        return get(hist, pid), Event(dev.name, dev.host, "ACTION_FAILED", WARNING,
                                     f"Fix {p['id']} NOT run on {dev.name}: router unreachable",
                                     f"{label} was approved but SSH failed: {before.error}", ts)
    if not still_broken:
        _set(hist, p["id"], status="not_needed", result="fault already cleared before execution")
        return get(hist, pid), Event(dev.name, dev.host, "ACTION_NOT_NEEDED", INFO,
                                     f"Fix {p['id']} not needed on {dev.name}",
                                     f"{dev.name} is healthy again ({dev.interface} = {before.ip}, internet OK); "
                                     f"{label} was not run.", ts)

    # 2. Run the fixed command sequence.
    outputs: list[str] = []
    error: Optional[str] = None
    conn = None
    try:
        conn = connect(dev, settings["ssh_timeout"])
        for c in action.exec_cmds:
            cmd = c.format(intf=dev.interface)
            outputs.append(f"# {cmd}\n{conn.send_command(cmd, read_timeout=60)}")
        if action.config_cmds:
            try:
                lines = [c.format(intf=dev.interface) for c in action.config_cmds]
                outputs.append(f"# config: {lines}\n{conn.send_config_set(lines)}")
                if action.pause_seconds:
                    sleep(action.pause_seconds)
            finally:
                lines = [c.format(intf=dev.interface) for c in action.restore_cmds]
                outputs.append(f"# restore: {lines}\n{conn.send_config_set(lines)}")
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}"[:300]
        outputs.append(f"# ERROR {error}")
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
    _set(hist, p["id"], executed_at=now_fn().isoformat(timespec="seconds"), output="\n".join(outputs)[:8000])

    # 3. Verify.
    sleep(action.settle_seconds)
    after = check_device(dev, settings, connect)
    after_snap = _state_snapshot(after)
    ok = after.reachable and after.internet_ok is True
    status = "succeeded" if ok and not error else "failed"
    result = (f"internet restored: {dev.interface} = {after.ip}, ping {after.ping}" if ok else
              f"still failing after action: {after.reason or after.error}") + (f"; command error: {error}" if error else "")
    _set(hist, p["id"], status=status, after_state=json.dumps(after_snap), result=result)
    ev = Event(dev.name, dev.host, "ACTION_SUCCEEDED" if status == "succeeded" else "ACTION_FAILED",
               OK if status == "succeeded" else CRITICAL,
               f"Fix {p['id']} {'WORKED' if status == 'succeeded' else 'DID NOT WORK'} on {dev.name}: {label}",
               f"Approved by {who}. Before: {dev.interface} {before.intf_status}/{before.intf_protocol}, ip {before.ip}, "
               f"internet {'OK' if before.internet_ok else 'DOWN'} ({before.reason}). "
               f"After: {after.intf_status}/{after.intf_protocol}, ip {after.ip}, internet {'OK' if ok else 'DOWN'}"
               f"{'' if ok else ' (' + str(after.reason or after.error) + ')'}."
               + (f" Command error: {error}." if error else "")
               + ("" if ok else " Next step: escalate - this router needs hands-on attention or the fault is upstream."),
               now_fn().isoformat(timespec="seconds"))
    log.warning("ACTION %s %s on %s: %s", p["id"], status.upper(), dev.name, result)
    return get(hist, pid), ev
