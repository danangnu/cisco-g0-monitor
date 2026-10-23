"""Turn check results into state transitions and alert events.

Pure logic (no I/O) so it can be unit tested.
"""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

from .collector import CheckResult
from .config import Device

CRITICAL, WARNING, INFO, OK = "critical", "warning", "info", "ok"


@dataclass
class Event:
    device: str
    host: str
    kind: str
    severity: str
    title: str
    detail: str
    timestamp: str
    notify: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


def new_state() -> dict:
    return {
        "reachable": None,           # None = never checked
        "unreach_count": 0,
        "reach_ok_count": 0,
        "unreach_since": None,
        "internet": "unknown",       # unknown | up | down
        "internet_fail_count": 0,
        "internet_ok_count": 0,
        "internet_fail_since": None,
        "baseline_network": None,
        "baseline_ip": None,
        "mismatch_network": None,
        "addr_lost": False,
        "addr_lost_count": 0,
        "last_reminder_at": None,
        "subnet_history": [],
        "last_check": None,
        "last_result": None,
    }


def _fmt_duration(start_iso: Optional[str], now: datetime) -> str:
    if not start_iso:
        return "unknown"
    secs = int((now - datetime.fromisoformat(start_iso)).total_seconds())
    h, rem = divmod(max(secs, 0), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m" if h else f"{m}m {s}s"


def _reminder_due(state: dict, now: datetime, repeat_minutes: int) -> bool:
    if not repeat_minutes or not state.get("last_reminder_at"):
        return False
    elapsed = (now - datetime.fromisoformat(state["last_reminder_at"])).total_seconds()
    return elapsed >= repeat_minutes * 60


def evaluate(prev: Optional[dict], r: CheckResult, device: Device, settings: dict,
             now: datetime) -> tuple[dict, list[Event]]:
    s = copy.deepcopy(prev) if prev else new_state()
    for k, v in new_state().items():  # forward-compatible with older state files
        s.setdefault(k, v)

    fail_n = int(settings["thresholds"]["failure"])
    ok_n = int(settings["thresholds"]["recovery"])
    alerts = settings["alerts"]
    repeat = int(alerts.get("repeat_every_minutes") or 0)
    now_iso = now.isoformat(timespec="seconds")
    intf = device.interface
    events: list[Event] = []

    def emit(kind: str, severity: str, title: str, detail: str, notify: bool = True) -> None:
        events.append(Event(device.name, device.host, kind, severity, title, detail, now_iso, notify))

    s["last_check"] = now_iso
    s["last_result"] = r.to_dict()

    # ---- 1. Can we reach / log in to the device? ----------------------------
    if not r.reachable:
        s["reach_ok_count"] = 0
        s["unreach_count"] += 1
        if s["unreach_count"] == 1:
            s["unreach_since"] = now_iso
        if s["reachable"] is not False and s["unreach_count"] >= fail_n:
            s["reachable"] = False
            s["last_reminder_at"] = now_iso
            emit("DEVICE_UNREACHABLE", CRITICAL,
                 f"DEVICE UNREACHABLE: {device.name} ({device.host})",
                 f"SSH check failed {s['unreach_count']}x in a row. Last error: {r.error}. "
                 f"Internet / subnet status of {intf} is unknown while the device is unreachable.",
                 notify=alerts.get("on_device_unreachable", True))
        elif s["reachable"] is False and _reminder_due(s, now, repeat):
            s["last_reminder_at"] = now_iso
            emit("DEVICE_STILL_UNREACHABLE", CRITICAL,
                 f"STILL UNREACHABLE: {device.name} ({device.host})",
                 f"Unreachable for {_fmt_duration(s['unreach_since'], now)}. Last error: {r.error}",
                 notify=alerts.get("on_device_unreachable", True))
        return s, events

    s["unreach_count"] = 0
    if s["reachable"] is False:
        s["reach_ok_count"] += 1
        if s["reach_ok_count"] >= ok_n:
            emit("DEVICE_REACHABLE", OK, f"DEVICE REACHABLE AGAIN: {device.name} ({device.host})",
                 f"SSH is working again after {_fmt_duration(s['unreach_since'], now)}.",
                 notify=alerts.get("on_device_unreachable", True) and alerts.get("send_recovery", True))
            s["reachable"], s["reach_ok_count"], s["unreach_since"] = True, 0, None
    else:
        s["reachable"], s["reach_ok_count"], s["unreach_since"] = True, 0, None

    # ---- 2. G0/0 address / subnet -------------------------------------------
    expected = device.expected_subnet
    baseline = expected or s["baseline_network"]
    if r.network:
        if s["addr_lost"]:
            s["addr_lost"] = False
            if r.network == baseline:
                emit("ADDRESS_RESTORED", OK, f"{intf} ADDRESS RESTORED on {device.name}",
                     f"{intf} has address {r.ip} again (subnet {r.network}, unchanged).",
                     notify=alerts.get("send_recovery", True))
        s["addr_lost_count"] = 0

        if baseline is None:
            s["baseline_network"], s["baseline_ip"] = r.network, r.ip
            emit("BASELINE_LEARNED", INFO, f"Baseline learned for {device.name}",
                 f"{intf} = {r.ip} (subnet {r.network}, {r.addr_method}).", notify=False)
        elif r.network != baseline:
            if expected:
                if s["mismatch_network"] != r.network:
                    s["mismatch_network"] = r.network
                    emit("SUBNET_MISMATCH", CRITICAL,
                         f"{intf} SUBNET NOT AS EXPECTED on {device.name}: {r.network}",
                         f"Expected subnet {expected}, device now has {r.ip} ({r.addr_method}).")
            else:
                old_net, old_ip = s["baseline_network"], s["baseline_ip"]
                s["subnet_history"] = (s["subnet_history"] + [
                    {"at": now_iso, "from": old_net, "to": r.network, "from_ip": old_ip, "to_ip": r.ip}
                ])[-20:]
                s["baseline_network"], s["baseline_ip"] = r.network, r.ip
                emit("SUBNET_CHANGED", WARNING,
                     f"{intf} SUBNET CHANGED on {device.name}: {old_net} -> {r.network}",
                     f"IP changed {old_ip} -> {r.ip} ({r.addr_method}). "
                     f"The new subnet is now the baseline. Check NAT, ACLs, tunnels and static routes "
                     f"that reference the old address.")
        else:
            if expected:
                s["baseline_network"] = expected
                if s["mismatch_network"]:
                    s["mismatch_network"] = None
                    emit("SUBNET_MATCHES_EXPECTED", OK,
                         f"{intf} subnet back to expected on {device.name}",
                         f"{intf} = {r.ip}, matches expected subnet {expected}.",
                         notify=alerts.get("send_recovery", True))
            if s["baseline_ip"] and r.ip != s["baseline_ip"]:
                emit("IP_CHANGED", INFO, f"{intf} IP changed on {device.name}: {s['baseline_ip']} -> {r.ip}",
                     f"Same subnet {r.network} ({r.addr_method}).",
                     notify=alerts.get("on_ip_change_same_subnet", False))
            s["baseline_ip"] = r.ip
    elif r.intf_status is not None:
        s["addr_lost_count"] += 1
        if not s["addr_lost"] and s["addr_lost_count"] >= fail_n:
            s["addr_lost"] = True
            emit("ADDRESS_LOST", CRITICAL, f"{intf} HAS NO IP ADDRESS on {device.name}",
                 f"Previously {s['baseline_ip']} (subnet {s['baseline_network']}). "
                 f"Interface is {r.intf_status}/{r.intf_protocol}. If this is DHCP, the lease was lost.")

    # ---- 3. Internet via G0/0 -----------------------------------------------
    if r.internet_ok is True:
        s["internet_fail_count"] = 0
        if s["internet"] == "down":
            s["internet_ok_count"] += 1
            if s["internet_ok_count"] >= ok_n:
                emit("INTERNET_RESTORED", OK, f"INTERNET RESTORED on {device.name} ({intf})",
                     f"Down for {_fmt_duration(s['internet_fail_since'], now)}. "
                     f"Ping: {_ping_summary(r)}. {intf} = {r.ip}.",
                     notify=alerts.get("send_recovery", True))
                s["internet"], s["internet_ok_count"], s["internet_fail_since"] = "up", 0, None
        else:
            s["internet"], s["internet_ok_count"], s["internet_fail_since"] = "up", 0, None
    elif r.internet_ok is False:
        s["internet_ok_count"] = 0
        s["internet_fail_count"] += 1
        if s["internet_fail_count"] == 1:
            s["internet_fail_since"] = now_iso
        if s["internet"] != "down" and s["internet_fail_count"] >= fail_n:
            s["internet"] = "down"
            s["last_reminder_at"] = now_iso
            emit("INTERNET_DOWN", CRITICAL, f"INTERNET DOWN on {device.name} ({intf})",
                 f"{r.reason}. Failed {s['internet_fail_count']} checks in a row. "
                 f"{intf} = {r.ip or 'no IP'}, status {r.intf_status}/{r.intf_protocol}.")
        elif s["internet"] == "down" and _reminder_due(s, now, repeat):
            s["last_reminder_at"] = now_iso
            emit("INTERNET_STILL_DOWN", CRITICAL, f"STILL DOWN: internet on {device.name} ({intf})",
                 f"Down for {_fmt_duration(s['internet_fail_since'], now)}. {r.reason}.")
    # internet_ok None -> check was incomplete; leave internet state untouched

    return s, events


def _ping_summary(r: CheckResult) -> str:
    return ", ".join(f"{t} {p}%" for t, p in r.ping.items()) or "n/a"
