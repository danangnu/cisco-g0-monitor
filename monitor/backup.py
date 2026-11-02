"""Stage 2: daily running-config backup with change detection.

Once a day (settings.backup.hour, local time) every router's `show running-config` is pulled,
secrets are redacted, volatile lines are stripped, and the result is stored in history.db.
If it differs from the previous snapshot a CONFIG_CHANGED event is raised with the diff, so a
subnet change or outage can be traced to "someone edited the config yesterday".

Read-only: `show running-config` is the only command this module runs.
"""
from __future__ import annotations

import difflib
import hashlib
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable, Optional

from .collector import _default_connect
from .config import Device
from .diagnose import redact
from .engine import Event, INFO, WARNING
from .history import History

log = logging.getLogger(__name__)

DEFAULTS = {"enabled": True, "hour": 3, "max_diff_lines": 80, "warn_on_change": True}

# Lines that change on every pull without the config really changing.
_VOLATILE = re.compile(r"^(! Last configuration change|! NVRAM config last updated|! No configuration change since|"
                       r"Current configuration :|ntp clock-period|Building configuration)", re.I)


def normalise(raw: str) -> str:
    lines = [ln.rstrip() for ln in redact(raw).splitlines()]
    lines = [ln for ln in lines if not _VOLATILE.match(ln)]
    # drop the leading "!" / blank noise before "version"
    while lines and lines[0].strip() in ("", "!"):
        lines.pop(0)
    return "\n".join(lines).strip() + "\n"


def diff_configs(old: str, new: str, max_lines: int) -> tuple[str, int, int]:
    d = list(difflib.unified_diff(old.splitlines(), new.splitlines(), "previous", "current", lineterm="", n=2))
    added = sum(1 for ln in d if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in d if ln.startswith("-") and not ln.startswith("---"))
    text = "\n".join(d[:max_lines]) + (f"\n... ({len(d) - max_lines} more lines)" if len(d) > max_lines else "")
    return text, added, removed


def fetch_config(device: Device, settings: dict, connect: Optional[Callable] = None) -> str:
    connect = connect or _default_connect
    conn = connect(device, settings["ssh_timeout"])
    try:
        return conn.send_command("show running-config", read_timeout=90)
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001
            pass


def is_due(hist: History, settings: dict, now: datetime) -> bool:
    cfg = {**DEFAULTS, **(settings.get("backup") or {})}
    if not cfg["enabled"] or now.hour < int(cfg["hour"]):
        return False
    return hist.get_meta("backup:last_date") != now.date().isoformat()


def run(devices: list[Device], settings: dict, hist: History, now: datetime,
        connect: Optional[Callable] = None, force: bool = False) -> list[Event]:
    """Back up every router. Returns CONFIG_CHANGED events (first snapshot = info, later changes = warning)."""
    cfg = {**DEFAULTS, **(settings.get("backup") or {})}
    if not force and not cfg["enabled"]:
        return []
    events: list[Event] = []
    ts = now.isoformat(timespec="seconds")

    def one(dv: Device):
        try:
            return dv, normalise(fetch_config(dv, settings, connect)), None
        except Exception as e:  # noqa: BLE001
            return dv, None, f"{type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}"[:200]

    with ThreadPoolExecutor(max_workers=max(1, int(settings.get("max_workers", 10)))) as pool:
        outcomes = list(pool.map(one, devices))

    for dv, text, err in outcomes:
        if err or not text or len(text) < 50:
            log.warning("Config backup failed for %s: %s", dv.name, err or "empty output")
            continue
        sha = hashlib.sha256(text.encode()).hexdigest()
        prev = hist.latest_config(dv.name)
        if prev and prev["sha256"] == sha:
            log.info("Config backup %s: unchanged", dv.name)
            continue
        if prev:
            diff, added, removed = diff_configs(prev["config"], text, int(cfg["max_diff_lines"]))
            hist.record_config(dv.name, now, sha, text, diff, added, removed)
            log.warning("Config backup %s: CHANGED (+%d/-%d lines)", dv.name, added, removed)
            events.append(Event(dv.name, dv.host, "CONFIG_CHANGED", WARNING if cfg["warn_on_change"] else INFO,
                                f"CONFIG CHANGED on {dv.name}: +{added}/-{removed} lines since {prev['ts'][:16]}",
                                f"Running-config differs from the last backup.\n{diff}", ts,
                                notify=bool(cfg["warn_on_change"])))
        else:
            hist.record_config(dv.name, now, sha, text, None, 0, 0)
            log.info("Config backup %s: first snapshot stored (%d lines)", dv.name, text.count("\n") + 1)
            events.append(Event(dv.name, dv.host, "CONFIG_BACKUP", INFO, f"First config backup stored for {dv.name}",
                                f"{text.count(chr(10)) + 1} lines, sha256 {sha[:12]}", ts, notify=False))
    hist.set_meta("backup:last_date", now.date().isoformat())
    return events
