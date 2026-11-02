"""Stage 2: warn about links that are degrading before they fail.

Deterministic rules over the history database (no AI involved):
  LATENCY_DEGRADED  24h average round-trip time is >= `latency_ratio` x the previous 7-day average
                    and at least `latency_min_increase_ms` higher
  PACKET_LOSS       average ping success over 24h below `loss_threshold_percent` while the link is "up"
  FLAPPING          >= `flap_incidents_24h` outages in the last 24h

Each warning is raised at most once per `repeat_hours` per device per kind.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta

from .engine import Event, WARNING
from .history import History

DEFAULTS = {
    "enabled": True,
    "latency_ratio": 2.0,
    "latency_min_increase_ms": 20,
    "min_samples": 24,            # at least 2h of 5-minute checks in each window
    "loss_threshold_percent": 90,
    "flap_incidents_24h": 3,
    "repeat_hours": 24,
}


def _due(hist: History, device: str, kind: str, now: datetime, repeat_hours: float) -> bool:
    last = hist.get_meta(f"trend:{device}:{kind}")
    return not last or (now - datetime.fromisoformat(last)) >= timedelta(hours=repeat_hours)


def detect(hist: History, devices: list, states: dict, settings: dict, now: datetime) -> list[Event]:
    cfg = {**DEFAULTS, **(settings.get("trends") or {})}
    if not cfg["enabled"]:
        return []
    events: list[Event] = []
    ts = now.isoformat(timespec="seconds")
    day_ago, week_ago = now - timedelta(days=1), now - timedelta(days=7)

    for dv in devices:
        st = states.get(dv.name) or {}
        if st.get("internet") != "up":
            continue  # a link that is down gets a real alert; don't pile trend warnings on top

        def emit(kind: str, title: str, detail: str) -> None:
            if _due(hist, dv.name, kind, now, cfg["repeat_hours"]):
                hist.set_meta(f"trend:{dv.name}:{kind}", ts)
                events.append(Event(dv.name, dv.host, kind, WARNING, title, detail, ts))

        base = hist.latency(dv.name, week_ago, day_ago)
        recent = hist.latency(dv.name, day_ago)
        if len(base) >= cfg["min_samples"] and len(recent) >= cfg["min_samples"]:
            b, r = statistics.median(base), statistics.median(recent)
            if b > 0 and r >= b * float(cfg["latency_ratio"]) and r - b >= cfg["latency_min_increase_ms"]:
                emit("LATENCY_DEGRADED", f"LATENCY DEGRADED on {dv.name} ({dv.interface})",
                     f"Median round-trip from {dv.interface} is {r:.0f} ms over the last 24h vs {b:.0f} ms over the "
                     f"previous week ({r / b:.1f}x). The link still works but is getting worse - check for "
                     f"congestion, a failing modem, or ISP issues before it fails.")

        loss = hist.loss(dv.name, day_ago)
        n24 = len(hist.latency(dv.name, day_ago)) + 0  # cheap proxy for sample count
        if loss is not None and n24 >= cfg["min_samples"] and loss < cfg["loss_threshold_percent"]:
            emit("PACKET_LOSS", f"PACKET LOSS on {dv.name} ({dv.interface})",
                 f"Only {loss:.0f}% of pings from {dv.interface} succeeded over the last 24h (threshold "
                 f"{cfg['loss_threshold_percent']}%). The internet is up but unreliable.")

        inc = hist.incidents(dv.name, day_ago)
        if len(inc) >= cfg["flap_incidents_24h"]:
            times = ", ".join(i["started_at"][11:16] for i in inc)
            emit("FLAPPING", f"FLAPPING link on {dv.name} ({dv.interface})",
                 f"{len(inc)} outages in the last 24h (at {times}). A link that keeps dropping usually means "
                 f"an unstable modem, a bad cable/port, or an ISP fault - worth fixing before it fails for good.")
    return events
