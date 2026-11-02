"""Stage 2: weekly summary report.

Sent once a week (settings.report.weekday/hour, local time) through the same channels as alerts:
uptime, outages and downtime, latency, packet loss and config changes per router, plus - if
ai.enabled - a short narrative from Claude with the fleet's history as context (one API call a week).
"""
from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from .history import History, _fmt_dur

log = logging.getLogger(__name__)

DEFAULTS = {"enabled": True, "weekday": 0, "hour": 8, "days": 7, "use_ai": True}

REPORT_TOOL = {
    "name": "weekly_narrative",
    "description": "Short narrative for the weekly network report.",
    "input_schema": {
        "type": "object",
        "properties": {
            "headline": {"type": "string", "description": "One sentence: how the week went overall."},
            "highlights": {"type": "array", "items": {"type": "string"},
                           "description": "3-6 bullets: what mattered, with numbers. Patterns across days/routers."},
            "recommendations": {"type": "array", "items": {"type": "string"},
                                "description": "0-4 concrete things worth doing this week, most valuable first."},
        },
        "required": ["headline", "highlights", "recommendations"],
    },
}

REPORT_SYSTEM = """You write the weekly WAN health report for a small fleet of Cisco routers for a busy IT manager.
You get per-router statistics (uptime, outages with durations and times, latency trend, packet loss,
config changes) and the AI diagnoses issued during the week. Be specific and numeric, point out patterns
(same hour every night, one site worse than the rest, latency creeping up, a config change followed by
an outage), and keep it short. If the week was quiet, say so in one line and do not invent concerns.
Call weekly_narrative."""


def is_due(hist: History, settings: dict, now: datetime) -> bool:
    cfg = {**DEFAULTS, **(settings.get("report") or {})}
    if not cfg["enabled"] or now.weekday() != int(cfg["weekday"]) or now.hour < int(cfg["hour"]):
        return False
    if hist.get_meta("report:last_date") == now.date().isoformat():
        return False
    first = hist.conn.execute("SELECT MIN(ts) AS t FROM checks").fetchone()["t"]
    return bool(first) and (now - datetime.fromisoformat(first)) >= timedelta(days=1)   # no report on install day


def build_stats(hist: History, devices: list, now: datetime, days: int) -> list[dict]:
    since = now - timedelta(days=days)
    rows = []
    for dv in devices:
        s = hist.summary_for(dv.name, now, days)
        inc = hist.incidents(dv.name, since)
        rows.append({
            "device": dv.name, "host": dv.host,
            "uptime": s["uptime_percent"], "incidents": len(inc),
            "downtime": s["total_downtime"], "longest": _fmt_dur(max((i["duration_s"] or 0 for i in inc), default=0)) if inc else "-",
            "latency": s["latency_ms"]["avg_last_24h"], "latency_prev": s["latency_ms"]["avg_prev_7d"],
            "ping_ok": s["ping_success_last_24h_percent"],
            "config_changes": len(s["config"]["recent_changes"]) if s["config"] else 0,
            "subnet_changes": len(s["subnet_changes"]),
            "by_hour": s["incidents_by_hour_of_day"],
            "recent": s["recent_incidents"],
        })
    return rows


def narrative(stats: list[dict], diagnoses: list, cfg_ai: dict, days: int, client=None) -> Optional[dict]:
    try:
        from .diagnose import _default_client
        client = client or _default_client(cfg_ai)
        payload = {"period_days": days, "routers": stats,
                   "ai_diagnoses_this_period": [{"at": d["ts"][:16], "devices": json.loads(d["devices"] or "[]"),
                                                 "scope": d["scope"], "summary": d["summary"]} for d in diagnoses]}
        resp = client.messages.create(model=cfg_ai["model"], max_tokens=800, system=REPORT_SYSTEM,
                                      tools=[REPORT_TOOL], tool_choice={"type": "auto"},
                                      messages=[{"role": "user", "content": json.dumps(payload, indent=1)
                                                 + "\n\nCall weekly_narrative."}])
        for b in resp.content:
            if getattr(b, "type", "") == "tool_use" and isinstance(getattr(b, "input", None), dict):
                return b.input
        text = "\n".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text").strip()
        return {"headline": text[:300], "highlights": [], "recommendations": []} if text else None
    except Exception as e:  # noqa: BLE001
        log.warning("Weekly narrative failed (%s: %s); sending the numbers only", type(e).__name__, e)
        return None


def render(stats: list[dict], story: Optional[dict], now: datetime, days: int) -> tuple[str, str, str]:
    """Returns (subject, html, text)."""
    start = (now - timedelta(days=days)).strftime("%d %b")
    end = now.strftime("%d %b %Y")
    worst = min((s["uptime"] for s in stats if s["uptime"] is not None), default=None)
    total_inc = sum(s["incidents"] for s in stats)
    subject = f"Cisco WAN weekly report {start} - {end}: {total_inc} outage{'s' if total_inc != 1 else ''}" + (
        f", lowest uptime {worst:.1f}%" if worst is not None else "")

    def fmt(v, suffix=""):
        return "-" if v is None else f"{v}{suffix}"

    def lat(s):
        if s["latency"] is None:
            return "-"
        arrow = ""
        if s["latency_prev"]:
            ratio = s["latency"] / s["latency_prev"]
            arrow = " ↑" if ratio >= 1.5 else (" ↓" if ratio <= 0.67 else "")
        return f"{s['latency']} ms{arrow}"

    trs = "".join(
        f"<tr><td>{html.escape(s['device'])}</td><td>{fmt(s['uptime'], '%')}</td><td>{s['incidents']}</td>"
        f"<td>{html.escape(s['downtime'])}</td><td>{html.escape(s['longest'])}</td><td>{html.escape(lat(s))}</td>"
        f"<td>{fmt(s['ping_ok'], '%')}</td><td>{s['config_changes']}</td></tr>"
        for s in stats)
    story_html = ""
    if story:
        hl = "".join(f"<li>{html.escape(x)}</li>" for x in story.get("highlights", []))
        rec = "".join(f"<li>{html.escape(x)}</li>" for x in story.get("recommendations", []))
        story_html = (f"<p style='font-size:15px'><b>{html.escape(story.get('headline', ''))}</b></p>"
                      + (f"<ul>{hl}</ul>" if hl else "")
                      + (f"<p><b>Recommended this week</b></p><ol>{rec}</ol>" if rec else ""))
    body = (f"<div style='font-family:Segoe UI,Arial,sans-serif;font-size:14px'>"
            f"<h2 style='margin:0 0 4px 0'>Cisco WAN weekly report</h2>"
            f"<p style='color:#555;margin:0 0 12px 0'>{start} - {end} · {len(stats)} routers · every router's "
            f"GigabitEthernet0/0 checked every 5 minutes</p>{story_html}"
            f"<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse'>"
            f"<thead><tr><th>Router</th><th>Uptime</th><th>Outages</th><th>Downtime</th><th>Longest</th>"
            f"<th>Latency (24h)</th><th>Ping OK (24h)</th><th>Config changes</th></tr></thead><tbody>{trs}</tbody></table>"
            f"<p style='color:#888;font-size:12px'>Uptime = share of checks with internet reachable from G0/0. "
            f"Latency arrows compare the last 24h with the previous week.</p></div>")

    lines = [f"Cisco WAN weekly report {start} - {end}", ""]
    if story:
        lines += [story.get("headline", ""), ""] + [f"- {x}" for x in story.get("highlights", [])]
        if story.get("recommendations"):
            lines += ["", "Recommended this week:"] + [f"{i}. {x}" for i, x in enumerate(story["recommendations"], 1)]
        lines.append("")
    lines.append(f"{'ROUTER':14} {'UPTIME':>7} {'OUTAGES':>8} {'DOWNTIME':>9} {'LATENCY':>10} {'PING OK':>8} {'CFG':>4}")
    for s in stats:
        lines.append(f"{s['device']:14} {fmt(s['uptime'], '%'):>7} {s['incidents']:>8} {s['downtime']:>9} "
                     f"{lat(s):>10} {fmt(s['ping_ok'], '%'):>8} {s['config_changes']:>4}")
    return subject, body, "\n".join(lines)


def run(hist: History, devices: list, settings: dict, now: datetime, notifier, client=None) -> dict:
    cfg = {**DEFAULTS, **(settings.get("report") or {})}
    days = int(cfg["days"])
    stats = build_stats(hist, devices, now, days)
    story = None
    if cfg["use_ai"] and settings.get("ai", {}).get("enabled"):
        story = narrative(stats, hist.recent_diagnoses(now - timedelta(days=days), 20), settings["ai"], days, client)
    subject, body, text = render(stats, story, now, days)
    notifier.send_report(subject, body, text)
    hist.set_meta("report:last_date", now.date().isoformat())
    log.info("Weekly report sent: %s", subject)
    return {"subject": subject, "html": body, "text": text, "stats": stats, "story": story}
