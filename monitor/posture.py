"""Stage 4: security-finding lifecycle, alerts and reports.

  run_audit()   audit raw configs (from the daily backup or --audit), store findings, work out what is
                new / still open / resolved, and email a report when something changed
  summary()     open findings per router (for the weekly report and for Claude's diagnosis context)
"""
from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from .audit import SEV_ORDER, Finding, audit_config, fix_script, score
from .engine import Event, INFO, WARNING
from .history import History

log = logging.getLogger(__name__)

DEFAULTS = {"enabled": True, "notify_min_severity": "medium", "use_ai": True, "remind_days": 7}

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_findings (
  fingerprint TEXT PRIMARY KEY, device TEXT NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL, title TEXT,
  detail TEXT, evidence TEXT, fix TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT);
CREATE INDEX IF NOT EXISTS audit_dev ON audit_findings(device, resolved_at);
"""

AI_SYSTEM = """You are a network security engineer writing a short note for an IT manager about the security
posture of a few Cisco routers. You get the audit findings (rule, severity, title, evidence, fix commands)
split into NEW, STILL OPEN and RESOLVED. Write 3-6 sentences max: what matters most and why, in plain
language, what to fix first and what can wait. No generic advice, no repetition of the table. Mention
anything that interacts (e.g. Telnet + reversible passwords = credentials readable on the wire AND in
backups). If everything is low severity, say the routers are in reasonable shape."""


def _cfg(settings: dict) -> dict:
    return {**DEFAULTS, **(settings.get("audit") or {})}


def ensure_schema(hist: History) -> None:
    hist.conn.executescript(SCHEMA)


def run_audit(hist: History, settings: dict, raw_configs: dict, devices: list, now: datetime, notifier=None,
              client=None, force_report: bool = False) -> dict:
    """raw_configs: {device_name: raw running-config text}. Returns {"new":[], "open":[], "resolved":[], "score":{}}."""
    cfg = _cfg(settings)
    ensure_schema(hist)
    ts = now.isoformat(timespec="seconds")
    by_dev = {d.name: d for d in devices}
    new, still_open, resolved, scores, all_now = [], [], [], {}, {}
    for name, raw in raw_configs.items():
        dv = by_dev.get(name)
        findings = audit_config(raw, name, [dv.interface] if dv else ["GigabitEthernet0/0"],
                                monitor_user=dv.username if dv else "")
        all_now[name] = findings
        scores[name] = score(findings)
        seen = {f.fingerprint for f in findings}
        with hist.conn:
            for f in findings:
                row = hist.conn.execute("SELECT first_seen, resolved_at FROM audit_findings WHERE fingerprint=?",
                                        (f.fingerprint,)).fetchone()
                if row and not row["resolved_at"]:
                    hist.conn.execute("UPDATE audit_findings SET last_seen=? WHERE fingerprint=?", (ts, f.fingerprint))
                    still_open.append(f)
                else:
                    hist.conn.execute("INSERT INTO audit_findings (fingerprint,device,rule,severity,title,detail,evidence,fix,"
                                      "first_seen,last_seen,resolved_at) VALUES (?,?,?,?,?,?,?,?,?,?,NULL) "
                                      "ON CONFLICT(fingerprint) DO UPDATE SET first_seen=excluded.first_seen, last_seen=excluded.last_seen, resolved_at=NULL",
                                      (f.fingerprint, name, f.rule, f.severity, f.title, f.detail, json.dumps(f.evidence),
                                       json.dumps(f.fix), ts, ts))
                    new.append(f)
            for r in hist.conn.execute("SELECT * FROM audit_findings WHERE device=? AND resolved_at IS NULL", (name,)).fetchall():
                if r["fingerprint"] not in seen:
                    hist.conn.execute("UPDATE audit_findings SET resolved_at=? WHERE fingerprint=?", (ts, r["fingerprint"]))
                    resolved.append(Finding(r["rule"], r["severity"], r["title"], r["detail"], json.loads(r["fix"] or "[]"),
                                            json.loads(r["evidence"] or "[]"), r["device"]))
    hist.set_meta("audit:last_run", ts)
    for name in raw_configs:
        log.info("Security audit %s: score %d/100, %d finding(s), %d new, %d resolved", name, scores[name],
                 len(all_now[name]), sum(f.device == name for f in new), sum(f.device == name for f in resolved))

    # record a timeline event per router with new/resolved counts (not emailed; the report below is)
    events = []
    for name in raw_configs:
        n_new = [f for f in new if f.device == name]
        n_res = [f for f in resolved if f.device == name]
        if n_new or n_res:
            dv = by_dev.get(name)
            worst = min((SEV_ORDER[f.severity] for f in n_new), default=9)
            events.append(Event(name, dv.host if dv else "", "SECURITY_AUDIT", WARNING if worst <= 1 else INFO,
                                f"Security audit {name}: {len(n_new)} new, {len(n_res)} resolved, score {scores[name]}/100",
                                "; ".join(f"[{f.severity}] {f.title}" for f in n_new[:6]) or "no new findings", ts, notify=False))
    if events:
        hist.record_cycle({}, events, now)

    threshold = SEV_ORDER.get(cfg["notify_min_severity"], 2)
    notable_new = [f for f in new if SEV_ORDER[f.severity] <= threshold]
    due_reminder = _reminder_due(hist, now, cfg)
    if notifier and (force_report or notable_new or resolved or due_reminder):
        story = None
        if cfg["use_ai"] and settings.get("ai", {}).get("enabled"):
            story = _narrative(new, still_open, resolved, settings["ai"], client)
        subject, body, text = render(new, still_open, resolved, scores, now, story)
        notifier.send_report(subject, body, text)
        hist.set_meta("audit:last_report", ts)
    return {"new": new, "open": still_open, "resolved": resolved, "score": scores, "findings": all_now}


def _reminder_due(hist: History, now: datetime, cfg: dict) -> bool:
    last = hist.get_meta("audit:last_report")
    if not last:
        return True
    open_count = hist.conn.execute("SELECT COUNT(*) FROM audit_findings WHERE resolved_at IS NULL AND severity IN ('critical','high')").fetchone()[0]
    return open_count > 0 and (now - datetime.fromisoformat(last)) >= timedelta(days=int(cfg["remind_days"]))


def _narrative(new, still_open, resolved, cfg_ai: dict, client=None) -> Optional[str]:
    try:
        from .diagnose import _default_client
        client = client or _default_client(cfg_ai)
        payload = {"new": [f.to_dict() for f in new], "still_open": [f.to_dict() for f in still_open],
                   "resolved": [f.to_dict() for f in resolved]}
        resp = client.messages.create(model=cfg_ai["model"], max_tokens=500, system=AI_SYSTEM,
                                      messages=[{"role": "user", "content": json.dumps(payload, indent=1)}])
        text = "\n".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text").strip()
        return text or None
    except Exception as e:  # noqa: BLE001
        log.warning("Audit narrative failed (%s: %s); sending findings only", type(e).__name__, e)
        return None


def open_findings(hist: History, device: Optional[str] = None) -> list[dict]:
    ensure_schema(hist)
    q = "SELECT * FROM audit_findings WHERE resolved_at IS NULL" + (" AND device=?" if device else "")
    rows = hist.conn.execute(q, (device,) if device else ()).fetchall()
    out = [dict(r) for r in rows]
    for r in out:
        r["evidence"], r["fix"] = json.loads(r["evidence"] or "[]"), json.loads(r["fix"] or "[]")
    out.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["device"], r["title"]))
    return out


def summary(hist: History, device: str) -> dict:
    """Compact posture for Claude's context / weekly report."""
    rows = open_findings(hist, device)
    counts = {s: sum(r["severity"] == s for r in rows) for s in SEV_ORDER}
    weights = {"critical": 25, "high": 10, "medium": 4, "low": 1}
    return {"score": max(0, 100 - sum(weights[r["severity"]] for r in rows)) if hist.get_meta("audit:last_run") else None,
            "open": counts, "top": [f"[{r['severity']}] {r['title']}" for r in rows[:4]]}


def render(new, still_open, resolved, scores: dict, now: datetime, story: Optional[str]) -> tuple[str, str, str]:
    esc = html.escape
    crit_high_new = sum(SEV_ORDER[f.severity] <= 1 for f in new)
    worst = min(scores.values(), default=100)
    subject = (f"Cisco security audit: {len(new)} new finding{'s' if len(new) != 1 else ''}"
               + (f" ({crit_high_new} critical/high)" if crit_high_new else "")
               + (f", {len(resolved)} resolved" if resolved else "")
               + f", lowest score {worst}/100 - {now.strftime('%d %b %Y')}")

    def table(items: list[Finding], with_fix: bool) -> str:
        if not items:
            return "<p style='color:#666'>none</p>"
        rows = ""
        for f in items:
            ev = "<br>".join(f"<code>{esc(e)}</code>" for e in f.evidence[:4])
            fx = ("<pre style='margin:4px 0 0 0;white-space:pre-wrap;font-size:12px'>" + esc("\n".join(f.fix)) + "</pre>") if with_fix else ""
            rows += (f"<tr><td style='white-space:nowrap'>{esc(f.device)}</td><td><b>{esc(f.severity.upper())}</b></td>"
                     f"<td><b>{esc(f.title)}</b><br><span style='color:#444'>{esc(f.detail)}</span>"
                     f"{('<br>' + ev) if ev else ''}{fx}</td></tr>")
        return ("<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;font-size:13px'>"
                "<thead><tr><th>Router</th><th>Severity</th><th>Finding / fix</th></tr></thead><tbody>" + rows + "</tbody></table>")

    score_tr = "".join(f"<tr><td>{esc(d)}</td><td>{s}/100</td><td>{sum(1 for f in still_open + new if f.device == d)}</td></tr>"
                       for d, s in sorted(scores.items()))
    body = (f"<div style='font-family:Segoe UI,Arial,sans-serif;font-size:14px'><h2 style='margin:0 0 4px 0'>Cisco security audit</h2>"
            f"<p style='color:#555;margin:0 0 12px 0'>{now.strftime('%d %b %Y %H:%M')} · daily running-config review · "
            f"secrets are never included</p>"
            + (f"<div style='border-left:5px solid #0078d4;background:#f3f9ff;padding:10px 14px;margin:0 0 14px 0'>{esc(story)}</div>" if story else "")
            + "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse'><thead><tr><th>Router</th><th>Score</th>"
              f"<th>Open findings</th></tr></thead><tbody>{score_tr}</tbody></table>"
            f"<h3>New ({len(new)})</h3>{table(new, True)}"
            f"<h3>Resolved ({len(resolved)})</h3>{table(resolved, False)}"
            f"<h3>Still open ({len(still_open)})</h3>{table(still_open, False)}"
            "<p style='color:#888;font-size:12px'>Fix commands use &lt;PLACEHOLDERS&gt; - never paste them blindly; apply in a "
            "maintenance window with a second session open. <code>--audit-fix &lt;router&gt;</code> prints a full script.</p></div>")

    lines = [f"Cisco security audit - {now.strftime('%d %b %Y %H:%M')}", ""]
    if story:
        lines += [story, ""]
    lines += [f"{d}: score {s}/100, {sum(1 for f in still_open + new if f.device == d)} open" for d, s in sorted(scores.items())]
    for label, items in (("NEW", new), ("RESOLVED", resolved), ("STILL OPEN", still_open)):
        lines += ["", f"{label} ({len(items)})"] + [f"  [{f.severity.upper():8}] {f.device}: {f.title}" for f in items]
    return subject, body, "\n".join(lines)


__all__ = ["run_audit", "open_findings", "summary", "render", "fix_script"]
