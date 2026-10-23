"""Send batched alerts via TrackIT logbulkmail, email (SMTP), Microsoft Teams and Slack."""
from __future__ import annotations

import html
import logging
import smtplib
import ssl
from email.message import EmailMessage

import requests

from .trackit import TrackitQueue

log = logging.getLogger(__name__)

ICON = {"critical": "🔴", "warning": "🟠", "info": "🔵", "ok": "🟢"}
COLOR = {"critical": "#d13438", "warning": "#ca5010", "info": "#0078d4", "ok": "#107c10"}
TEAMS_COLOR = {"critical": "Attention", "warning": "Warning", "info": "Accent", "ok": "Good"}
PREFIX = "[Cisco G0/0 Monitor]"


def _subject(events: list) -> str:
    crit = sum(e.severity == "critical" for e in events)
    head = events[0].title if len(events) == 1 else f"{len(events)} events ({crit} critical): {events[0].title}"
    return f"{PREFIX} {head}"[:200]


class Notifier:
    def __init__(self, notify_cfg: dict, state_dir: str = "/data", timeout: int = 15, trackit_connect=None):
        self.cfg = notify_cfg
        self.timeout = timeout
        self.trackit = TrackitQueue(notify_cfg.get("trackit", {}), state_dir, connect=trackit_connect)

    def channels(self) -> list[str]:
        return [name for name in ("trackit", "email", "teams", "slack") if self.cfg.get(name, {}).get("enabled")]

    def send(self, events: list) -> None:
        events = [e for e in events if e.notify]
        if not events:
            # Nothing new, but retry any TrackIT reports left over from a DB outage.
            if "trackit" in self.channels() and self.trackit.pending():
                try:
                    self.trackit.flush()
                except Exception as e:  # noqa: BLE001
                    log.warning("TrackIT retry failed: %s", e)
            return
        order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
        events = sorted(events, key=lambda e: (order.get(e.severity, 9), e.device))
        for name in self.channels():
            try:
                getattr(self, f"_send_{name}")(events)
                log.info("Sent %d event(s) via %s", len(events), name)
            except Exception as e:  # noqa: BLE001 - one channel failing must not block others
                if name == "trackit":
                    # Reports stay in the outbox and are retried next cycle; no traceback spam.
                    log.warning("TrackIT not reachable (%s); %d report(s) queued for retry",
                                e, self.trackit.pending())
                else:
                    log.exception("Failed to send alerts via %s", name)

    # ---- TrackIT logbulkmail (same path the Teltonika SMS Console uses) -----
    def _send_trackit(self, events: list) -> None:
        self.trackit.send(events)

    # ---- email (direct SMTP) -------------------------------------------------
    def _send_email(self, events: list) -> None:
        c = self.cfg["email"]
        if not c.get("host") or not c.get("to"):
            raise ValueError("email.host and email.to are required")
        msg = EmailMessage()
        msg["Subject"] = _subject(events)
        msg["From"] = c.get("from") or c.get("username")
        msg["To"] = ", ".join(c["to"])

        text = "\n\n".join(
            f"[{e.severity.upper()}] {e.title}\n  Device: {e.device} ({e.host})\n  {e.detail}\n  Time: {e.timestamp}"
            for e in events
        )
        msg.set_content(text)

        rows = "".join(
            f"<tr><td style='padding:6px 10px;border-left:4px solid {COLOR.get(e.severity, '#666')}'>"
            f"<b>{html.escape(e.title)}</b><br>"
            f"<span style='color:#555'>{html.escape(e.device)} ({html.escape(e.host)}) · {html.escape(e.timestamp)}</span><br>"
            f"{html.escape(e.detail)}</td></tr>"
            for e in events
        )
        msg.add_alternative(
            f"<html><body style='font-family:Segoe UI,Arial,sans-serif;font-size:14px'>"
            f"<table cellspacing='0' cellpadding='0' style='border-collapse:separate;border-spacing:0 8px'>{rows}</table>"
            f"<p style='color:#888;font-size:12px'>Sent by cisco-g0-monitor</p></body></html>",
            subtype="html",
        )

        port = int(c.get("port") or 587)
        security = (c.get("security") or "starttls").lower()
        ctx = ssl.create_default_context()
        if security == "ssl":
            server = smtplib.SMTP_SSL(c["host"], port, timeout=self.timeout, context=ctx)
        else:
            server = smtplib.SMTP(c["host"], port, timeout=self.timeout)
        with server:
            if security == "starttls":
                server.starttls(context=ctx)
            if c.get("username"):
                server.login(c["username"], c.get("password", ""))
            server.send_message(msg)

    # ---- Microsoft Teams (Workflows / Power Automate webhook) ---------------
    def _send_teams(self, events: list) -> None:
        url = self.cfg["teams"].get("webhook_url")
        if not url:
            raise ValueError("teams.webhook_url is required")
        body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True,
                 "text": _subject(events).replace(PREFIX, "").strip()}]
        for e in events:
            body.append({"type": "Container", "separator": True, "items": [
                {"type": "TextBlock", "wrap": True, "weight": "Bolder",
                 "color": TEAMS_COLOR.get(e.severity, "Default"), "text": f"{ICON.get(e.severity, '')} {e.title}"},
                {"type": "TextBlock", "wrap": True, "spacing": "None", "isSubtle": True,
                 "text": f"{e.device} ({e.host}) · {e.timestamp}"},
                {"type": "TextBlock", "wrap": True, "text": e.detail},
            ]})
        payload = {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4", "msteams": {"width": "Full"}, "body": body},
        }]}
        resp = requests.post(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()

    # ---- Slack (incoming webhook) -------------------------------------------
    def _send_slack(self, events: list) -> None:
        url = self.cfg["slack"].get("webhook_url")
        if not url:
            raise ValueError("slack.webhook_url is required")
        lines = [f"*{_subject(events)}*"]
        for e in events:
            lines.append(f"{ICON.get(e.severity, '')} *{e.title}*\n`{e.device}` ({e.host}) · {e.timestamp}\n{e.detail}")
        resp = requests.post(url, json={"text": "\n\n".join(lines)}, timeout=self.timeout)
        resp.raise_for_status()
