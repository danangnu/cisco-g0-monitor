"""Queue alert emails in TrackIT `logbulkmail`, the same way the Teltonika SMS Console does.

TrackIT's mailer picks up rows with mailstatus 'Queue in Database' and sends them,
so this app never talks to an SMTP server itself.

Mirrors teltonika-sms-console/src/main/services/trackitDeviceFaultAlert.ts:
  * one consolidated HTML report per cycle, subject ends with a report ID [ABCDEF1234]
  * idempotent: a row with the same sendto + mailsubject is never inserted twice
  * SELECT + INSERT inside one transaction
  * same columns/values: dates, times, sendto, mailsubject, mailcontent,
    mailstatus='Queue in Database', mailtype='Email', cc=0, spoofas, spoofname, priority, attachment=0

Extra over the Teltonika version: if the TrackIT database is unreachable, reports are kept
in <state_dir>/trackit_outbox.json and retried every cycle (safe because inserts are idempotent).
"""
from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import tempfile

log = logging.getLogger(__name__)

MARKER_PREFIX = "CISCO-G0-MONITOR-REPORT"
MAX_OUTBOX = 500
SEVERITY_LABEL = {"critical": "CRITICAL", "warning": "WARNING", "info": "INFO", "ok": "RESOLVED"}


def _split(value) -> list[str]:
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(v).strip() for v in (value or []) if str(v).strip()]


def build_report(events: list, recipient: str, diagnosis=None) -> dict:
    if not events:
        raise ValueError("At least one event is required for a report.")

    signature = "|".join(sorted(f"{e.device}:{e.kind}:{e.timestamp}" for e in events))
    report_id = hashlib.sha256(signature.encode()).hexdigest()[:10].upper()
    marker = f"{MARKER_PREFIX}-{report_id}"

    devices = sorted({e.device for e in events})
    critical = sum(e.severity == "critical" for e in events)
    if len(events) == 1:
        head = f"Cisco G0/0 alert: {events[0].title}"
    elif len(devices) == 1:
        head = f"Cisco G0/0 alerts: {devices[0]} ({len(events)} events)"
    else:
        head = f"Cisco G0/0 alerts: {len(devices)} devices ({critical} critical)"
    tag = f" [{report_id}]"
    subject = head[: 180 - len(tag)] + tag   # keep the report ID even if the title is long

    rows = "".join(
        f"""
      <tr>
        <td>{html.escape(e.device)}</td>
        <td>{html.escape(e.host)}</td>
        <td>{html.escape(SEVERITY_LABEL.get(e.severity, e.severity.upper()))}</td>
        <td><b>{html.escape(e.title)}</b><pre style="white-space:pre-wrap;margin:4px 0 0 0">{html.escape(e.detail)}</pre></td>
        <td>{html.escape(e.timestamp.replace("T", " "))}</td>
      </tr>"""
        for e in events
    )
    n = len(events)
    from .notifier import diagnosis_html  # local import: notifier imports this module

    body = f"""
    {diagnosis_html(diagnosis)}
    <p>The Cisco G0/0 Monitor detected {n} event{'' if n == 1 else 's'} on {len(devices)} router{'' if len(devices) == 1 else 's'}.</p>
    <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse">
      <thead>
        <tr><th>Device</th><th>Host</th><th>Severity</th><th>Details</th><th>Detected</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <p>This monitor reports only. It did not change any router configuration.</p>
    <!-- {marker} -->"""

    # TrackIT's logbulkmail is DEFAULT CHARSET=latin1: keep the subject latin1-safe and
    # turn any non-ASCII in the HTML body into entities so nothing is mangled or rejected.
    subject = subject.encode("latin-1", "replace").decode("latin-1")
    body = body.encode("ascii", "xmlcharrefreplace").decode("ascii")
    return {"recipient": recipient, "subject": subject, "body": body, "marker": marker}


def persist_report(conn, report: dict, from_address: str, from_name: str, priority: int) -> str:
    """Insert one report into logbulkmail. Returns 'inserted' or 'reused'."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM logbulkmail WHERE sendto = %s AND mailsubject = %s LIMIT 1",
                (report["recipient"], report["subject"]),
            )
            if cur.fetchone():
                conn.commit()
                return "reused"
            cur.execute(
                """
                INSERT INTO logbulkmail
                  (dates, times, sendto, mailsubject, mailcontent, mailstatus, mailtype,
                   cc, spoofas, spoofname, priority, attachment)
                VALUES
                  (CURDATE(), CURTIME(), %s, %s, %s, 'Queue in Database', 'Email',
                   0, %s, %s, %s, 0)
                """,
                (report["recipient"], report["subject"], report["body"],
                 from_address or report["recipient"], from_name, int(priority)),
            )
        conn.commit()
        return "inserted"
    except Exception:
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001 - preserve the original database error
            pass
        raise


class TrackitQueue:
    def __init__(self, cfg: dict, state_dir: str, connect=None):
        self.cfg = cfg
        self.recipients = _split(cfg.get("to"))
        self.from_address = str(cfg.get("from") or "").strip()
        self.from_name = str(cfg.get("from_name") or "Cisco G0/0 Monitor")
        self.priority = int(cfg.get("priority") or 1)
        self.outbox_path = os.path.join(state_dir, "trackit_outbox.json")
        self._connect = connect or self._default_connect

    def _default_connect(self):
        import pymysql

        if not self.cfg.get("db_host"):
            raise ValueError("notify.trackit.db_host (TRACKIT_DB_HOST) is not set")
        return pymysql.connect(
            host=self.cfg["db_host"],
            port=int(self.cfg.get("db_port") or 3306),
            user=self.cfg.get("db_user") or "root",
            password=self.cfg.get("db_password") or "",
            database=self.cfg.get("db_name") or "trackitlive",
            charset="utf8mb4",
            autocommit=False,
            connect_timeout=10,
            read_timeout=30,
            write_timeout=30,
        )

    # ---- outbox (survives TrackIT DB outages and container restarts) -------
    def _load_outbox(self) -> list[dict]:
        try:
            with open(self.outbox_path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return []

    def _save_outbox(self, items: list[dict]) -> None:
        if not items:
            if os.path.exists(self.outbox_path):
                os.remove(self.outbox_path)
            return
        if len(items) > MAX_OUTBOX:
            log.error("TrackIT outbox over %d reports; dropping %d oldest", MAX_OUTBOX, len(items) - MAX_OUTBOX)
            items = items[-MAX_OUTBOX:]
        d = os.path.dirname(self.outbox_path)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".outbox-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=1)
        os.replace(tmp, self.outbox_path)

    def pending(self) -> int:
        return len(self._load_outbox())

    # ---- public --------------------------------------------------------------
    def send(self, events: list, diagnosis=None) -> None:
        if not self.recipients:
            raise ValueError("notify.trackit.to (CISCO_ALERT_RECIPIENT) is required")
        outbox = self._load_outbox()
        if events:
            outbox += [build_report(events, r, diagnosis) for r in self.recipients]
        self._save_outbox(outbox)
        self.flush()

    def flush(self) -> None:
        outbox = self._load_outbox()
        if not outbox:
            return
        conn = self._connect()  # on failure the outbox is untouched; caller logs and retries next cycle
        remaining = []
        try:
            for i, report in enumerate(outbox):
                try:
                    result = persist_report(conn, report, self.from_address, self.from_name, self.priority)
                    log.info("TrackIT logbulkmail %s: %s -> %s", result, report["subject"], report["recipient"])
                except Exception:  # noqa: BLE001
                    log.exception("TrackIT insert failed; keeping %d report(s) for retry", len(outbox) - i)
                    remaining = outbox[i:]
                    break
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._save_outbox(remaining)
        if remaining:
            raise RuntimeError(f"{len(remaining)} TrackIT report(s) pending retry")
