"""Stage 2: long-term memory in SQLite (<state_dir>/history.db).

Tables
  checks       one row per device per cycle: reachability, address, internet, ping %, latency
  events       every event the state machine produced
  incidents    outages with start/end/duration (opened by *_DOWN/LOST/UNREACHABLE, closed by the recovery event)
  diagnoses    every AI diagnosis
  configs      daily running-config snapshots (redacted) with a diff against the previous one
  meta         key/value (last backup date, last report date, ...)

The summary_for() output is what Claude gets as "history" on every alert, so it can see patterns
("6th outage this month, always ~02:00", "latency doubled over 3 days", "config changed yesterday").
"""
from __future__ import annotations

import json
import sqlite3
import statistics
from collections import Counter
from datetime import datetime, timedelta
from typing import Optional

OPENERS = {"INTERNET_DOWN": "internet", "DEVICE_UNREACHABLE": "ssh", "ADDRESS_LOST": "address"}
CLOSERS = {"INTERNET_RESTORED": "internet", "DEVICE_REACHABLE": "ssh", "ADDRESS_RESTORED": "address"}
POINT_EVENTS = {"SUBNET_CHANGED", "SUBNET_MISMATCH", "CONFIG_CHANGED", "LATENCY_DEGRADED", "PACKET_LOSS", "FLAPPING"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, device TEXT NOT NULL, reachable INTEGER, intf_status TEXT,
  ip TEXT, network TEXT, internet_ok INTEGER, ping_pct INTEGER, rtt_ms INTEGER, target TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS checks_dev_ts ON checks(device, ts);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, device TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT,
  title TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS events_dev_ts ON events(device, ts);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY, device TEXT NOT NULL, kind TEXT NOT NULL, category TEXT NOT NULL,
  started_at TEXT NOT NULL, ended_at TEXT, duration_s INTEGER, detail TEXT, diagnosis TEXT);
CREATE INDEX IF NOT EXISTS incidents_dev ON incidents(device, started_at);
CREATE TABLE IF NOT EXISTS diagnoses (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, devices TEXT, scope TEXT, confidence TEXT, summary TEXT,
  likely_cause TEXT, actions TEXT, model TEXT, input_tokens INTEGER, output_tokens INTEGER);
CREATE TABLE IF NOT EXISTS configs (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, device TEXT NOT NULL, sha256 TEXT NOT NULL, lines INTEGER,
  config TEXT NOT NULL, diff TEXT, added INTEGER, removed INTEGER);
CREATE INDEX IF NOT EXISTS configs_dev_ts ON configs(device, ts);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _fmt_dur(seconds: Optional[int]) -> str:
    if seconds is None:
        return "ongoing"
    h, rem = divmod(int(seconds), 3600)
    m = rem // 60
    return f"{h}h {m}m" if h else f"{m}m"


class History:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # ---- writes --------------------------------------------------------------
    def record_cycle(self, results: dict, events: list, now: datetime, diagnosis=None) -> None:
        ts = _iso(now)
        rows = []
        for name, r in results.items():
            target = next((t for t, p in r.ping.items() if p > 0), next(iter(r.ping), None))
            rows.append((ts, name, int(r.reachable), r.intf_status, r.ip, r.network,
                         None if r.internet_ok is None else int(r.internet_ok),
                         r.ping.get(target) if target else None, r.rtt.get(target) if target else None,
                         target, r.error))
        with self.conn:
            self.conn.executemany("INSERT INTO checks (ts,device,reachable,intf_status,ip,network,internet_ok,"
                                  "ping_pct,rtt_ms,target,error) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            self.conn.executemany("INSERT INTO events (ts,device,kind,severity,title,detail) VALUES (?,?,?,?,?,?)",
                                  [(e.timestamp, e.device, e.kind, e.severity, e.title, e.detail) for e in events])
            for e in events:
                if e.kind in OPENERS:
                    self.conn.execute("INSERT INTO incidents (device,kind,category,started_at,detail) VALUES (?,?,?,?,?)",
                                      (e.device, e.kind, OPENERS[e.kind], e.timestamp, e.detail))
                elif e.kind in CLOSERS:
                    row = self.conn.execute("SELECT id, started_at FROM incidents WHERE device=? AND category=? "
                                            "AND ended_at IS NULL ORDER BY id DESC LIMIT 1",
                                            (e.device, CLOSERS[e.kind])).fetchone()
                    if row:
                        dur = int((_parse(e.timestamp) - _parse(row["started_at"])).total_seconds())
                        self.conn.execute("UPDATE incidents SET ended_at=?, duration_s=? WHERE id=?",
                                          (e.timestamp, max(dur, 0), row["id"]))
                elif e.kind in POINT_EVENTS:
                    self.conn.execute("INSERT INTO incidents (device,kind,category,started_at,ended_at,duration_s,detail)"
                                      " VALUES (?,?,?,?,?,0,?)", (e.device, e.kind, "change", e.timestamp, e.timestamp, e.detail))
            if diagnosis:
                devs = sorted({e.device for e in events if e.notify})
                self.conn.execute("INSERT INTO diagnoses (ts,devices,scope,confidence,summary,likely_cause,actions,model,"
                                  "input_tokens,output_tokens) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                  (ts, json.dumps(devs), diagnosis.scope, diagnosis.confidence, diagnosis.summary,
                                   diagnosis.likely_cause, json.dumps(diagnosis.recommended_actions), diagnosis.model,
                                   diagnosis.input_tokens, diagnosis.output_tokens))
                self.conn.execute("UPDATE incidents SET diagnosis=? WHERE ended_at IS NULL AND diagnosis IS NULL "
                                  "AND device IN (%s)" % ",".join("?" * len(devs)), (diagnosis.summary, *devs))

    def record_config(self, device: str, now: datetime, sha: str, config: str, diff: Optional[str],
                      added: int, removed: int) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO configs (ts,device,sha256,lines,config,diff,added,removed) VALUES (?,?,?,?,?,?,?,?)",
                              (_iso(now), device, sha, config.count("\n") + 1, config, diff, added, removed))

    def latest_config(self, device: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM configs WHERE device=? ORDER BY id DESC LIMIT 1", (device,)).fetchone()

    def get_meta(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO meta (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                              (key, value))

    def prune(self, now: datetime, retention_days: int) -> None:
        cutoff = _iso(now - timedelta(days=retention_days))
        with self.conn:
            self.conn.execute("DELETE FROM checks WHERE ts < ?", (cutoff,))
            self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            # keep the newest config per device even if old, so there is always a baseline to diff against
            self.conn.execute("DELETE FROM configs WHERE ts < ? AND id NOT IN "
                              "(SELECT MAX(id) FROM configs GROUP BY device)", (cutoff,))

    # ---- reads ---------------------------------------------------------------
    def incidents(self, device: Optional[str], since: datetime, categories=("internet", "ssh", "address")) -> list:
        q = "SELECT * FROM incidents WHERE started_at >= ? AND category IN (%s)" % ",".join("?" * len(categories))
        args: list = [_iso(since), *categories]
        if device:
            q += " AND device=?"
            args.append(device)
        return self.conn.execute(q + " ORDER BY started_at", args).fetchall()

    def latency(self, device: str, since: datetime, until: Optional[datetime] = None) -> list[int]:
        q = "SELECT rtt_ms FROM checks WHERE device=? AND ts >= ? AND rtt_ms IS NOT NULL"
        args = [device, _iso(since)]
        if until:
            q += " AND ts < ?"
            args.append(_iso(until))
        return [r["rtt_ms"] for r in self.conn.execute(q, args)]

    def loss(self, device: str, since: datetime) -> Optional[float]:
        """Average ping success % over the window, counting only cycles where the device answered SSH."""
        row = self.conn.execute("SELECT AVG(ping_pct) AS a, COUNT(*) AS n FROM checks WHERE device=? AND ts >= ? "
                                "AND reachable=1 AND ping_pct IS NOT NULL", (device, _iso(since))).fetchone()
        return round(row["a"], 1) if row and row["n"] else None

    def uptime(self, device: str, since: datetime) -> Optional[float]:
        row = self.conn.execute("SELECT SUM(internet_ok) AS ok, COUNT(internet_ok) AS n FROM checks "
                                "WHERE device=? AND ts >= ? AND internet_ok IS NOT NULL", (device, _iso(since))).fetchone()
        return round(100.0 * row["ok"] / row["n"], 2) if row and row["n"] else None

    def summary_for(self, device: str, now: datetime, days: int = 30) -> dict:
        """Compact history for Claude's context (and --history)."""
        since = now - timedelta(days=days)
        inc = self.incidents(device, since)
        hours = Counter(_parse(i["started_at"]).hour for i in inc)
        recent = [{"kind": i["kind"], "started": i["started_at"][:16], "duration": _fmt_dur(i["duration_s"]),
                   "diagnosis": (i["diagnosis"] or "")[:160] or None} for i in inc[-5:]]
        lat_7d = self.latency(device, now - timedelta(days=7), now - timedelta(days=1))
        lat_24h = self.latency(device, now - timedelta(days=1))
        cfg = self.latest_config(device)
        changes = self.conn.execute("SELECT ts, added, removed FROM configs WHERE device=? AND diff IS NOT NULL "
                                    "AND ts >= ? ORDER BY id DESC LIMIT 3", (device, _iso(since))).fetchall()
        subnet_changes = self.conn.execute("SELECT started_at, detail FROM incidents WHERE device=? AND kind='SUBNET_CHANGED' "
                                           "AND started_at >= ? ORDER BY id DESC LIMIT 3", (device, _iso(since))).fetchall()
        out = {
            "window_days": days,
            "uptime_percent": self.uptime(device, since),
            "incidents": len(inc),
            "total_downtime": _fmt_dur(sum(i["duration_s"] or 0 for i in inc)) if inc else "0m",
            "incidents_by_hour_of_day": dict(sorted(hours.items())) if inc else {},
            "recent_incidents": recent,
            "latency_ms": {"avg_prev_7d": round(statistics.mean(lat_7d)) if lat_7d else None,
                           "avg_last_24h": round(statistics.mean(lat_24h)) if lat_24h else None},
            "ping_success_last_24h_percent": self.loss(device, now - timedelta(days=1)),
            "subnet_changes": [{"at": s["started_at"][:16], "detail": s["detail"][:120]} for s in subnet_changes],
            "config": None if not cfg else {
                "last_backup": cfg["ts"][:16], "lines": cfg["lines"],
                "recent_changes": [{"at": c["ts"][:16], "added": c["added"], "removed": c["removed"]} for c in changes],
            },
        }
        return out

    def fleet_summary(self, devices: list[str], now: datetime, days: int = 7) -> dict:
        return {d: self.summary_for(d, now, days) for d in devices}

    def recent_diagnoses(self, since: datetime, limit: int = 10) -> list:
        return self.conn.execute("SELECT * FROM diagnoses WHERE ts >= ? ORDER BY id DESC LIMIT ?",
                                 (_iso(since), limit)).fetchall()
