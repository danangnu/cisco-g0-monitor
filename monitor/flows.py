"""Stage 5: traffic visibility from the routers' own NetFlow cache.

How it works
  * Each router runs a small Flexible NetFlow monitor on its LAN-side interface(s) (ingress only, so it
    sees what hosts behind the router send, before NAT). Nothing is exported: the flows stay in the
    router's cache. `--netflow-config <router>` prints the exact commands; a human applies them.
  * Every cycle the monitor reads that cache over the SSH session it already uses
    (`show flow monitor <NAME> cache format csv`, read-only) and works out what changed since the
    previous read. No inbound port, no collector, no firewall rule.
  * Deltas are rolled up per hour in history.db: totals per host+port always, destination detail for
    watched ports and for anything above `detail_min_mb`. Metadata only (addresses, port, bytes) -
    never packet contents.
  * Once a day (with the config audit) rules turn the rollups into findings: cleartext protocols in use,
    internal-only services leaving the site, large uploads to one destination, scanning behaviour.
    They share the audit's lifecycle: new / still open / resolved / accepted.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

from .audit import Config, Finding
from .collector import _default_connect
from .config import Device
from .history import History

log = logging.getLogger(__name__)

DEFAULTS = {
    "enabled": False,
    "monitor_name": "G0MON",
    "cache_entries": 32768,
    "detail_min_mb": 1,            # keep destination detail for host->dst flows above this per poll
    "retention_days": 14,
    "lookback_days": 7,            # a finding stays open while seen within this window
    "upload_gb_alert": 5,          # one host -> one external destination, per day
    "scan_min_destinations": 100,  # distinct destinations on one port within one poll
    "cache_warn_percent": 85,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS flow_hourly (
  hour TEXT NOT NULL, device TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, proto INTEGER NOT NULL,
  dport INTEGER NOT NULL, bytes INTEGER NOT NULL, pkts INTEGER NOT NULL, polls INTEGER NOT NULL, dsts INTEGER NOT NULL,
  PRIMARY KEY (hour, device, src, dst, proto, dport));
CREATE INDEX IF NOT EXISTS flow_hourly_dev ON flow_hourly(device, hour);
CREATE TABLE IF NOT EXISTS flow_state (
  device TEXT NOT NULL, k TEXT NOT NULL, first TEXT, bytes INTEGER, pkts INTEGER, PRIMARY KEY (device, k));
CREATE TABLE IF NOT EXISTS flow_hosts (
  device TEXT NOT NULL, src TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY (device, src));
"""

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp"}
PORT_NAMES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 69: "tftp", 80: "http",
              110: "pop3", 123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
              389: "ldap", 443: "https", 445: "smb", 465: "smtps", 513: "rlogin", 514: "rsh/syslog", 587: "submission",
              993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5060: "sip", 8080: "http-alt"}
COMMON_PORTS = {(6, 80), (6, 443), (17, 443), (17, 53), (6, 53), (17, 123)}   # never treated as "scanning"
# Replies from a server to a client carry the client's temporary port as "destination port" (Windows uses
# 49152-65535, Linux 32768-60999). Grouping them keeps the rollups small and the reports readable.
EPHEMERAL = 65536
EPHEMERAL_MIN = 32768


@dataclass(frozen=True)
class Service:
    id: str
    label: str
    ports: frozenset          # {(proto, port)}
    severity: str
    external_only: bool       # only a problem when the destination is outside the private ranges
    why: str
    fix: tuple


SERVICES = [
    Service("telnet", "Telnet", frozenset({(6, 23)}), "high", False,
            "Telnet sends the login and everything typed in cleartext; anyone on the path can read it.",
            ("Find the source device (on the router: show ip arp <source-ip>).",
             "Enable SSH on the destination and switch the client/script to SSH.",
             "Then block it: deny tcp any any eq 23 on the LAN interface ACL.")),
    Service("ftp", "FTP", frozenset({(6, 21)}), "high", False,
            "FTP sends username, password and file contents in cleartext.",
            ("Find the job or device that uploads/downloads by FTP (often a backup job, scanner or camera).",
             "Switch it to SFTP or FTPS (same server, usually a settings change).")),
    Service("mail-cleartext", "POP3/IMAP without TLS", frozenset({(6, 110), (6, 143)}), "high", False,
            "Mail clients on ports 110/143 send the mailbox password in cleartext unless STARTTLS is used.",
            ("Reconfigure the mail client or device to IMAPS (993) / POP3S (995).",)),
    Service("rsh", "rlogin/rsh", frozenset({(6, 513), (6, 514)}), "high", False,
            "rlogin and rsh are unauthenticated/cleartext remote shells.",
            ("Replace with SSH and disable the r-services on the destination.",)),
    Service("tftp", "TFTP", frozenset({(17, 69)}), "medium", False,
            "TFTP has no authentication or encryption; configs and firmware sent over it can be read or replaced.",
            ("Use SCP/SFTP for config and firmware transfers; keep TFTP for provisioning VLANs only.",)),
    Service("smb-external", "SMB/NetBIOS to the internet", frozenset({(6, 445), (6, 139), (17, 137), (17, 138)}), "high", True,
            "Windows file sharing should never leave the site: it leaks password hashes to whoever answers and is the "
            "classic worm/ransomware path.",
            ("Identify the source PC and check it for malware / a mis-typed share path.",
             "Block outbound tcp/445, tcp/139, udp/137-138 on the WAN ACL.")),
    Service("rdp-external", "RDP to the internet", frozenset({(6, 3389), (17, 3389)}), "high", True,
            "Remote Desktop directly to an internet address exposes credentials and is a common intrusion route.",
            ("Confirm who uses it and why; move it behind a VPN or a gateway with MFA.",)),
    Service("snmp-external", "SNMP to the internet", frozenset({(17, 161)}), "high", True,
            "SNMP v1/v2c sends its community string in cleartext; it should stay inside the management network.",
            ("Find what polls an external address by SNMP; use a VPN or SNMPv3 with authentication and privacy.",)),
    Service("db-external", "Database protocol to the internet", frozenset({(6, 1433), (6, 3306)}), "medium", True,
            "MSSQL/MySQL straight across the internet is usually unencrypted and exposes the database login.",
            ("Tunnel database access through a VPN or enable TLS on the database connection.",)),
    Service("ldap-external", "LDAP to the internet", frozenset({(6, 389)}), "medium", True,
            "Plain LDAP to an external server can carry directory passwords in cleartext.",
            ("Use LDAPS (636) or a VPN for external directory lookups.",)),
    Service("smtp-external", "SMTP (port 25) to the internet", frozenset({(6, 25)}), "low", True,
            "Port 25 is server-to-server mail and often unencrypted; from a PC it can also be the pattern of a spam bot. "
            "Printers and scanners using scan-to-email legitimately do this.",
            ("Check the source: a mail server or scanner is fine (accept this finding); a PC is not.",
             "Point devices at the mail provider's submission port 587 with TLS.")),
]
WATCH_PORTS = frozenset(p for s in SERVICES for p in s.ports)


def bucket_port(proto: int, dport: int) -> int:
    if proto in (6, 17) and dport >= EPHEMERAL_MIN and (proto, dport) not in WATCH_PORTS:
        return EPHEMERAL
    return dport


class FlowNotConfigured(Exception):
    pass


@dataclass
class FlowRow:
    src: str
    dst: str
    proto: int
    dport: int
    bytes: int
    pkts: int
    first: str = ""

    @property
    def key(self) -> str:
        return f"{self.src}|{self.dst}|{self.proto}|{self.dport}"


def _cfg(settings: dict) -> dict:
    return {**DEFAULTS, **(settings.get("flows") or {})}


def ensure_schema(hist: History) -> None:
    hist.conn.executescript(SCHEMA)


def svc_name(proto: int, dport: int) -> str:
    p = PROTO_NAMES.get(proto, str(proto))
    if proto == 1:
        return "icmp"
    if dport == EPHEMERAL:
        return f"{p}/high ports (replies)"
    name = PORT_NAMES.get(dport)
    return f"{p}/{dport}" + (f" ({name})" if name else "")


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_multicast or a.is_link_local or a.is_loopback or a.is_reserved or a.is_unspecified)


# --------------------------------------------------------------------------- router configuration
def lan_interfaces_from_config(config_text: str, wan_interface: str) -> tuple[list[str], str]:
    """Pick the LAN-side interfaces from a (redacted) running-config. Returns (interfaces, how)."""
    c = Config(config_text)
    wan = wan_interface.lower()
    nat_inside, addressed = [], []
    for header, body in c.blocks.items():
        if not header.lower().startswith("interface "):
            continue
        name = header.split(" ", 1)[1]
        if name.lower() == wan or "shutdown" in body:
            continue
        if re.match(r"(?i)(loopback|null|tunnel|dialer|virtual|nvi|embedded|async)", name):
            continue
        if "ip nat inside" in body:
            nat_inside.append(name)
        if any(b.startswith("ip address ") for b in body) and "ip nat outside" not in body:
            addressed.append(name)
    if nat_inside:
        return nat_inside, "interfaces marked 'ip nat inside'"
    return addressed, "interfaces with an IP address other than the WAN interface (no 'ip nat inside' found)"


def router_config(device: Device, lan_interfaces: list[str], settings: dict) -> str:
    cfg = _cfg(settings)
    name = cfg["monitor_name"]
    inactive = int(settings.get("interval_seconds", 300)) + 120
    lines = [
        f"! Flexible NetFlow for {device.name} ({device.host}) - traffic visibility for cisco-g0-monitor",
        "! Nothing is exported: flows stay in the router's cache and the monitor reads them over SSH.",
        "! Ingress on the LAN side only, so it sees what hosts behind this router send, before NAT.",
        "configure terminal",
        f"flow record {name}-REC",
        " match ipv4 source address",
        " match ipv4 destination address",
        " match ipv4 protocol",
        " match transport destination-port",
        " collect counter bytes long",
        " collect counter packets long",
        " collect timestamp sys-uptime first",
        " collect timestamp sys-uptime last",
        f"flow monitor {name}",
        f" record {name}-REC",
        f" cache entries {int(cfg['cache_entries'])}",
        f" cache timeout inactive {inactive}",
        " cache timeout active 604800",
    ]
    for intf in lan_interfaces:
        lines += [f"interface {intf}", f" ip flow monitor {name} input"]
    lines += [
        "end",
        "!",
        "! Check it is collecting (wait a minute, browse something from a PC behind the router):",
        f"!   show flow monitor {name} cache format csv",
        "!   show processes cpu history        <- CPU should look the same as before",
        "! If all is well:  write memory",
        "!",
        "! To remove it again:",
    ]
    for intf in lan_interfaces:
        lines += [f"!   interface {intf}", f"!    no ip flow monitor {name} input"]
    lines += [f"!   no flow monitor {name}", f"!   no flow record {name}-REC"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- reading the cache
_META_RES = {
    "cache_size": re.compile(r"Cache size:\s+(\d+)"),
    "entries": re.compile(r"Current entries:\s+(\d+)"),
    "high_watermark": re.compile(r"High Watermark:\s+(\d+)"),
    "flows_added": re.compile(r"Flows added:\s+(\d+)"),
}
_NOT_CONFIGURED_RE = re.compile(r"(?im)^\s*%|not found|does not exist|invalid input|unrecognized command")
_PROTO_BY_NAME = {"TCP": 6, "UDP": 17, "ICMP": 1, "GRE": 47, "ESP": 50}


def _col(header: str) -> Optional[str]:
    h = header.strip().upper()
    if "SRC ADDR" in h:
        return "src"
    if "DST ADDR" in h:
        return "dst"
    if "DST PORT" in h:
        return "dport"
    if "PROT" in h:
        return "proto"
    if h.startswith("BYTES"):
        return "bytes"
    if h.startswith("PKTS") or h.startswith("PACKETS"):
        return "pkts"
    if "FIRST" in h:
        return "first"
    return None


def parse_cache_csv(output: str) -> tuple[dict, list[FlowRow]]:
    """Parse `show flow monitor NAME cache format csv`. Returns (meta, rows)."""
    meta = {k: int(m.group(1)) for k, rx in _META_RES.items() if (m := rx.search(output))}
    lines = output.splitlines()
    hdr_idx = next((i for i, ln in enumerate(lines) if "," in ln and "SRC ADDR" in ln.upper()), None)
    if hdr_idx is None:
        if "entries" in meta:                       # monitor exists, cache is empty
            return meta, []
        if _NOT_CONFIGURED_RE.search(output) or not output.strip():
            msg = next((ln.strip() for ln in lines if ln.strip().startswith("%")), None) \
                or next((ln.strip() for ln in lines if ln.strip() and ln.strip() != "^"), "no output")
            if "invalid input" in msg.lower() or "not found" in msg.lower() or "does not exist" in msg.lower():
                msg += (" - the router does not know this flow monitor: the --netflow-config block was not applied, "
                        "or part of it was refused")
            raise FlowNotConfigured(msg[:300])
        raise FlowNotConfigured("unrecognised output: " + (lines[0][:120] if lines else ""))
    cols = [_col(h) for h in lines[hdr_idx].split(",")]
    need = {"src", "dst", "proto", "dport", "bytes"}
    if not need <= set(cols):
        raise FlowNotConfigured(f"flow record is missing fields {sorted(need - set(c for c in cols if c))}; "
                                f"header was: {lines[hdr_idx][:160]}")
    rows: list[FlowRow] = []
    for ln in lines[hdr_idx + 1:]:
        parts = [p.strip() for p in ln.split(",")]
        if len(parts) != len(cols):
            continue
        rec = {c: v for c, v in zip(cols, parts) if c}
        try:
            proto = _PROTO_BY_NAME.get(rec["proto"].upper()) or int(rec["proto"], 0)
            dport = 0 if proto == 1 else int(rec["dport"], 0)   # ICMP: "port" is type/code - collapse it
            ipaddress.ip_address(rec["src"])
            ipaddress.ip_address(rec["dst"])
            rows.append(FlowRow(rec["src"], rec["dst"], proto, dport, int(rec["bytes"]), int(rec.get("pkts") or 0),
                                rec.get("first", "")))
        except (ValueError, KeyError):
            continue
    return meta, rows


def fetch_cache(device: Device, settings: dict, connect: Optional[Callable] = None) -> str:
    connect = connect or _default_connect
    cmd = f"show flow monitor {_cfg(settings)['monitor_name']} cache format csv"
    assert cmd.startswith("show ")           # read-only by construction
    conn = connect(device, settings["ssh_timeout"])
    try:
        return conn.send_command(cmd, read_timeout=180)
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- ingest
def ingest(hist: History, device: str, rows: list[FlowRow], now: datetime, settings: dict) -> dict:
    """Turn a cache snapshot into per-hour deltas. Returns stats for logging."""
    cfg = _cfg(settings)
    ensure_schema(hist)
    interval = int(settings.get("interval_seconds", 300))
    ts = now.isoformat(timespec="seconds")
    hour = now.strftime("%Y-%m-%dT%H")
    last = hist.get_meta(f"flow:last_poll:{device}")
    prev = {r["k"]: (r["first"], r["bytes"], r["pkts"])
            for r in hist.conn.execute("SELECT k, first, bytes, pkts FROM flow_state WHERE device=?", (device,))}
    # After a gap the cache holds an unknown amount of history; counting it now would pile days of traffic
    # into one hour. Re-baseline instead: remember the counters, record nothing.
    baseline = last is None or (now - datetime.fromisoformat(last)).total_seconds() > interval * 2 + 120

    # Collapse duplicate keys (several LAN interfaces can report the same flow key).
    merged: dict[str, FlowRow] = {}
    for r in rows:
        m = merged.get(r.key)
        if m:
            m.bytes += r.bytes
            m.pkts += r.pkts
        else:
            merged[r.key] = FlowRow(r.src, r.dst, r.proto, r.dport, r.bytes, r.pkts, r.first)

    stats = {"entries": len(merged), "active": 0, "bytes": 0, "baseline": baseline}
    if not baseline:
        totals: dict[tuple, list] = defaultdict(lambda: [0, 0, set()])
        detail: dict[tuple, list] = {}
        detail_min = int(float(cfg["detail_min_mb"]) * 1024 * 1024)
        for k, r in merged.items():
            p = prev.get(k)
            same_entry = p is not None and (p[0] or "") == (r.first or "") and r.bytes >= (p[1] or 0)
            d_bytes = r.bytes - p[1] if same_entry else r.bytes
            d_pkts = max(0, r.pkts - (p[2] or 0)) if same_entry else r.pkts
            if d_bytes <= 0:
                continue
            stats["active"] += 1
            stats["bytes"] += d_bytes
            dport = bucket_port(r.proto, r.dport)
            t = totals[(r.src, r.proto, dport)]
            t[0] += d_bytes
            t[1] += d_pkts
            t[2].add(r.dst)
            if (r.proto, dport) in WATCH_PORTS or d_bytes >= detail_min:
                d = detail.setdefault((r.src, r.dst, r.proto, dport), [0, 0])
                d[0] += d_bytes
                d[1] += d_pkts
        up = ("INSERT INTO flow_hourly (hour,device,src,dst,proto,dport,bytes,pkts,polls,dsts) VALUES (?,?,?,?,?,?,?,?,1,?) "
              "ON CONFLICT(hour,device,src,dst,proto,dport) DO UPDATE SET bytes=bytes+excluded.bytes, pkts=pkts+excluded.pkts, "
              "polls=polls+1, dsts=MAX(dsts, excluded.dsts)")
        with hist.conn:
            hist.conn.executemany(up, [(hour, device, s, "*", pr, dp, b, pk, len(dsts)) for (s, pr, dp), (b, pk, dsts) in totals.items()])
            hist.conn.executemany(up, [(hour, device, s, d, pr, dp, b, pk, 1) for (s, d, pr, dp), (b, pk) in detail.items()])
            hist.conn.executemany("INSERT INTO flow_hosts (device,src,first_seen,last_seen) VALUES (?,?,?,?) "
                                  "ON CONFLICT(device,src) DO UPDATE SET last_seen=excluded.last_seen",
                                  [(device, s, ts, ts) for s in {s for (s, _, _) in totals}])
    with hist.conn:
        hist.conn.execute("DELETE FROM flow_state WHERE device=?", (device,))
        hist.conn.executemany("INSERT INTO flow_state (device,k,first,bytes,pkts) VALUES (?,?,?,?,?)",
                              [(device, k, r.first, r.bytes, r.pkts) for k, r in merged.items()])
    hist.set_meta(f"flow:last_poll:{device}", ts)
    return stats


def poll_all(devices: list[Device], settings: dict, hist: History, now: datetime, connect: Optional[Callable] = None) -> dict:
    """Read every router's flow cache (in parallel) and ingest it. Never raises for a single router."""
    cfg = _cfg(settings)
    out: dict = {}
    due = []
    for dv in devices:
        skipped = hist.get_meta(f"flow:unconfigured:{dv.name}")
        if skipped and (now - datetime.fromisoformat(skipped)).total_seconds() < 3600:
            continue                      # no flow monitor on this router yet: look again in an hour
        due.append(dv)
    if not due:
        return out

    def one(dv: Device):
        try:
            return dv, fetch_cache(dv, settings, connect), None
        except Exception as e:  # noqa: BLE001
            return dv, None, f"{type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}"[:200]

    with ThreadPoolExecutor(max_workers=max(1, int(settings.get("max_workers", 10)))) as pool:
        fetched = list(pool.map(one, due))
    for dv, raw, err in fetched:
        if err:
            log.warning("Flows %s: could not read cache: %s", dv.name, err)
            continue
        try:
            meta, rows = parse_cache_csv(raw)
        except FlowNotConfigured as e:
            hist.set_meta(f"flow:unconfigured:{dv.name}", now.isoformat(timespec="seconds"))
            log.info("Flows %s: no flow monitor '%s' on this router (%s). Run --netflow-config %s for the commands.",
                     dv.name, cfg["monitor_name"], e, dv.name)
            continue
        stats = ingest(hist, dv.name, rows, now, settings)
        stats.update(meta)
        out[dv.name] = stats
        size, cur = meta.get("cache_size"), meta.get("entries", len(rows))
        full = bool(size) and cur * 100 >= size * int(cfg["cache_warn_percent"])
        hist.set_meta(f"flow:cache:{dv.name}", f"{cur}/{size or '?'}")
        log.log(logging.WARNING if full else logging.INFO, "Flows %s: %d cache entries%s, %d active, %s sent%s%s",
                dv.name, cur, f" of {size}" if size else "", stats["active"], fmt_bytes(stats["bytes"]),
                " (baseline read, nothing counted yet)" if stats["baseline"] else "",
                " - CACHE NEARLY FULL: raise flows.cache_entries and re-apply --netflow-config" if full else "")
    return out


def prune(hist: History, now: datetime, settings: dict) -> None:
    ensure_schema(hist)
    cutoff = (now - timedelta(days=int(_cfg(settings)["retention_days"]))).strftime("%Y-%m-%dT%H")
    with hist.conn:
        hist.conn.execute("DELETE FROM flow_hourly WHERE hour < ?", (cutoff,))


# --------------------------------------------------------------------------- analysis
def _has_data(hist: History, device: str) -> bool:
    return hist.get_meta(f"flow:last_poll:{device}") is not None


def analyse(hist: History, devices: list[Device], now: datetime, settings: dict) -> dict[str, list[Finding]]:
    """Findings per router that has flow data. A router with data and no problems maps to []."""
    cfg = _cfg(settings)
    ensure_schema(hist)
    since = (now - timedelta(days=int(cfg["lookback_days"]))).strftime("%Y-%m-%dT%H")
    out: dict[str, list[Finding]] = {}
    for dv in devices:
        if not _has_data(hist, dv.name):
            continue
        findings: list[Finding] = []
        rows = hist.conn.execute("SELECT hour, src, dst, proto, dport, bytes, polls FROM flow_hourly "
                                 "WHERE device=? AND hour>=? AND dst!='*'", (dv.name, since)).fetchall()

        # 1. watched services (cleartext protocols; internal-only services leaving the site)
        for s in SERVICES:
            pairs: dict[tuple, dict] = {}
            for r in rows:
                if (r["proto"], r["dport"]) not in s.ports or (s.external_only and not is_external(r["dst"])):
                    continue
                p = pairs.setdefault((r["src"], r["dst"], r["proto"], r["dport"]),
                                     {"bytes": 0, "polls": 0, "last": "", "hours": Counter()})
                p["bytes"] += r["bytes"]
                p["polls"] += r["polls"]
                p["last"] = max(p["last"], r["hour"])
                p["hours"][r["hour"][11:13]] += r["polls"]
            if not pairs:
                continue
            hosts = sorted({k[0] for k in pairs})
            top = sorted(pairs.items(), key=lambda kv: -kv[1]["polls"])[:6]
            ev = [f"{src} -> {dst} {svc_name(pr, dp)}: seen in {p['polls']} five-minute interval(s), {fmt_bytes(p['bytes'])} sent, "
                  f"last {p['last'].replace('T', ' ')}:00, mostly around {p['hours'].most_common(1)[0][0]}:00"
                  for (src, dst, pr, dp), p in top]
            findings.append(Finding(
                f"flow_{s.id}", s.severity, f"{s.label} in use",
                f"{s.why} Seen from {len(hosts)} host(s) behind this router in the last {cfg['lookback_days']} days "
                f"({', '.join(hosts[:5])}{'...' if len(hosts) > 5 else ''}). Flow data shows who talks to whom on which "
                f"port, not the contents.", list(s.fix), ev, dv.name, key=s.id))

        # 2. large uploads from one host to one external destination in a day
        limit = int(float(cfg["upload_gb_alert"]) * 1024 ** 3)
        per_day: dict[tuple, int] = defaultdict(int)
        for r in rows:
            if is_external(r["dst"]):
                per_day[(r["src"], r["dst"], r["hour"][:10])] += r["bytes"]
        big: dict[tuple, list] = defaultdict(list)
        for (src, dst, day), b in per_day.items():
            if b >= limit:
                big[(src, dst)].append((day, b))
        for (src, dst), days in sorted(big.items()):
            days.sort()
            findings.append(Finding(
                "flow_upload", "medium", f"Large upload from {src} to {dst}",
                f"One host sent more than {cfg['upload_gb_alert']} GB to a single internet address in a day. That is normal for "
                f"cloud backup or video upload and abnormal for most office PCs - check what {src} is and whether {dst} is expected.",
                [f"Identify the host (on the router: show ip arp {src}) and what it runs.",
                 f"Look up who owns {dst} (whois) - a backup or cloud provider is usually fine; accept the finding if so.",
                 "If unexpected, isolate the host and check it for malware or an unauthorised sync tool."],
                [f"{day}: {fmt_bytes(b)} sent" for day, b in days[-5:]], dv.name, key=f"{src}>{dst}"))

        # 3. scanning: one host touching many destinations on the same port within one poll
        scans = hist.conn.execute("SELECT src, proto, dport, MAX(dsts) AS m, MAX(hour) AS last, COUNT(*) AS hours FROM flow_hourly "
                                  "WHERE device=? AND hour>=? AND dst='*' AND dsts>=? GROUP BY src, proto, dport",
                                  (dv.name, since, int(cfg["scan_min_destinations"]))).fetchall()
        for r in scans:
            if (r["proto"], r["dport"]) in COMMON_PORTS or r["proto"] not in (1, 6, 17) or r["dport"] == EPHEMERAL:
                continue
            risky = (r["proto"], r["dport"]) in WATCH_PORTS or r["dport"] in (22, 23, 445, 3389, 5900)
            what = "ping sweep" if r["proto"] == 1 else f"scan on {svc_name(r['proto'], r['dport'])}"
            findings.append(Finding(
                "flow_scan", "high" if risky else "medium", f"Possible {what} from {r['src']}",
                "One host contacted an unusually large number of different addresses on the same port within five minutes. "
                "That is what a network scanner, a worm or a mis-behaving monitoring tool looks like.",
                [f"Identify the host (on the router: show ip arp {r['src']}).",
                 "If it is a known scanner or monitoring server, accept this finding.",
                 "Otherwise isolate it and check it for malware."],
                [f"{r['src']} -> up to {r['m']} different destinations on {svc_name(r['proto'], r['dport'])} in one interval; "
                 f"seen in {r['hours']} hour(s), last {r['last'].replace('T', ' ')}:00"], dv.name,
                key=f"{r['src']}|{r['proto']}|{r['dport']}"))
        out[dv.name] = findings
    return out


def traffic_summary(hist: History, device: str, now: datetime, hours: int = 24, top: int = 5) -> Optional[dict]:
    """What the hosts behind a router sent in the last N hours. None when the router has no flow data."""
    ensure_schema(hist)
    if not _has_data(hist, device):
        return None
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H")
    q = lambda sql, *a: hist.conn.execute(sql, (device, since, *a)).fetchall()  # noqa: E731
    total = q("SELECT COALESCE(SUM(bytes),0) AS b, COUNT(DISTINCT src) AS hosts, COALESCE(SUM(polls),0) AS p FROM flow_hourly "
              "WHERE device=? AND hour>=? AND dst='*'")[0]
    hosts = q("SELECT src, SUM(bytes) AS b FROM flow_hourly WHERE device=? AND hour>=? AND dst='*' GROUP BY src ORDER BY b DESC LIMIT ?", top)
    ports = q("SELECT proto, dport, SUM(bytes) AS b, COUNT(DISTINCT src) AS n FROM flow_hourly WHERE device=? AND hour>=? AND dst='*' "
              "GROUP BY proto, dport ORDER BY b DESC LIMIT ?", top)
    dsts = q("SELECT dst, SUM(bytes) AS b, COUNT(DISTINCT src) AS n FROM flow_hourly WHERE device=? AND hour>=? AND dst!='*' "
             "GROUP BY dst ORDER BY b DESC LIMIT ?", top)
    peak = q("SELECT hour, SUM(bytes) AS b FROM flow_hourly WHERE device=? AND hour>=? AND dst='*' GROUP BY hour ORDER BY b DESC LIMIT 1")
    return {
        "hours": hours, "sent_bytes": total["b"], "sent": fmt_bytes(total["b"]), "hosts": total["hosts"],
        "top_hosts": [{"host": r["src"], "sent": fmt_bytes(r["b"])} for r in hosts],
        "top_services": [{"service": svc_name(r["proto"], r["dport"]), "sent": fmt_bytes(r["b"]), "hosts": r["n"]} for r in ports],
        "top_destinations": [{"dst": r["dst"], "sent": fmt_bytes(r["b"]), "hosts": r["n"]} for r in dsts],
        "peak_hour": ({"hour": peak[0]["hour"].replace("T", " ") + ":00", "sent": fmt_bytes(peak[0]["b"])} if peak else None),
        "last_poll": hist.get_meta(f"flow:last_poll:{device}"), "cache": hist.get_meta(f"flow:cache:{device}"),
    }
