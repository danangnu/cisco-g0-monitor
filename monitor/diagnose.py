"""Stage 1 of the AI agent: diagnose alerts.

When a cycle produces alert-worthy events, this module
  1. logs in to the affected routers and runs a FIXED, READ-ONLY set of commands
     (nothing in this file can change router configuration),
  2. redacts anything that looks like a secret,
  3. sends the whole picture for the cycle (every router, not just the broken ones)
     to Claude once, and
  4. returns a structured Diagnosis that the notifier puts at the top of the alert.

Any failure here (SSH, API, budget) is logged and the alert is sent without a
diagnosis. Diagnosis never blocks or delays alerting beyond the configured timeout.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .collector import CheckResult, _default_connect
from .config import Device

log = logging.getLogger(__name__)

# Which event kinds are worth an investigation. Recovery / info events are not.
DIAGNOSE_KINDS = {
    "INTERNET_DOWN", "SUBNET_CHANGED", "SUBNET_MISMATCH", "ADDRESS_LOST", "DEVICE_UNREACHABLE",
}
REMINDER_KINDS = {"INTERNET_STILL_DOWN", "DEVICE_STILL_UNREACHABLE"}

MAX_OUTPUT_CHARS = 3500        # per command, keeps the prompt small
LOG_TAIL_LINES = 40

# ---------------------------------------------------------------------------
# Read-only command set. `{intf}` is the monitored interface, `{gw}` the default
# gateway learned from the routing table (commands using it are skipped if unknown).
# Add commands here only if they are `show`, `ping` or `traceroute`.
# ---------------------------------------------------------------------------
READ_ONLY_COMMANDS: list[tuple[str, str]] = [
    ("uptime",        "show version | include uptime|restarted|System returned"),
    ("ip_interface",  "show ip interface {intf}"),
    ("interface",     "show interfaces {intf}"),
    ("default_route", "show ip route 0.0.0.0"),
    ("dhcp_lease",    "show dhcp lease"),
    ("arp",           "show ip arp {intf}"),
    ("ping_gateway",  "ping {gw} source {intf} repeat 5 timeout 1"),
    ("ping_dns_ip",   "ping 8.8.8.8 source {intf} repeat 5 timeout 1"),
    ("ping_dns_name", "ping google.com source {intf} repeat 2 timeout 2"),
    ("traceroute",    "traceroute 8.8.8.8 source {intf} numeric timeout 1 probe 1 ttl 1 8"),
    ("log_tail",      "show logging"),
]
_ALLOWED_PREFIXES = ("show ", "ping ", "traceroute ")
assert all(c.startswith(_ALLOWED_PREFIXES) for _, c in READ_ONLY_COMMANDS)

# Default gateway, from `show ip route 0.0.0.0` (static/DHCP-installed: "  * 192.168.1.1" descriptor
# block, or "via 192.168.1.1") and from `show dhcp lease` ("Temp default-gateway addr: 192.168.1.1").
_GATEWAY_RES = [
    re.compile(r"default-gateway addr:\s*(\d{1,3}(?:\.\d{1,3}){3})", re.I),
    re.compile(r"gateway of last resort is\s+(\d{1,3}(?:\.\d{1,3}){3})", re.I),
    re.compile(r"\bvia\s+(\d{1,3}(?:\.\d{1,3}){3})", re.I),
    re.compile(r"^\s*\*?\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$", re.M),
]


def find_gateway(text: str) -> Optional[str]:
    for rx in _GATEWAY_RES:
        m = rx.search(text)
        if m:
            try:
                ip = ipaddress.ip_address(m.group(1))
                if not ip.is_unspecified:
                    return str(ip)
            except ValueError:
                continue
    return None
_REDACT_RES = [
    re.compile(r"(?i)\b(password|secret|key|community|psk|token)(\s+\d)?\s+\S+"),
    re.compile(r"(?i)\b(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:password|secret))\s+\S+"),
]


def redact(text: str) -> str:
    for rx in _REDACT_RES:
        text = rx.sub(lambda m: m.group(1) + " [REDACTED]", text)
    return text


def _tail(text: str, n: int) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n:]) if len(lines) > n else text


def _clip(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_OUTPUT_CHARS else text[:MAX_OUTPUT_CHARS] + "\n...[truncated]"


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> bool:
    """Can the monitor itself open a TCP connection to the router? (for unreachable devices)"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@dataclass
class DeviceDiagnostics:
    device: str
    host: str
    collected: bool
    error: Optional[str] = None
    tcp_port_open: Optional[bool] = None
    gateway: Optional[str] = None
    outputs: dict = field(default_factory=dict)   # name -> {"command": str, "output": str}
    seconds: float = 0.0


def collect_device(device: Device, settings: dict, connect: Optional[Callable] = None) -> DeviceDiagnostics:
    """Run the read-only command set on one router."""
    connect = connect or _default_connect
    t0 = time.monotonic()
    d = DeviceDiagnostics(device=device.name, host=device.host, collected=False)
    conn = None
    try:
        conn = connect(device, settings["ssh_timeout"])
        for name, template in READ_ONLY_COMMANDS:
            if "{gw}" in template and not d.gateway:
                d.outputs[name] = {"command": template, "output": "(skipped: default gateway unknown)"}
                continue
            cmd = template.format(intf=device.interface, gw=d.gateway or "")
            assert cmd.startswith(_ALLOWED_PREFIXES)  # belt and braces: never anything but show/ping/traceroute
            try:
                out = conn.send_command(cmd, read_timeout=45)
            except Exception as e:  # noqa: BLE001 - one slow/unsupported command must not stop the rest
                out = f"(command failed: {type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''})"
            if name == "log_tail":
                out = _tail(out, LOG_TAIL_LINES)
            if name in ("default_route", "dhcp_lease") and not d.gateway:
                d.gateway = find_gateway(out)
            d.outputs[name] = {"command": cmd, "output": _clip(redact(out))}
        d.collected = True
    except Exception as e:  # noqa: BLE001
        d.error = f"{type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}"[:200]
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
    d.seconds = round(time.monotonic() - t0, 1)
    return d


def collect(devices: list[Device], settings: dict, connect: Optional[Callable] = None,
            probe: Optional[Callable] = None) -> dict[str, DeviceDiagnostics]:
    """Run diagnostics on several routers in parallel. Unreachable ones get a TCP probe only."""
    connect, probe = connect or _default_connect, probe or tcp_probe
    cfg = settings.get("ai", {})
    out: dict[str, DeviceDiagnostics] = {}
    with ThreadPoolExecutor(max_workers=max(1, int(settings.get("max_workers", 10)))) as pool:
        futs = {pool.submit(collect_device, dv, settings, connect): dv for dv in devices}
        for fut, dv in futs.items():
            try:
                out[dv.name] = fut.result(timeout=int(cfg.get("collect_timeout_seconds", 120)))
            except Exception as e:  # noqa: BLE001
                out[dv.name] = DeviceDiagnostics(dv.name, dv.host, False, error=f"{type(e).__name__}: {e}"[:200])
    for dv in devices:
        dd = out[dv.name]
        if not dd.collected:
            dd.tcp_port_open = probe(dv.host, dv.port)
    return out


# ---------------------------------------------------------------------------
# Claude
# ---------------------------------------------------------------------------
@dataclass
class Diagnosis:
    summary: str
    scope: str                       # single_device | multiple_devices | all_devices | upstream | unknown
    likely_cause: str
    evidence: list[str]
    recommended_actions: list[str]
    confidence: str                  # low | medium | high
    per_device: list[dict]           # [{"device": ..., "finding": ...}]
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def as_text(self) -> str:
        lines = [f"AI DIAGNOSIS ({self.confidence} confidence, scope: {self.scope.replace('_', ' ')})",
                 self.summary, "", f"Likely cause: {self.likely_cause}"]
        if self.evidence:
            lines += ["Evidence:"] + [f"  - {e}" for e in self.evidence]
        if self.recommended_actions:
            lines += ["Recommended actions:"] + [f"  {i}. {a}" for i, a in enumerate(self.recommended_actions, 1)]
        if self.per_device:
            lines += ["Per device:"] + [f"  - {d.get('device')}: {d.get('finding')}" for d in self.per_device]
        return "\n".join(lines)


DIAGNOSIS_TOOL = {
    "name": "report_diagnosis",
    "description": "Report the diagnosis of the current alert(s).",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "1-2 sentences a network engineer can act on."},
            "scope": {"type": "string", "enum": ["single_device", "multiple_devices", "all_devices", "upstream", "unknown"],
                      "description": "upstream = the problem is beyond the routers (modem/ISP), all routers affected."},
            "likely_cause": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"},
                         "description": "Specific facts from the command output that support the cause. Quote values."},
            "recommended_actions": {"type": "array", "items": {"type": "string"},
                                    "description": "Ordered, concrete next steps for a human. Read-only or physical actions first."},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "per_device": {"type": "array", "items": {"type": "object", "properties": {
                "device": {"type": "string"}, "finding": {"type": "string"}}, "required": ["device", "finding"]}},
        },
        "required": ["summary", "scope", "likely_cause", "evidence", "recommended_actions", "confidence", "per_device"],
    },
}

SYSTEM_PROMPT = """You are a senior network engineer on call for a fleet of Cisco IOS / IOS-XE routers.
Each router's WAN/internet interface (usually GigabitEthernet0/0) is monitored every few minutes for
internet reachability (ping sourced from that interface) and for changes to its IP subnet.
An automated monitor has just raised one or more alerts and collected READ-ONLY diagnostics.

Your job: explain what is most likely wrong and what a human should do next.

Rules:
- Reason only from the data provided. Quote specific values (interface state, counters, DHCP lease,
  gateway ping result, traceroute hops, log lines, uptime) as evidence. Never invent output.
- Look at the fleet as a whole. If every router behind the same upstream subnet fails together,
  the cause is almost certainly upstream (modem, ISP, shared switch) rather than the routers.
  If one router fails while its neighbours on the same subnet are fine, look at that router.
- A short uptime means the router rebooted. A DHCP lease on a new subnet usually means the upstream
  modem was reset, replaced, or re-provisioned. Interface input/CRC errors suggest cabling or a port.
  Gateway unreachable with the interface up/up suggests the modem. Gateway reachable but 8.8.8.8 not
  suggests the ISP. DNS name ping failing while 8.8.8.8 works means DNS only.
- Be honest about uncertainty: if the diagnostics are missing or inconclusive, say so and give the
  next read-only check a human should run. Do not pad.
- Recommended actions must be safe and concrete (e.g. "power-cycle the modem at 192.168.1.1",
  "check the cable on rtr-147 G0/0", "call the ISP with these traceroute results"). Never
  recommend configuration changes you cannot justify from the evidence.
- Keep the summary under 60 words. Write for someone reading an email on a phone."""


def _device_context(dv: Device, r: Optional[CheckResult], state: Optional[dict], dd: Optional[DeviceDiagnostics]) -> dict:
    ctx: dict = {"device": dv.name, "host": dv.host, "interface": dv.interface,
                 "expected_subnet": dv.expected_subnet, "ping_targets": dv.ping_targets}
    if r:
        ctx["latest_check"] = {k: v for k, v in r.to_dict().items() if k not in ("device", "host", "interface")}
    if state:
        ctx["state"] = {k: state.get(k) for k in ("internet", "internet_fail_since", "baseline_network",
                                                  "baseline_ip", "reachable", "unreach_since", "addr_lost")}
        if state.get("subnet_history"):
            ctx["state"]["subnet_history"] = state["subnet_history"][-5:]
    if dd:
        ctx["diagnostics"] = {"collected": dd.collected, "error": dd.error, "tcp_port_open": dd.tcp_port_open,
                              "default_gateway": dd.gateway,
                              "commands": {k: v for k, v in dd.outputs.items()}}
    return ctx


def build_messages(events: list, devices: list[Device], results: dict, states: dict,
                   diagnostics: dict[str, DeviceDiagnostics], now: datetime) -> list[dict]:
    alerted = {e.device for e in events}
    payload = {
        "time": now.isoformat(timespec="seconds"),
        "alerts": [{"device": e.device, "kind": e.kind, "severity": e.severity, "title": e.title, "detail": e.detail}
                   for e in events],
        "routers": [
            _device_context(dv, results.get(dv.name), states.get(dv.name),
                            diagnostics.get(dv.name) if dv.name in alerted else None)
            for dv in devices
        ],
        "note": ("Routers without 'diagnostics' are healthy this cycle; their latest_check is included for comparison. "
                 "Alerts of kind MANUAL_CHECK are an engineer asking for a health assessment, not a fault: for those, "
                 "report the link's condition (lease, gateway latency, errors, uptime) and anything worth watching."),
    }
    return [{"role": "user", "content":
             "Alerts and diagnostics for this monitoring cycle (JSON):\n\n" + json.dumps(payload, indent=1)
             + "\n\nDiagnose, then call the report_diagnosis tool with your findings (do not answer in prose)."}]


class Budget:
    """Cap API calls per hour so a flapping link cannot run up a bill."""

    def __init__(self, state_dir: str, max_per_hour: int):
        self.path = os.path.join(state_dir, "ai_usage.json")
        self.max_per_hour = int(max_per_hour)

    def _load(self) -> list[float]:
        try:
            with open(self.path, encoding="utf-8") as f:
                return [float(t) for t in json.load(f)]
        except (FileNotFoundError, ValueError):
            return []

    def allow(self, now_ts: Optional[float] = None) -> bool:
        now_ts = now_ts or time.time()
        recent = [t for t in self._load() if now_ts - t < 3600]
        if self.max_per_hour and len(recent) >= self.max_per_hour:
            return False
        recent.append(now_ts)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), prefix=".ai-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(recent, f)
        os.replace(tmp, self.path)
        return True


def _default_client(cfg: dict):
    import anthropic

    return anthropic.Anthropic(api_key=cfg.get("api_key") or None,
                               timeout=float(cfg.get("timeout_seconds", 90)), max_retries=2)


def ask_claude(messages: list[dict], cfg: dict, client=None) -> Diagnosis:
    client = client or _default_client(cfg)
    t0 = time.monotonic()
    resp = client.messages.create(
        model=cfg["model"],
        max_tokens=int(cfg.get("max_tokens", 1500)),
        system=SYSTEM_PROMPT,
        tools=[DIAGNOSIS_TOOL],
        tool_choice={"type": "auto"},   # some models reject forced tool choice; the prompt asks for the tool
        messages=messages,
    )
    data = parse_response(resp)
    usage = getattr(resp, "usage", None)
    return Diagnosis(
        summary=str(data.get("summary", "")).strip(),
        scope=str(data.get("scope", "unknown")),
        likely_cause=str(data.get("likely_cause", "")).strip(),
        evidence=[str(x) for x in data.get("evidence", [])][:10],
        recommended_actions=[str(x) for x in data.get("recommended_actions", [])][:8],
        confidence=str(data.get("confidence", "low")),
        per_device=[d for d in data.get("per_device", []) if isinstance(d, dict)][:20],
        model=getattr(resp, "model", cfg["model"]),
        input_tokens=getattr(usage, "input_tokens", 0) or 0,
        output_tokens=getattr(usage, "output_tokens", 0) or 0,
        seconds=round(time.monotonic() - t0, 1),
        timestamp=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
    )


def parse_response(resp) -> dict:
    """Prefer the report_diagnosis tool call; fall back to a JSON object in the text."""
    for b in resp.content:
        if getattr(b, "type", "") == "tool_use" and isinstance(getattr(b, "input", None), dict):
            return b.input
    text = "\n".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text")
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            data = json.loads(m.group(0))
            if isinstance(data, dict) and "summary" in data:
                return data
        except json.JSONDecodeError:
            pass
    if text.strip():
        # Last resort: keep the model's prose as the summary so the engineer still sees it.
        return {"summary": text.strip()[:600], "scope": "unknown", "likely_cause": "see summary",
                "evidence": [], "recommended_actions": [], "confidence": "low", "per_device": []}
    raise ValueError("Claude returned neither a report_diagnosis tool call nor text")


def wants_diagnosis(events: list, cfg: dict) -> list:
    kinds = set(DIAGNOSE_KINDS)
    if cfg.get("diagnose_reminders"):
        kinds |= REMINDER_KINDS
    return [e for e in events if e.notify and e.kind in kinds]


def diagnose_cycle(events: list, devices: list[Device], results: dict, states: dict, settings: dict,
                   state_dir: str, now: datetime, connect: Optional[Callable] = None,
                   client=None, probe: Optional[Callable] = None) -> Optional[Diagnosis]:
    """Entry point used by the main loop. Returns None when nothing to do or on any failure."""
    cfg = settings.get("ai", {})
    if not cfg.get("enabled"):
        return None
    targets = wants_diagnosis(events, cfg)
    if not targets:
        return None
    if not (cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")):
        log.warning("ai.enabled is true but ANTHROPIC_API_KEY is not set; sending alert without diagnosis")
        return None
    if not Budget(state_dir, cfg.get("max_per_hour", 6)).allow():
        log.warning("AI diagnosis budget (%s/hour) exhausted; sending alert without diagnosis", cfg.get("max_per_hour"))
        return None

    affected = [dv for dv in devices if dv.name in {e.device for e in targets}]
    log.info("Collecting diagnostics on %s", ", ".join(d.name for d in affected))
    diagnostics = collect(affected, settings, connect=connect, probe=probe)
    for dd in diagnostics.values():
        log.info("  %s: %s in %.0fs%s", dd.device, "collected" if dd.collected else "NOT collected", dd.seconds,
                 f" ({dd.error}; tcp/22 open={dd.tcp_port_open})" if dd.error else "")

    messages = build_messages(targets, devices, results, states, diagnostics, now)
    try:
        diag = ask_claude(messages, cfg, client=client)
    except Exception as e:  # noqa: BLE001 - never let the API block an alert
        log.warning("Claude diagnosis failed (%s: %s); sending alert without diagnosis", type(e).__name__, e)
        return None
    log.info("AI diagnosis (%s, %s confidence, %d+%d tokens, %.0fs): %s",
             diag.scope, diag.confidence, diag.input_tokens, diag.output_tokens, diag.seconds, diag.summary)
    try:
        with open(os.path.join(state_dir, "diagnoses.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"diagnosis": diag.to_dict(), "alerts": [e.to_dict() for e in targets],
                                "diagnostics": {k: asdict(v) for k, v in diagnostics.items()}}) + "\n")
    except OSError as e:
        log.warning("Could not write diagnoses.jsonl: %s", e)
    return diag
