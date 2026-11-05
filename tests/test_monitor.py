from datetime import datetime, timedelta, timezone

import pytest

from monitor.collector import CheckResult, build_ping_command, check_device
from monitor.config import DEFAULT_SETTINGS, Device
from monitor.engine import evaluate
from monitor.main import run_cycle
from monitor.parsers import ParseError, parse_ping, parse_show_ip_interface
from monitor.state import StateStore

SHOW_STATIC = """GigabitEthernet0/0 is up, line protocol is up
  Internet address is 203.0.113.5/29
  Broadcast address is 255.255.255.255
  MTU is 1500 bytes
  Helper address is not set
"""
SHOW_DHCP = """GigabitEthernet0/0 is up, line protocol is up
  Internet address is 100.64.12.34/22
  Broadcast address is 255.255.255.255
  Address determined by DHCP
"""
SHOW_ADMIN_DOWN = """GigabitEthernet0/0 is administratively down, line protocol is down
  Internet address is 203.0.113.5/29
"""
SHOW_NO_IP = """GigabitEthernet0/0 is up, line protocol is up
  Internet protocol processing disabled
"""
SHOW_XE = """GigabitEthernet0/0/0 is up, line protocol is up
  Internet address is 198.51.100.10/30
  Broadcast address is 255.255.255.255
  Address determined by non-volatile memory
"""
PING_OK = """Type escape sequence to abort.
Sending 5, 100-byte ICMP Echos to 8.8.8.8, timeout is 2 seconds:
Packet sent with a source address of 203.0.113.5
!!!!!
Success rate is 100 percent (5/5), round-trip min/avg/max = 12/14/18 ms"""
PING_FAIL = """Type escape sequence to abort.
Sending 5, 100-byte ICMP Echos to 8.8.8.8, timeout is 2 seconds:
.....
Success rate is 0 percent (0/5)"""


# ---------------- parsers ----------------
def test_parse_static():
    i = parse_show_ip_interface(SHOW_STATIC)
    assert (i.status, i.protocol, i.ip, i.network, i.method) == ("up", "up", "203.0.113.5/29", "203.0.113.0/29", "static")
    assert i.is_up


def test_parse_dhcp_and_xe():
    assert parse_show_ip_interface(SHOW_DHCP).method == "dhcp"
    assert parse_show_ip_interface(SHOW_DHCP).network == "100.64.12.0/22"
    xe = parse_show_ip_interface(SHOW_XE)
    assert xe.name == "GigabitEthernet0/0/0" and xe.network == "198.51.100.8/30"


def test_parse_admin_down_and_no_ip():
    d = parse_show_ip_interface(SHOW_ADMIN_DOWN)
    assert d.status == "administratively down" and not d.is_up
    n = parse_show_ip_interface(SHOW_NO_IP)
    assert n.ip is None and n.network is None and n.is_up


def test_parse_mask_notation():
    i = parse_show_ip_interface("GigabitEthernet0/0 is up, line protocol is up\n  Internet address is 10.1.1.1 255.255.255.0\n")
    assert i.network == "10.1.1.0/24"


def test_parse_invalid_command():
    with pytest.raises(ParseError):
        parse_show_ip_interface("              ^\n% Invalid input detected at '^' marker.\n")


def test_parse_ping():
    assert parse_ping(PING_OK) == 100
    assert parse_ping(PING_FAIL) == 0
    assert parse_ping("Success rate is 60 percent (3/5), round-trip min/avg/max = 1/2/3 ms") == 60
    assert parse_ping("% Invalid source address- IP address not on this router") == 0


def test_ping_command():
    assert build_ping_command("8.8.8.8", "GigabitEthernet0/0", None, 5, 2) == \
        "ping 8.8.8.8 source GigabitEthernet0/0 repeat 5 timeout 2"
    assert build_ping_command("1.1.1.1", "Gi0/0", "INTERNET", 3, 1) == \
        "ping vrf INTERNET 1.1.1.1 source Gi0/0 repeat 3 timeout 1"


# ---------------- engine ----------------
DEV = Device(name="r1", host="10.0.0.1", device_type="cisco_ios", port=22, username="u", password="p",
             secret="", interface="GigabitEthernet0/0", vrf=None, ping_targets=["8.8.8.8"])
T0 = datetime(2026, 10, 22, 8, 0, tzinfo=timezone(timedelta(hours=8)))


def res(ok=True, ip="203.0.113.5/29", net="203.0.113.0/29", reachable=True, status="up"):
    return CheckResult(device="r1", host="10.0.0.1", interface="GigabitEthernet0/0", timestamp="t",
                       reachable=reachable, error=None if reachable else "timeout",
                       intf_status=status if reachable else None, intf_protocol=status if reachable else None,
                       ip=ip if reachable else None, network=net if reachable else None, addr_method="static",
                       ping={"8.8.8.8": 100 if ok else 0}, internet_ok=(ok if reachable else None),
                       reason=None if ok else "ping from GigabitEthernet0/0 failed (8.8.8.8 0%)")


def run(seq, device=DEV, settings=DEFAULT_SETTINGS, step=5):
    state, out = None, []
    for i, r in enumerate(seq):
        state, ev = evaluate(state, r, device, settings, T0 + timedelta(minutes=step * i))
        out.append([e.kind for e in ev])
    return state, out


def test_baseline_then_quiet():
    state, out = run([res(), res(), res()])
    assert out == [["BASELINE_LEARNED"], [], []]
    assert state["baseline_network"] == "203.0.113.0/29" and state["internet"] == "up"


def test_internet_down_needs_two_failures_and_recovers():
    _, out = run([res(), res(ok=False), res(ok=False), res(ok=False), res(), res()])
    assert out == [["BASELINE_LEARNED"], [], ["INTERNET_DOWN"], [], [], ["INTERNET_RESTORED"]]


def test_single_blip_does_not_alert():
    _, out = run([res(), res(ok=False), res(), res()])
    assert out == [["BASELINE_LEARNED"], [], [], []]


def test_subnet_change_alerts_once_and_rebaselines():
    state, out = run([res(), res(ip="198.51.100.6/30", net="198.51.100.4/30"),
                      res(ip="198.51.100.6/30", net="198.51.100.4/30")])
    assert out == [["BASELINE_LEARNED"], ["SUBNET_CHANGED"], []]
    assert state["baseline_network"] == "198.51.100.4/30"
    assert state["subnet_history"][0]["from"] == "203.0.113.0/29"


def test_ip_change_same_subnet_is_info_not_notified():
    state = None
    state, _ = evaluate(state, res(), DEV, DEFAULT_SETTINGS, T0)
    state, ev = evaluate(state, res(ip="203.0.113.6/29"), DEV, DEFAULT_SETTINGS, T0)
    assert [e.kind for e in ev] == ["IP_CHANGED"] and ev[0].notify is False


def test_expected_subnet_mismatch():
    pinned = Device(**{**DEV.__dict__, "expected_subnet": "203.0.113.0/29"})
    _, out = run([res(ip="192.0.2.2/30", net="192.0.2.0/30"), res(ip="192.0.2.2/30", net="192.0.2.0/30"), res()],
                 device=pinned)
    assert out == [["SUBNET_MISMATCH"], [], ["SUBNET_MATCHES_EXPECTED"]]


def test_address_lost_then_new_subnet():
    _, out = run([res(), res(ok=False, ip=None, net=None), res(ok=False, ip=None, net=None),
                  res(ip="100.64.0.9/22", net="100.64.0.0/22"), res(ip="100.64.0.9/22", net="100.64.0.0/22")])
    assert out[2] == ["ADDRESS_LOST", "INTERNET_DOWN"]
    assert out[3] == ["SUBNET_CHANGED"]
    assert out[4] == ["INTERNET_RESTORED"]


def test_unreachable_does_not_touch_internet_state():
    state, out = run([res(), res(reachable=False), res(reachable=False), res(), res()])
    assert out == [["BASELINE_LEARNED"], [], ["DEVICE_UNREACHABLE"], [], ["DEVICE_REACHABLE"]]
    assert state["internet"] == "up"


def test_reminder_while_down():
    seq = [res()] + [res(ok=False)] * 15   # 5-minute steps -> 75 min of outage
    _, out = run(seq)
    flat = [k for ks in out for k in ks]
    assert flat.count("INTERNET_DOWN") == 1
    assert flat.count("INTERNET_STILL_DOWN") == 1   # 60 min after first alert


# ---------------- end-to-end with a fake router ----------------
class FakeConn:
    def __init__(self, router):
        self.r = router

    def send_command(self, cmd, read_timeout=None):
        self.r["commands"].append(cmd)
        if cmd.startswith("show ip interface"):
            return self.r["show"]
        if cmd.startswith("ping"):
            return self.r["ping"]
        return "% Invalid input detected"

    def disconnect(self):
        pass


class CaptureNotifier:
    def __init__(self):
        self.sent = []

    def send(self, events, diagnosis=None):
        self.sent.extend(e for e in events if e.notify)
        self.diagnosis = diagnosis


def test_end_to_end_cycle(tmp_path):
    routers = {"10.0.0.1": {"show": SHOW_STATIC, "ping": PING_OK, "commands": []},
               "10.0.0.2": {"show": SHOW_DHCP, "ping": PING_OK, "commands": []}}

    def connect(device, timeout):
        if device.host == "10.0.0.3":
            raise TimeoutError("TCP connection to device failed")
        return FakeConn(routers[device.host])

    devs = [Device(**{**DEV.__dict__, "name": f"r{i}", "host": f"10.0.0.{i}"}) for i in (1, 2, 3)]
    store, notifier = StateStore(str(tmp_path)), CaptureNotifier()
    clock = iter(T0 + timedelta(minutes=5 * i) for i in range(10))
    cycle = lambda: run_cycle(devs, DEFAULT_SETTINGS, store, notifier, connect=connect, now_fn=lambda: next(clock))

    cycle()                                    # baselines; r3 unreachable once (below threshold)
    assert notifier.sent == []
    routers["10.0.0.1"]["ping"] = PING_FAIL    # r1 loses internet
    routers["10.0.0.2"]["show"] = SHOW_DHCP.replace("100.64.12.34/22", "100.65.0.7/24")  # r2 new subnet
    cycle()
    cycle()
    kinds = sorted((e.device, e.kind) for e in notifier.sent)
    assert kinds == [("r1", "INTERNET_DOWN"), ("r2", "SUBNET_CHANGED"), ("r3", "DEVICE_UNREACHABLE")]
    assert "ping 8.8.8.8 source GigabitEthernet0/0 repeat 5 timeout 2" in routers["10.0.0.1"]["commands"]
    assert (tmp_path / "heartbeat").exists()
    assert len((tmp_path / "events.jsonl").read_text().splitlines()) >= 3
    assert store.load()["r2"]["baseline_network"] == "100.65.0.0/24"


def test_check_device_skips_ping_when_interface_down():
    router = {"show": SHOW_ADMIN_DOWN, "ping": PING_OK, "commands": []}
    r = check_device(DEV, DEFAULT_SETTINGS, connect=lambda d, t: FakeConn(router))
    assert r.internet_ok is False and "administratively down" in r.reason
    assert not any(c.startswith("ping") for c in router["commands"])


# ---------------- TrackIT logbulkmail ----------------
from monitor.engine import Event  # noqa: E402
from monitor.trackit import TrackitQueue, build_report  # noqa: E402


class FakeDB:
    """Minimal stand-in for a PyMySQL connection to TrackIT."""
    def __init__(self, fail=False):
        self.rows, self.fail, self.commits, self.rollbacks = [], fail, 0, 0

    def cursor(self):
        db = self

        class Cur:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def execute(self, sql, params):
                if db.fail:
                    raise ConnectionError("lost connection")
                self.last = None
                if sql.strip().startswith("SELECT"):
                    self.last = next((r for r in db.rows if (r[0], r[1]) == params), None)
                else:
                    db.rows.append(params)
            def fetchone(self): return self.last
        return Cur()

    def commit(self): self.commits += 1
    def rollback(self): self.rollbacks += 1
    def close(self): pass


def ev(device="r1", kind="INTERNET_DOWN", sev="critical"):
    return Event(device, "192.168.18.143", kind, sev, f"INTERNET DOWN on {device} (GigabitEthernet0/0)",
                 "ping from GigabitEthernet0/0 failed (8.8.8.8 0%) <script>", "2026-10-22T17:00:00+08:00")


def test_trackit_report_format():
    r = build_report([ev()], "a@x.com")
    assert r["subject"].startswith("Cisco G0/0 alert: INTERNET DOWN on r1") and r["subject"].endswith("]")
    assert "&lt;script&gt;" in r["body"] and r["marker"] in r["body"]
    multi = build_report([ev("r1"), ev("r2")], "a@x.com")
    assert multi["subject"].startswith("Cisco G0/0 alerts: 2 devices (2 critical) [")
    assert build_report([ev()], "a@x.com")["subject"] == r["subject"]   # deterministic -> idempotent


def test_trackit_inserts_like_teltonika_and_is_idempotent(tmp_path):
    db = FakeDB()
    q = TrackitQueue({"to": "a@x.com, b@x.com", "from": "", "priority": 1}, str(tmp_path), connect=lambda: db)
    q.send([ev()])
    q.send([ev()])  # same events again -> no duplicate rows
    assert len(db.rows) == 2   # one per recipient
    sendto, subject, body, spoofas, spoofname, priority = db.rows[0]
    assert (sendto, spoofas, spoofname, priority) == ("a@x.com", "a@x.com", "Cisco G0/0 Monitor", 1)
    assert q.pending() == 0


def test_trackit_outage_keeps_reports_then_retries(tmp_path):
    state = {"up": False}
    db = FakeDB()

    def connect():
        if not state["up"]:
            raise ConnectionRefusedError("TrackIT DB down")
        return db

    q = TrackitQueue({"to": "a@x.com"}, str(tmp_path), connect=connect)
    with pytest.raises(ConnectionRefusedError):
        q.send([ev()])
    assert q.pending() == 1 and db.rows == []
    state["up"] = True
    q.flush()
    assert q.pending() == 0 and len(db.rows) == 1


# ---------------- Stage 1: AI diagnosis ----------------
import copy  # noqa: E402
import json  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from monitor import diagnose  # noqa: E402
from monitor.diagnose import (Budget, Diagnosis, READ_ONLY_COMMANDS, build_messages,  # noqa: E402
                              collect, diagnose_cycle, redact, wants_diagnosis)
from monitor.notifier import diagnosis_html  # noqa: E402

AI_SETTINGS = copy.deepcopy(DEFAULT_SETTINGS)
AI_SETTINGS["ai"].update(enabled=True, api_key="sk-test", model="claude-test")


def test_command_set_is_read_only():
    for _, cmd in READ_ONLY_COMMANDS:
        assert cmd.split()[0] in ("show", "ping", "traceroute"), cmd
        assert not any(w in cmd for w in ("configure", "write", "reload", "clear", "debug", "copy"))


def test_redact_secrets():
    txt = ("username admin privilege 15 secret 5 $1$abc\nenable password cisco123\n"
           "snmp-server community public RO\ncrypto isakmp key MyPSK address 1.2.3.4\nGigabitEthernet0/0 is up")
    out = redact(txt)
    assert "cisco123" not in out and "$1$abc" not in out and "public" not in out and "MyPSK" not in out
    assert "GigabitEthernet0/0 is up" in out


class DiagRouter:
    """Fake router that answers the diagnostic command set."""
    def __init__(self, gw_ok=True, inet_ok=True, uptime="2 weeks, 3 days", errors=0):
        self.cmds = []
        self.gw_ok, self.inet_ok, self.uptime, self.errors = gw_ok, inet_ok, uptime, errors

    def send_command(self, cmd, read_timeout=None):
        self.cmds.append(cmd)
        if cmd.startswith("show version"):
            return f"rtr uptime is {self.uptime}\nSystem returned to ROM by power-on"
        if cmd.startswith("show ip interface"):
            return SHOW_DHCP
        if cmd.startswith("show interfaces"):
            return f"GigabitEthernet0/0 is up, line protocol is up\n  {self.errors} input errors, {self.errors} CRC"
        if cmd.startswith("show ip route"):   # real IOS output for a DHCP-installed default route
            return ("Routing entry for 0.0.0.0/0, supernet\n  Known via \"static\", distance 254, metric 0, candidate default path\n"
                    "  Routing Descriptor Blocks:\n  * 192.168.1.1\n      Route metric is 0, traffic share count is 1")
        if cmd.startswith("show dhcp lease"):
            return "Temp IP addr: 100.64.12.34  for peer on Interface: GigabitEthernet0/0\n  Lease: 86400 secs"
        if cmd.startswith("show ip arp"):
            return "Internet  192.168.1.1   5   aabb.cc00.0100  ARPA   GigabitEthernet0/0"
        if cmd.startswith("ping 192.168.1.1"):
            return PING_OK if self.gw_ok else PING_FAIL
        if cmd.startswith("ping"):
            return PING_OK if self.inet_ok else PING_FAIL
        if cmd.startswith("traceroute"):
            return "  1 192.168.1.1 2 msec\n  2 * \n  3 * " if not self.inet_ok else "  1 192.168.1.1 1 msec\n  2 10.0.0.1 5 msec"
        if cmd.startswith("show logging"):
            return "\n".join(f"line {i}" for i in range(100)) + "\n%LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to up\nenable secret 5 $1$zzz"
        return "% Invalid input"

    def disconnect(self):
        pass


def test_collect_runs_commands_learns_gateway_and_redacts():
    r = DiagRouter()
    dd = collect([DEV], AI_SETTINGS, connect=lambda d, t: r, probe=lambda h, p: True)[DEV.name]
    assert dd.collected and dd.gateway == "192.168.1.1"
    assert "ping 192.168.1.1 source GigabitEthernet0/0 repeat 5 timeout 1" in r.cmds
    assert all(c.split()[0] in ("show", "ping", "traceroute") for c in r.cmds)
    assert "$1$zzz" not in dd.outputs["log_tail"]["output"]
    assert dd.outputs["log_tail"]["output"].count("\n") <= 40
    assert dd.tcp_port_open is None  # only probed when SSH fails


def test_collect_unreachable_device_gets_tcp_probe():
    def boom(d, t):
        raise TimeoutError("TCP connection to device failed")
    dd = collect([DEV], AI_SETTINGS, connect=boom, probe=lambda h, p: False)[DEV.name]
    assert not dd.collected and dd.tcp_port_open is False and "TimeoutError" in dd.error


def test_budget_caps_calls_per_hour(tmp_path):
    b = Budget(str(tmp_path), max_per_hour=2)
    assert b.allow(1000) and b.allow(1001) and not b.allow(1002)
    assert b.allow(1000 + 3601)  # window rolled


def test_wants_diagnosis_filters_kinds():
    evs = [ev(kind="INTERNET_DOWN"), ev(kind="INTERNET_RESTORED", sev="ok"), ev(kind="BASELINE_LEARNED", sev="info"),
           ev(kind="INTERNET_STILL_DOWN")]
    assert [e.kind for e in wants_diagnosis(evs, {})] == ["INTERNET_DOWN"]
    assert [e.kind for e in wants_diagnosis(evs, {"diagnose_reminders": True})] == ["INTERNET_DOWN", "INTERNET_STILL_DOWN"]


class FakeClaude:
    """Stands in for anthropic.Anthropic; returns a fixed report_diagnosis tool call."""
    def __init__(self, answer=None, fail=False):
        self.calls, self.fail = [], fail
        self.answer = answer or {
            "summary": "All four routers lost internet at once; their G0/0 links are up but the upstream modem at 192.168.1.1 does not answer.",
            "scope": "upstream", "likely_cause": "Upstream modem / ISP outage",
            "evidence": ["ping 192.168.1.1 from G0/0: 0% on every router", "G0/0 up/up, 0 input errors"],
            "recommended_actions": ["Power-cycle the modem at 192.168.1.1", "If still down after 5 min, call the ISP"],
            "confidence": "high", "per_device": [{"device": "rtr-143", "finding": "link up, gateway unreachable"}],
        }
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise RuntimeError("API down")
        return SimpleNamespace(content=[SimpleNamespace(type="tool_use", input=self.answer)],
                               model=kw["model"], usage=SimpleNamespace(input_tokens=1200, output_tokens=180))


def test_end_to_end_cycle_with_ai_diagnosis(tmp_path):
    hosts = [f"192.168.18.{n}" for n in (143, 145, 147, 149)]
    routers = {h: {"show": SHOW_DHCP, "ping": PING_OK, "commands": []} for h in hosts}
    diag_routers = {h: DiagRouter(gw_ok=False, inet_ok=False) for h in hosts}
    mode = {"diag": False}

    def connect(device, timeout):
        # The monitor's own check talks to FakeConn; once alerts fire, the diagnostics
        # connections (which run after all checks) talk to the richer DiagRouter.
        return diag_routers[device.host] if mode["diag"] else FakeConn(routers[device.host])

    devs = [Device(**{**DEV.__dict__, "name": f"rtr-{h.rsplit('.', 1)[1]}", "host": h}) for h in hosts]
    store, notifier, claude = StateStore(str(tmp_path)), CaptureNotifier(), FakeClaude()
    clock = iter(T0 + timedelta(minutes=5 * i) for i in range(10))

    def cycle():
        checks = {"n": 0}
        def routed(device, timeout):
            checks["n"] += 1
            mode["diag"] = checks["n"] > len(devs)   # first 4 connections are the checks
            return connect(device, timeout)
        run_cycle(devs, AI_SETTINGS, store, notifier, connect=routed, now_fn=lambda: next(clock), ai_client=claude)

    cycle()                                       # baseline, healthy -> no API call
    assert claude.calls == [] and notifier.diagnosis is None
    for r in routers.values():
        r["ping"] = PING_FAIL
    cycle()                                       # 1st failure: below threshold -> no API call
    assert claude.calls == []
    cycle()                                       # 2nd failure: INTERNET_DOWN x4 -> diagnostics + one API call

    assert len(claude.calls) == 1
    kw = claude.calls[0]
    assert kw["tool_choice"] == {"type": "auto"} and kw["tools"][0]["name"] == "report_diagnosis"
    payload = json.loads(kw["messages"][0]["content"].split("(JSON):\n\n", 1)[1].rsplit("\n\nDiagnose", 1)[0])
    assert {a["kind"] for a in payload["alerts"]} == {"INTERNET_DOWN"} and len(payload["alerts"]) == 4
    assert all("diagnostics" in r for r in payload["routers"])
    assert payload["routers"][0]["diagnostics"]["default_gateway"] == "192.168.1.1"
    assert payload["routers"][0]["diagnostics"]["commands"]["ping_gateway"]["output"].startswith("Type escape")

    d = notifier.diagnosis
    assert isinstance(d, Diagnosis) and d.scope == "upstream" and d.confidence == "high"
    assert d.input_tokens == 1200 and d.model == "claude-test"
    assert "Power-cycle the modem" in d.as_text()
    html_block = diagnosis_html(d)
    assert "AI diagnosis" in html_block and "Power-cycle the modem at 192.168.1.1" in html_block
    assert len((tmp_path / "diagnoses.jsonl").read_text().splitlines()) == 1
    assert (tmp_path / "ai_usage.json").exists()
    assert [e.kind for e in notifier.sent] == ["INTERNET_DOWN"] * 4


def test_api_failure_still_sends_alert(tmp_path):
    claude = FakeClaude(fail=True)
    evs = [ev()]
    d = diagnose_cycle(evs, [DEV], {DEV.name: res(ok=False)}, {}, AI_SETTINGS, str(tmp_path), T0,
                       connect=lambda dv, t: DiagRouter(), client=claude, probe=lambda h, p: True)
    assert d is None and len(claude.calls) == 1


def test_disabled_or_no_key_skips_quietly(tmp_path):
    off = copy.deepcopy(AI_SETTINGS); off["ai"]["enabled"] = False
    assert diagnose_cycle([ev()], [DEV], {}, {}, off, str(tmp_path), T0) is None
    nokey = copy.deepcopy(AI_SETTINGS); nokey["ai"]["api_key"] = ""
    import os
    os.environ.pop("ANTHROPIC_API_KEY", None)
    assert diagnose_cycle([ev()], [DEV], {}, {}, nokey, str(tmp_path), T0) is None


def test_trackit_report_includes_diagnosis():
    claude = FakeClaude()
    d = diagnose.ask_claude([{"role": "user", "content": "x"}], AI_SETTINGS["ai"], client=claude)
    report = build_report([ev()], "a@x.com", d)
    assert "AI diagnosis" in report["body"] and "Upstream modem" in report["body"]
    assert build_report([ev()], "a@x.com", d)["subject"] == build_report([ev()], "a@x.com")["subject"]


def test_real_sdk_request_and_response_shape():
    """Drive the real anthropic SDK against a mock HTTP transport to validate the wire format."""
    import anthropic
    try:
        import httpx2 as httpx   # anthropic >= 2.x
    except ImportError:
        import httpx
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["url"] = str(request.url)
        return httpx.Response(200, json={
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
            "stop_reason": "tool_use", "stop_sequence": None,
            "usage": {"input_tokens": 900, "output_tokens": 120},
            "content": [{"type": "tool_use", "id": "tu_1", "name": "report_diagnosis",
                         "input": FakeClaude().answer}],
        })

    client = anthropic.Anthropic(api_key="sk-test", http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    d = diagnose.ask_claude(build_messages([ev()], [DEV], {}, {}, {}, T0), AI_SETTINGS["ai"], client=client)
    assert seen["url"].endswith("/v1/messages")
    b = seen["body"]
    assert b["model"] == "claude-test" and b["tool_choice"] == {"type": "auto"}
    assert b["tools"][0]["name"] == "report_diagnosis" and "senior network engineer" in b["system"]
    assert d.scope == "upstream" and d.input_tokens == 900 and d.model == "claude-test"


def test_cmd_diagnose_all_runs_fleet_in_one_call(tmp_path, monkeypatch, capsys):
    from monitor import main as main_mod
    hosts = [f"192.168.18.{n}" for n in (143, 145, 147, 149)]
    devs = [Device(**{**DEV.__dict__, "name": f"rtr-{h.rsplit('.', 1)[1]}", "host": h}) for h in hosts]
    claude = FakeClaude()
    monkeypatch.setattr(main_mod, "check_device", lambda d, s: res(ok=d.host != hosts[1]))
    monkeypatch.setattr("monitor.diagnose._default_connect", lambda d, t: DiagRouter())
    monkeypatch.setattr("monitor.diagnose._default_client", lambda cfg: claude)
    import monitor.diagnose as dg
    monkeypatch.setattr(dg, "tcp_probe", lambda h, p: True)
    assert main_mod.cmd_diagnose("all", devs, AI_SETTINGS, StateStore(str(tmp_path))) == 0
    assert len(claude.calls) == 1
    payload = json.loads(claude.calls[0]["messages"][0]["content"].split("(JSON):\n\n", 1)[1].rsplit("\n\nDiagnose", 1)[0])
    kinds = {a["device"]: a["kind"] for a in payload["alerts"]}
    assert kinds == {"rtr-143": "MANUAL_CHECK", "rtr-145": "INTERNET_DOWN", "rtr-147": "MANUAL_CHECK", "rtr-149": "MANUAL_CHECK"}
    assert all("diagnostics" in r for r in payload["routers"])
    out = capsys.readouterr().out
    assert "Checking 4 router(s)" in out and "AI DIAGNOSIS" in out
    assert main_mod.cmd_diagnose("rtr-999", devs, AI_SETTINGS, StateStore(str(tmp_path))) == 1


def test_find_gateway_from_real_ios_outputs():
    from monitor.diagnose import find_gateway
    route_dhcp = ("Routing entry for 0.0.0.0/0, supernet\n  Known via \"static\", distance 254, metric 0, candidate default path\n"
                  "  Routing Descriptor Blocks:\n  * 192.168.1.1\n      Route metric is 0, traffic share count is 1\n")
    route_via = "S*    0.0.0.0/0 [1/0] via 203.0.113.1\n"
    lease = ("Temp IP addr: 192.168.1.104  for peer on Interface: GigabitEthernet0/0\n"
             "   DHCP Lease server: 192.168.1.1, state: 5 Bound\nTemp default-gateway addr: 192.168.1.1\n")
    assert find_gateway(route_dhcp) == "192.168.1.1"
    assert find_gateway(route_via) == "203.0.113.1"
    assert find_gateway(lease) == "192.168.1.1"
    assert find_gateway("% Network not in table") is None


def test_parse_response_falls_back_to_json_text_and_prose():
    from monitor.diagnose import parse_response
    tool = SimpleNamespace(content=[SimpleNamespace(type="tool_use", input={"summary": "s", "scope": "upstream"})])
    assert parse_response(tool)["scope"] == "upstream"
    jtext = SimpleNamespace(content=[SimpleNamespace(type="text", text='Here you go:\n{"summary": "modem down", "scope": "upstream", "confidence": "high"}')])
    assert parse_response(jtext)["summary"] == "modem down"
    prose = SimpleNamespace(content=[SimpleNamespace(type="text", text="The modem looks dead.")])
    d = parse_response(prose)
    assert d["summary"] == "The modem looks dead." and d["confidence"] == "low"
    with pytest.raises(ValueError):
        parse_response(SimpleNamespace(content=[]))


# ---------------- Stage 2: history, trends, backup, weekly report ----------------
from monitor import backup as backup_mod, report as report_mod, trends as trends_mod  # noqa: E402
from monitor.history import History  # noqa: E402

RUNNING_CFG = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:00:00 WST Mon Oct 27 2026
version 15.4
hostname rtr-143
!
enable secret 5 $1$abcd
username admin privilege 15 secret 5 $1$efgh
!
interface GigabitEthernet0/0
 ip address dhcp
 ip nat outside
!
ip route 0.0.0.0 0.0.0.0 dhcp
snmp-server community public RO
end
"""


def res_rtt(ok=True, rtt=15, pct=None):
    r = res(ok=ok)
    r.ping = {"8.8.8.8": (100 if ok else 0) if pct is None else pct}
    if ok or (pct and pct > 0):
        r.rtt = {"8.8.8.8": rtt}
    return r


def test_parse_ping_rtt():
    from monitor.parsers import parse_ping_rtt
    assert parse_ping_rtt(PING_OK) == (12, 14, 18) and parse_ping_rtt(PING_FAIL) is None


def test_history_incidents_open_close_and_summary(tmp_path):
    h = History(str(tmp_path / "h.db"))
    t = T0
    evs_down = [Event("r1", "h", "INTERNET_DOWN", "critical", "down", "ping failed", (t + timedelta(minutes=10)).isoformat())]
    evs_up = [Event("r1", "h", "INTERNET_RESTORED", "ok", "up", "back", (t + timedelta(minutes=40)).isoformat())]
    h.record_cycle({"r1": res_rtt()}, [], t)
    h.record_cycle({"r1": res_rtt(ok=False)}, evs_down, t + timedelta(minutes=10))
    h.record_cycle({"r1": res_rtt()}, evs_up, t + timedelta(minutes=40))
    inc = h.incidents("r1", t - timedelta(days=1))
    assert len(inc) == 1 and inc[0]["duration_s"] == 1800 and inc[0]["ended_at"]
    s = h.summary_for("r1", t + timedelta(hours=1), 30)
    assert s["incidents"] == 1 and s["total_downtime"] == "30m" and s["recent_incidents"][0]["duration"] == "30m"
    assert s["incidents_by_hour_of_day"] == {8: 1}
    assert s["uptime_percent"] == round(100 * 2 / 3, 2)


def test_history_prune_keeps_latest_config(tmp_path):
    h = History(str(tmp_path / "h.db"))
    old = T0 - timedelta(days=200)
    h.record_cycle({"r1": res_rtt()}, [], old)
    h.record_config("r1", old, "sha-old", "hostname a\n", None, 0, 0)
    h.prune(T0, 90)
    assert h.conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 0
    assert h.latest_config("r1")["sha256"] == "sha-old"


def _fill_latency(h, device, now, base_ms, recent_ms, every_min=5):
    """7 days of checks: baseline latency, then the last 24h at recent_ms."""
    t = now - timedelta(days=7)
    while t < now:
        ms = recent_ms if t >= now - timedelta(days=1) else base_ms
        h.record_cycle({device: res_rtt(rtt=ms)}, [], t)
        t += timedelta(minutes=every_min)


def test_trend_latency_degraded_once_per_day(tmp_path):
    h = History(str(tmp_path / "h.db"))
    _fill_latency(h, DEV.name, T0, 15, 45, every_min=15)
    states = {DEV.name: {"internet": "up"}}
    evs = trends_mod.detect(h, [DEV], states, DEFAULT_SETTINGS, T0)
    assert [e.kind for e in evs] == ["LATENCY_DEGRADED"] and "45 ms" in evs[0].detail and "15 ms" in evs[0].detail
    assert trends_mod.detect(h, [DEV], states, DEFAULT_SETTINGS, T0 + timedelta(hours=1)) == []   # not repeated
    _fill_latency(h, DEV.name, T0 + timedelta(hours=25), 15, 45, every_min=15)                  # still bad a day later
    assert [e.kind for e in trends_mod.detect(h, [DEV], states, DEFAULT_SETTINGS, T0 + timedelta(hours=25))] == ["LATENCY_DEGRADED"]


def test_trend_no_warning_when_stable_or_down(tmp_path):
    h = History(str(tmp_path / "h.db"))
    _fill_latency(h, DEV.name, T0, 15, 18, every_min=15)
    assert trends_mod.detect(h, [DEV], {DEV.name: {"internet": "up"}}, DEFAULT_SETTINGS, T0) == []
    _fill_latency(h, "r2", T0, 15, 90, every_min=15)
    assert trends_mod.detect(h, [Device(**{**DEV.__dict__, "name": "r2"})], {"r2": {"internet": "down"}}, DEFAULT_SETTINGS, T0) == []


def test_trend_packet_loss_and_flapping(tmp_path):
    h = History(str(tmp_path / "h.db"))
    t = T0 - timedelta(days=1)
    while t < T0:
        h.record_cycle({DEV.name: res_rtt(rtt=20, pct=60)}, [], t)   # 60% success all day
        t += timedelta(minutes=15)
    for i in range(3):
        at = T0 - timedelta(hours=20 - i * 5)
        h.record_cycle({}, [Event(DEV.name, DEV.host, "INTERNET_DOWN", "critical", "d", "x", at.isoformat())], at)
        h.record_cycle({}, [Event(DEV.name, DEV.host, "INTERNET_RESTORED", "ok", "u", "x", (at + timedelta(minutes=10)).isoformat())], at)
    kinds = sorted(e.kind for e in trends_mod.detect(h, [DEV], {DEV.name: {"internet": "up"}}, DEFAULT_SETTINGS, T0))
    assert kinds == ["FLAPPING", "PACKET_LOSS"]


def test_backup_normalise_redacts_and_diffs(tmp_path):
    norm = backup_mod.normalise(RUNNING_CFG)
    assert "$1$abcd" not in norm and "public" not in norm and "Last configuration change" not in norm
    assert "hostname rtr-143" in norm and "ip address dhcp" in norm
    h = History(str(tmp_path / "h.db"))
    first = backup_mod.run([DEV], DEFAULT_SETTINGS, h, T0, connect=lambda d, t: FakeCfgConn(RUNNING_CFG), force=True)
    assert [e.kind for e in first] == ["CONFIG_BACKUP"] and first[0].notify is False
    again = backup_mod.run([DEV], DEFAULT_SETTINGS, h, T0 + timedelta(days=1),
                           connect=lambda d, t: FakeCfgConn(RUNNING_CFG.replace("10:00:00", "11:11:11")), force=True)
    assert again == []   # only a volatile line changed
    changed = RUNNING_CFG.replace("ip address dhcp", "ip address 203.0.113.5 255.255.255.248")
    third = backup_mod.run([DEV], DEFAULT_SETTINGS, h, T0 + timedelta(days=2), connect=lambda d, t: FakeCfgConn(changed), force=True)
    assert [e.kind for e in third] == ["CONFIG_CHANGED"] and third[0].severity == "warning"
    assert "- ip address dhcp" in third[0].detail and "+ ip address 203.0.113.5" in third[0].detail
    assert h.latest_config(DEV.name)["added"] == 1 and h.latest_config(DEV.name)["removed"] == 1
    assert not backup_mod.is_due(h, DEFAULT_SETTINGS, T0 + timedelta(days=2, hours=3))   # already done today
    assert backup_mod.is_due(h, DEFAULT_SETTINGS, T0 + timedelta(days=3))                # 08:00 next day > hour 3


SHOW_IP_SSH_1921 = """SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Hostkey Algorithms:x509v3-ssh-rsa,ssh-rsa
Encryption Algorithms:aes128-ctr,aes192-ctr,aes256-ctr
MAC Algorithms:hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96
KEX Algorithms:diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1
Authentication timeout: 60 secs; Authentication retries: 2
Minimum expected Diffie Hellman key size : 2048 bits
"""


class FakeCfgConn:
    def __init__(self, cfg, ssh=SHOW_IP_SSH_1921):
        self.cfg, self.ssh = cfg, ssh

    def send_command(self, cmd, read_timeout=None):
        if cmd == "show ip ssh":
            return self.ssh
        assert cmd == "show running-config"
        return self.cfg

    def disconnect(self):
        pass


class ReportNotifier:
    def __init__(self):
        self.reports, self.sent = [], []

    def send(self, events, diagnosis=None):
        self.sent.extend(events)

    def send_report(self, subject, html_body, text):
        self.reports.append((subject, html_body, text))


def test_weekly_report_with_ai_narrative(tmp_path):
    h = History(str(tmp_path / "h.db"))
    _fill_latency(h, DEV.name, T0, 15, 16, every_min=30)
    at = T0 - timedelta(days=2)
    h.record_cycle({}, [Event(DEV.name, DEV.host, "INTERNET_DOWN", "critical", "d", "x", at.isoformat())], at)
    h.record_cycle({}, [Event(DEV.name, DEV.host, "INTERNET_RESTORED", "ok", "u", "x", (at + timedelta(minutes=25)).isoformat())], at)
    story = {"headline": "A quiet week apart from one 25-minute outage on r1.", "highlights": ["r1 down 25m on Mon 02:00"],
             "recommendations": ["Check the modem log for Monday 02:00"]}
    claude = FakeClaude(answer=story)
    n = ReportNotifier()
    out = report_mod.run(h, [DEV], AI_SETTINGS, T0, n, client=claude)
    assert len(claude.calls) == 1 and claude.calls[0]["tools"][0]["name"] == "weekly_narrative"
    subject, body, text = n.reports[0]
    assert subject.startswith("Cisco WAN weekly report") and "1 outage" in subject
    assert "quiet week" in body and "25m" in text and "r1" in text
    assert h.get_meta("report:last_date") == T0.date().isoformat()
    assert not report_mod.is_due(h, DEFAULT_SETTINGS, T0)
    h.record_cycle({DEV.name: res_rtt()}, [], T0 - timedelta(days=8))   # enough history for a report
    monday_9 = datetime(2026, 11, 2, 9, 0, tzinfo=T0.tzinfo)
    assert report_mod.is_due(h, DEFAULT_SETTINGS, monday_9) and not report_mod.is_due(h, DEFAULT_SETTINGS, monday_9 + timedelta(days=1))


def test_report_without_ai_still_sends(tmp_path):
    h = History(str(tmp_path / "h.db"))
    n = ReportNotifier()
    out = report_mod.run(h, [DEV], DEFAULT_SETTINGS, T0, n)
    assert out["story"] is None and n.reports and "ROUTER" in n.reports[0][2]


def test_two_weeks_of_cycles_end_to_end(tmp_path):
    """Simulated fortnight: history fills, backup runs once a day, a repeat outage is diagnosed with history,
    latency creep raises a trend warning, and the Monday report goes out."""
    hosts = [f"192.168.18.{n}" for n in (143, 145)]
    routers = {h: {"show": SHOW_DHCP, "ping": PING_OK, "commands": []} for h in hosts}
    devs = [Device(**{**DEV.__dict__, "name": f"rtr-{h.rsplit('.', 1)[1]}", "host": h}) for h in hosts]
    settings = copy.deepcopy(AI_SETTINGS)
    settings["backup"]["hour"] = 3
    store, notifier, claude = StateStore(str(tmp_path)), ReportNotifier(), FakeClaude()
    hist = History(str(tmp_path / "history.db"))
    start = datetime(2026, 10, 19, 0, 0, tzinfo=T0.tzinfo)   # a Monday
    t = start
    step = timedelta(minutes=30)

    def connect(device, timeout):
        return FakeCfgConn(RUNNING_CFG) if mode["cfg"] else (DiagRouter(gw_ok=False, inet_ok=False) if mode["diag"] else FakeConn(routers[device.host]))
    mode = {"cfg": False, "diag": False}

    class Router:  # routes connections by command, so one connect() serves checks, backups and diagnostics
        def __init__(self, host): self.host = host
        def send_command(self, cmd, read_timeout=None):
            if cmd == "show running-config":
                return RUNNING_CFG
            if cmd.startswith(("show version", "show interfaces", "show ip route", "show dhcp", "show ip arp", "traceroute", "show logging")) or "repeat 5 timeout 1" in cmd or "google.com" in cmd:
                return DiagRouter(gw_ok=False, inet_ok=False).send_command(cmd)
            return FakeConn(routers[self.host]).send_command(cmd)
        def disconnect(self): pass

    outage_days = {3, 10}   # Thursday 02:00 both weeks
    while t < start + timedelta(days=14):
        day = (t - start).days
        for h in hosts:
            routers[h]["ping"] = PING_FAIL if (day in outage_days and 2 <= t.hour < 3) else PING_OK.replace("12/14/18", f"12/{14 + day}/18")
        run_cycle(devs, settings, store, notifier, connect=lambda d, to: Router(d.host), now_fn=lambda: t, ai_client=claude, hist=hist)
        t += step

    kinds = [e.kind for e in notifier.sent]
    assert kinds.count("INTERNET_DOWN") == 4 and kinds.count("INTERNET_RESTORED") == 4   # 2 routers x 2 nights
    assert hist.conn.execute("SELECT COUNT(*) FROM configs").fetchone()[0] == 2            # one snapshot each, unchanged after
    assert hist.conn.execute("SELECT COUNT(*) FROM incidents WHERE category='internet'").fetchone()[0] == 4
    diag_calls = [c for c in claude.calls if c.get("tools") and c["tools"][0]["name"] == "report_diagnosis"]
    report_calls = [c for c in claude.calls if c.get("tools") and c["tools"][0]["name"] == "weekly_narrative"]
    audit_calls = [c for c in claude.calls if not c.get("tools")]
    assert len(audit_calls) == 2   # first audit (new findings) + the 7-day reminder while critical/high stay open
    assert len(diag_calls) == 2 and len(report_calls) == 1
    second = json.loads(diag_calls[1]["messages"][0]["content"].split("(JSON):\n\n", 1)[1].rsplit("\n\nDiagnose", 1)[0])
    hist_ctx = second["history_last_30_days"]["rtr-143"]
    assert hist_ctx["incidents"] >= 1 and hist_ctx["incidents_by_hour_of_day"].get("2") == 1
    assert hist_ctx["config"]["last_backup"]
    weekly = [r for r in notifier.reports if r[0].startswith("Cisco WAN weekly report")]
    audits = [r for r in notifier.reports if r[0].startswith("Cisco security audit")]
    assert len(weekly) == 1 and len(audits) == 2            # first audit + 7-day reminder
    assert "new finding" in audits[0][0] and "/100 (" in weekly[0][2]   # security column in the weekly table
    s = hist.summary_for("rtr-143", t, 14)
    assert s["uptime_percent"] and 95 < s["uptime_percent"] < 100


# ---------------- Stage 3: proposals and approved actions ----------------
from monitor import actions as act_mod  # noqa: E402


class ActionRouter:
    """Fake router whose internet state can be flipped by the right fix."""
    def __init__(self, broken_by="dhcp"):
        self.broken_by, self.cmds, self.config_sets = broken_by, [], []
        self.fixed = False

    def _show(self):
        if self.broken_by == "dhcp" and not self.fixed:
            return SHOW_NO_IP
        return SHOW_DHCP

    def send_command(self, cmd, read_timeout=None):
        self.cmds.append(cmd)
        if cmd.startswith("show ip interface"):
            return self._show()
        if cmd.startswith("ping"):
            return PING_OK if self.fixed else PING_FAIL
        if cmd.startswith("renew dhcp") and self.broken_by == "dhcp":
            self.fixed = True
        if cmd.startswith("clear arp-cache") and self.broken_by == "arp":
            self.fixed = True
        return ""

    def send_config_set(self, lines):
        self.config_sets.append(list(lines))
        if "no shutdown" in lines and self.broken_by == "wedged":
            self.fixed = True
        return "\n".join(lines)

    def disconnect(self):
        pass


def test_action_catalogue_is_safe():
    for a in act_mod.ACTIONS.values():
        joined = " ".join(a.exec_cmds + a.config_cmds + a.restore_cmds)
        assert "write" not in joined and "reload" not in joined and "{intf}" in joined
        if a.config_cmds:
            assert a.restore_cmds and "no shutdown" in a.restore_cmds
    assert act_mod.render_commands(act_mod.ACTIONS["bounce_interface"], DEV) == [
        "configure terminal", "interface GigabitEthernet0/0", "shutdown", "(wait 5 s)",
        "interface GigabitEthernet0/0", "no shutdown", "end"]


def test_propose_validates_and_stores(tmp_path):
    h = History(str(tmp_path / "h.db"))
    evs = [ev(kind="INTERNET_DOWN")]
    assert act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "reload", "device": "r1", "reason": "x"}, evs, T0) is None
    assert act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "nope", "reason": "x"}, evs, T0) is None
    assert act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "x"},
                           [ev(kind="SUBNET_CHANGED", sev="warning")], T0) is None          # not applicable
    p = act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "lease lost"}, evs, T0)
    assert p and len(p["id"]) == 4 and p["status"] == "pending" and p["label"].startswith("Release and renew")
    assert p["commands"] == ["release dhcp GigabitEthernet0/0", "renew dhcp GigabitEthernet0/0"]
    # one pending per device
    assert act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "clear_arp_nat", "device": "r1", "reason": "x"}, evs, T0) is None
    assert act_mod.get(h, p["id"].lower())["expires_at"] == (T0 + timedelta(hours=4)).isoformat(timespec="seconds")


def test_housekeeping_expires_and_supersedes(tmp_path):
    h = History(str(tmp_path / "h.db"))
    evs = [ev(kind="INTERNET_DOWN")]
    p = act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "x"}, evs, T0)
    out = act_mod.housekeeping(h, {"r1": {"internet": "up"}}, T0 + timedelta(minutes=10))
    assert act_mod.get(h, p["id"])["status"] == "superseded" and out[0].kind == "PROPOSAL_SUPERSEDED"
    p2 = act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "x"}, evs, T0)
    act_mod.housekeeping(h, {"r1": {"internet": "down"}}, T0 + timedelta(hours=5))
    assert act_mod.get(h, p2["id"])["status"] == "expired"
    with pytest.raises(ValueError):
        act_mod.execute(h, DEFAULT_SETTINGS, [DEV], p2["id"], now_fn=lambda: T0 + timedelta(hours=5))


def test_execute_renew_dhcp_success(tmp_path):
    h = History(str(tmp_path / "h.db"))
    r = ActionRouter("dhcp")
    p = act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "no lease"},
                        [ev(kind="ADDRESS_LOST")], T0)
    sleeps = []
    row, e = act_mod.execute(h, DEFAULT_SETTINGS, [DEV], p["id"], now_fn=lambda: T0, connect=lambda d, t: r,
                             sleep=sleeps.append, who="danang")
    assert row["status"] == "succeeded" and e.kind == "ACTION_SUCCEEDED" and "WORKED" in e.title
    assert "release dhcp GigabitEthernet0/0" in r.cmds and "renew dhcp GigabitEthernet0/0" in r.cmds
    assert sleeps == [20]
    assert json.loads(row["before_state"])["ip"] is None and json.loads(row["after_state"])["internet_ok"] is True
    assert row["decided_by"] == "danang" and "Approved by danang" in e.detail


def test_execute_bounce_always_restores_and_reports_failure(tmp_path):
    h = History(str(tmp_path / "h.db"))

    class Flaky(ActionRouter):
        def send_config_set(self, lines):
            super().send_config_set(lines)
            if "shutdown" in lines and "no shutdown" not in lines:
                raise RuntimeError("session dropped")
            return ""
    r = Flaky("upstream")   # nothing fixes it
    p = act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "bounce_interface", "device": "r1", "reason": "x"},
                        [ev(kind="INTERNET_DOWN")], T0)
    row, e = act_mod.execute(h, DEFAULT_SETTINGS, [DEV], p["id"], now_fn=lambda: T0, connect=lambda d, t: r, sleep=lambda s: None)
    assert ["interface GigabitEthernet0/0", "no shutdown"] in r.config_sets      # restore ran despite the error
    assert row["status"] == "failed" and e.kind == "ACTION_FAILED" and "session dropped" in e.detail
    assert "escalate" in e.detail


def test_execute_skips_when_already_recovered(tmp_path):
    h = History(str(tmp_path / "h.db"))
    r = ActionRouter("dhcp"); r.fixed = True
    p = act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "x"}, [ev(kind="INTERNET_DOWN")], T0)
    row, e = act_mod.execute(h, DEFAULT_SETTINGS, [DEV], p["id"], now_fn=lambda: T0, connect=lambda d, t: r, sleep=lambda s: None)
    assert row["status"] == "not_needed" and e.kind == "ACTION_NOT_NEEDED"
    assert not any(c.startswith(("release", "renew")) for c in r.cmds)


def test_cooldown_and_daily_cap(tmp_path):
    h = History(str(tmp_path / "h.db"))
    r = ActionRouter("dhcp")
    evs = [ev(kind="INTERNET_DOWN")]
    p = act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "x"}, evs, T0)
    act_mod.execute(h, DEFAULT_SETTINGS, [DEV], p["id"], now_fn=lambda: T0, connect=lambda d, t: r, sleep=lambda s: None)
    assert act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "x"}, evs, T0 + timedelta(hours=1)) is None
    assert act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "x"}, evs, T0 + timedelta(hours=7))
    capped = copy.deepcopy(DEFAULT_SETTINGS); capped["actions"]["max_per_day"] = 1
    assert act_mod.propose(h, capped, [DEV], {"action": "clear_arp_nat", "device": "r1", "reason": "x"}, evs, T0 + timedelta(hours=1)) is None


def test_alert_with_proposal_end_to_end(tmp_path):
    """Outage -> diagnosis proposes renew_dhcp -> email shows it -> --approve runs it -> result event."""
    from monitor import main as main_mod
    host = "192.168.18.143"
    router = {host: {"show": SHOW_DHCP, "ping": PING_OK, "commands": []}}
    dev = Device(**{**DEV.__dict__, "name": "rtr-143", "host": host})
    answer = {**FakeClaude().answer, "scope": "single_device",
              "proposed_action": {"action": "renew_dhcp", "device": "rtr-143", "reason": "G0/0 is up/up with no lease; modem answers ARP"}}
    claude = FakeClaude(answer=answer)
    store, notifier = StateStore(str(tmp_path)), CaptureNotifier()
    hist = History(str(tmp_path / "history.db"))
    clock = iter(T0 + timedelta(minutes=5 * i) for i in range(10))
    seq = {"n": 0}

    def connect(d, t):
        seq["n"] += 1
        return FakeConn(router[host]) if seq["n"] <= 1 else DiagRouter(gw_ok=True, inet_ok=False)
    def cycle():
        seq["n"] = 0
        run_cycle([dev], AI_SETTINGS, store, notifier, connect=connect, now_fn=lambda: next(clock), ai_client=claude, hist=hist)

    cycle()
    router[host]["ping"] = PING_FAIL
    cycle(); cycle()
    d = notifier.diagnosis
    assert d and d.proposal and d.proposal["action"] == "renew_dhcp" and d.proposal["device"] == "rtr-143"
    assert "allowed_actions" in claude.calls[0]["messages"][0]["content"]
    body = diagnosis_html(d)
    assert f"--approve {d.proposal['id']}" in body and "release dhcp GigabitEthernet0/0" in body
    assert "PROPOSED FIX" in d.as_text()
    # a second cycle while still down must not create a second proposal
    cycle()
    assert len(act_mod.list_recent(hist)) == 1

    # approve it
    ar = ActionRouter("dhcp")
    row, e = act_mod.execute(hist, AI_SETTINGS, [dev], d.proposal["id"], now_fn=lambda: next(clock),
                             connect=lambda dd, t: ar, sleep=lambda s: None)
    assert row["status"] == "succeeded" and e.kind == "ACTION_SUCCEEDED"
    assert hist.conn.execute("SELECT status FROM proposals").fetchone()[0] == "succeeded"


def test_proposal_not_created_for_unreachable_or_upstream(tmp_path):
    h = History(str(tmp_path / "h.db"))
    # DEVICE_UNREACHABLE is not in any action's applies_to
    assert act_mod.propose(h, DEFAULT_SETTINGS, [DEV], {"action": "bounce_interface", "device": "r1", "reason": "x"},
                           [ev(kind="DEVICE_UNREACHABLE")], T0) is None
    off = copy.deepcopy(DEFAULT_SETTINGS); off["actions"]["enabled"] = False
    assert act_mod.propose(h, off, [DEV], {"action": "renew_dhcp", "device": "r1", "reason": "x"}, [ev(kind="INTERNET_DOWN")], T0) is None


def test_flapping_link_keeps_outage_start_and_counts_flaps():
    seq = [res(), res(ok=False), res(ok=False), res(), res(ok=False), res(), res(ok=False), res(ok=False)]
    seq += [res(ok=False)] * 12 + [res(), res()]
    state, out = run(seq)
    flat = [k for ks in out for k in ks]
    assert flat.count("INTERNET_DOWN") == 1 and flat.count("INTERNET_RESTORED") == 1
    # the reminder (fires ~60 min after the first alert) must report the full duration, not 0m
    st, outs = None, []
    for i, r in enumerate(seq):
        st, ev_ = evaluate(st, r, DEV, DEFAULT_SETTINGS, T0 + timedelta(minutes=5 * i))
        outs += ev_
    rem = [e for e in outs if e.kind == "INTERNET_STILL_DOWN"]
    assert rem and "Down for 1h" in rem[0].detail and "came back briefly 2x" in rem[0].detail
    restored = [e for e in outs if e.kind == "INTERNET_RESTORED"][0]
    assert "came back briefly 2x" in restored.detail and "Down for 1h" in restored.detail


def test_subjects_say_recovered():
    from monitor.notifier import _subject
    ups = [Event(f"rtr-{n}", "h", "INTERNET_RESTORED", "ok", f"INTERNET RESTORED on rtr-{n}", "x", "2026-11-03T10:52:00+08:00") for n in (143, 145, 147, 149)]
    assert build_report(ups, "a@x.com")["subject"].startswith("Cisco G0/0 INTERNET RESTORED: rtr-143, rtr-145, rtr-147, rtr-149 [")
    assert _subject(ups).startswith("[Cisco G0/0 Monitor] RECOVERED: rtr-143, rtr-145, rtr-147, rtr-149")
    mixed = ups[:2] + [ev("rtr-147"), ev("rtr-149", "FLAPPING", "warning")]
    assert "(1 critical, 1 warning, 2 recovered)" in build_report(mixed, "a@x.com")["subject"]


# ---------------- Stage 4: security audit ----------------
from monitor import audit as audit_mod, posture as posture_mod  # noqa: E402

INSECURE_CFG = """version 15.4
service tcp-small-servers
hostname rtr-143
!
enable password 7 0822455D0A16
username admin privilege 15 password 0 cisco123
username ops privilege 15 secret 5 $1$abc
!
ip http server
!
interface GigabitEthernet0/0
 ip address dhcp
 ip nat outside
!
interface GigabitEthernet0/1
 ip address 192.168.18.143 255.255.255.0
!
snmp-server community public RO
snmp-server community s3cretRW RW
!
line con 0
 exec-timeout 0 0
line aux 0
line vty 0 4
 password 7 094F471A1A0A
 transport input all
!
end
"""

HARDENED_CFG = """version 15.4
service password-encryption
service timestamps log datetime msec localtime show-timezone
no service tcp-small-servers
no service udp-small-servers
hostname rtr-143
!
aaa new-model
aaa authentication login default local
enable algorithm-type scrypt secret 9 $9$abc
username danang privilege 15 algorithm-type scrypt secret 9 $9$def
!
no ip source-route
no ip http server
no ip http secure-server
ip ssh version 2
ip ssh dh min size 2048
login block-for 120 attempts 5 within 60
logging host 192.168.18.22
ntp server pool.ntp.org
no cdp run
banner login ^C Authorised access only ^C
!
ip access-list standard MGMT
 permit 192.168.18.0 0.0.0.255
ip access-list extended WAN-IN
 deny tcp any any eq 22 log
 permit ip any any
!
interface GigabitEthernet0/0
 ip address dhcp
 ip access-group WAN-IN in
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 ip nat outside
!
line con 0
 exec-timeout 10 0
line aux 0
 no exec
 transport input none
line vty 0 4
 access-class MGMT in
 exec-timeout 10 0
 transport input ssh
!
end
"""


def test_audit_finds_the_classic_problems_and_redacts():
    fs = audit_mod.audit_config(INSECURE_CFG, "rtr-143")
    rules = {f.rule for f in fs}
    assert {"enable_password", "plaintext_passwords", "type7_passwords", "snmp", "http_server", "vty_telnet",
            "vty_no_acl", "wan_interface", "small_services", "exec_timeout", "accounts", "md5_secrets"} <= rules
    crit = [f for f in fs if f.severity == "critical"]
    assert {f.rule for f in crit} == {"enable_password", "plaintext_passwords", "snmp"}
    joined = " ".join(e for f in fs for e in f.evidence) + " ".join(f.detail + f.title for f in fs)
    assert "cisco123" not in joined and "0822455D0A16" not in joined and "s3cretRW" not in joined and "public" not in joined
    assert "[REDACTED]" in joined
    assert len({f.fingerprint for f in fs}) == len(fs)   # every finding tracked separately
    assert audit_mod.score(fs) < 20
    assert fs == sorted(fs, key=lambda f: audit_mod.SEV_ORDER[f.severity])
    # the RW community must not also be reported as "v2c without ACL"
    assert not any(f.title.startswith("SNMPv2c community without") and "RW" in " ".join(f.evidence) for f in fs)


def test_audit_hardened_config_is_mostly_clean():
    fs = audit_mod.audit_config(HARDENED_CFG, "rtr-143")
    assert not [f for f in fs if f.severity in ("critical", "high")], [f.title for f in fs]
    assert audit_mod.score(fs) >= 95
    assert not any(f.rule == "vty_telnet" for f in fs)


def test_fix_script_has_placeholders_and_no_secrets():
    fs = audit_mod.audit_config(INSECURE_CFG, "rtr-143")
    script = audit_mod.fix_script(fs, "rtr-143")
    assert script.startswith("! Remediation for rtr-143") and script.endswith("write memory")
    assert "<NEW-STRONG-SECRET>" in script and "no ip http server" in script and "transport input ssh" in script
    assert "cisco123" not in script and "public" not in script


class ReportCapture(ReportNotifier):
    def channels(self):
        return ["trackit"]


def test_posture_lifecycle_new_open_resolved(tmp_path):
    h = History(str(tmp_path / "h.db"))
    n = ReportCapture()
    r1 = posture_mod.run_audit(h, DEFAULT_SETTINGS, {"rtr-143": INSECURE_CFG}, [Device(**{**DEV.__dict__, "name": "rtr-143"})], T0, notifier=n)
    assert len(r1["new"]) > 10 and r1["open"] == [] and r1["resolved"] == [] and len(n.reports) == 1
    assert n.reports[0][0].startswith("Cisco security audit:") and "critical/high" in n.reports[0][0]
    # same config next day: nothing new -> no report, findings still open
    r2 = posture_mod.run_audit(h, DEFAULT_SETTINGS, {"rtr-143": INSECURE_CFG}, [Device(**{**DEV.__dict__, "name": "rtr-143"})], T0 + timedelta(days=1), notifier=n)
    assert r2["new"] == [] and len(r2["open"]) == len(r1["new"]) and len(n.reports) == 1
    # hardened: everything resolves -> report with resolved list
    r3 = posture_mod.run_audit(h, DEFAULT_SETTINGS, {"rtr-143": HARDENED_CFG}, [Device(**{**DEV.__dict__, "name": "rtr-143"})], T0 + timedelta(days=2), notifier=n)
    assert len(r3["resolved"]) >= 10 and len(n.reports) == 2 and "resolved" in n.reports[1][0]
    assert all(r["severity"] == "low" for r in posture_mod.open_findings(h, "rtr-143"))
    p = posture_mod.summary(h, "rtr-143")
    assert p["score"] >= 95 and p["open"]["critical"] == 0
    assert h.summary_for("rtr-143", T0 + timedelta(days=2), 30)["security_posture"]["score"] == p["score"]


def test_posture_report_includes_ai_note_and_renders(tmp_path):
    h = History(str(tmp_path / "h.db"))
    n = ReportCapture()
    claude = SimpleNamespace(messages=SimpleNamespace(create=lambda **kw: SimpleNamespace(
        content=[SimpleNamespace(type="text", text="Fix the SNMP write community and Telnet first; the rest can wait.")])))
    posture_mod.run_audit(h, AI_SETTINGS, {"rtr-143": INSECURE_CFG}, [DEV], T0, notifier=n, client=claude)
    subject, body, text = n.reports[0]
    assert "Fix the SNMP write community" in body and "Fix the SNMP write community" in text
    assert "no ip http server" in body and "[REDACTED]" in body and "cisco123" not in body


def test_audit_runs_with_daily_backup_and_skips_quiet_days(tmp_path):
    hist = History(str(tmp_path / "history.db"))
    n = ReportCapture()
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    raw: dict = {}
    evs = backup_mod.run([DEV], settings, hist, T0, connect=lambda d, t: FakeCfgConn(INSECURE_CFG), force=True, raw_out=raw)
    assert DEV.name in raw and "cisco123" in raw[DEV.name]          # raw is handed to the audit only, in memory
    stored = hist.latest_config(DEV.name)["config"]
    assert "cisco123" not in stored and "password 0 [REDACTED]" in stored   # what is stored keeps the type, not the value
    res = posture_mod.run_audit(hist, settings, raw, [DEV], T0, notifier=n)
    assert res["score"][DEV.name] < 50 and len(n.reports) == 1


def test_fix_script_warns_about_monitor_account():
    fs = audit_mod.audit_config(INSECURE_CFG, "rtr-143", monitor_user="admin")
    acct = next(f for f in fs if f.rule == "accounts" and "admin" in f.title)
    assert any("THIS MONITOR" in x for x in acct.fix) and acct.fix[-2] == "no username admin"
    assert "the monitor's own login" in acct.detail


def test_ssh_findings_come_from_show_ip_ssh_not_guesses():
    # no facts -> no DH/KEX finding at all (config cannot show defaults)
    fs = audit_mod.audit_config(HARDENED_CFG, "r1")
    assert not any("Diffie" in f.title or "key exchange" in f.title for f in fs)
    # real 1921 output: DH already 2048 -> no DH finding; sha1-only KEX -> one low finding
    fs = audit_mod.audit_config(HARDENED_CFG, "r1", facts={"ssh": SHOW_IP_SSH_1921})
    titles = [f.title for f in fs]
    assert not any("Diffie" in t for t in titles)
    kex = [f for f in fs if "SHA-1 methods only" in f.title]
    assert len(kex) == 1 and kex[0].severity == "low" and "IOS upgrade" in kex[0].detail
    # weak DH reported when the router says so
    fs = audit_mod.audit_config(HARDENED_CFG, "r1", facts={"ssh": SHOW_IP_SSH_1921.replace("2048 bits", "1024 bits")})
    assert any(f.title == "SSH Diffie-Hellman minimum is 1024 bits" for f in fs)


def test_backup_collects_facts_for_audit(tmp_path):
    h = History(str(tmp_path / "h.db"))
    raw, facts = {}, {}
    backup_mod.run([DEV], DEFAULT_SETTINGS, h, T0, connect=lambda d, t: FakeCfgConn(HARDENED_CFG), force=True, raw_out=raw, facts_out=facts)
    assert "KEX Algorithms" in facts[DEV.name]["ssh"]
    res = posture_mod.run_audit(h, DEFAULT_SETTINGS, raw, [DEV], T0, facts=facts)
    assert any("SHA-1 methods only" in f.title for f in res["findings"][DEV.name])


def test_accepted_findings_leave_score_and_reports(tmp_path):
    h = History(str(tmp_path / "h.db"))
    n = ReportCapture()
    facts = {DEV.name: {"ssh": SHOW_IP_SSH_1921}}
    r1 = posture_mod.run_audit(h, DEFAULT_SETTINGS, {DEV.name: HARDENED_CFG}, [DEV], T0, notifier=n, facts=facts)
    base = r1["score"][DEV.name]
    assert any("SHA-1" in f.title for f in r1["new"])
    rows = posture_mod.accept(h, "all", "SHA-1 methods only", "1921 IOS limitation", T0)
    assert len(rows) == 1
    r2 = posture_mod.run_audit(h, DEFAULT_SETTINGS, {DEV.name: HARDENED_CFG}, [DEV], T0 + timedelta(days=1), notifier=n,
                               facts=facts, force_report=True)
    assert r2["score"][DEV.name] == base + 1 and len(r2["accepted"]) == 1
    assert not any("SHA-1" in f.title for f in r2["open"] + r2["new"])
    assert "ACCEPTED (1)" in n.reports[-1][2] and "not counted in the score" in n.reports[-1][1]
    assert not any("SHA-1" in r["title"] for r in posture_mod.open_findings(h, DEV.name))
    assert posture_mod.unaccept(h, "all", "SHA-1") == 1
    r3 = posture_mod.run_audit(h, DEFAULT_SETTINGS, {DEV.name: HARDENED_CFG}, [DEV], T0 + timedelta(days=2), facts=facts)
    assert any("SHA-1" in f.title for f in r3["open"])


def test_acceptance_survives_evidence_change(tmp_path):
    h = History(str(tmp_path / "h.db"))
    cfg5 = HARDENED_CFG.replace("username danang privilege 15 algorithm-type scrypt secret 9 $9$def",
                                "username admin privilege 15 secret 5 $1$abc")
    cfg9 = cfg5.replace("secret 5 $1$abc", "secret 9 $9$abc")
    posture_mod.run_audit(h, DEFAULT_SETTINGS, {DEV.name: cfg5}, [DEV], T0)
    assert posture_mod.accept(h, "all", "Default-style account name", "shared by apps", T0)
    r = posture_mod.run_audit(h, DEFAULT_SETTINGS, {DEV.name: cfg9}, [DEV], T0 + timedelta(days=1))
    assert not any("admin" in f.title for f in r["new"] + r["open"])
    assert any("admin" in f.title for f in r["accepted"])
    assert any("MD5" in f.title for f in r["resolved"])      # the real change is still reported


def test_ppp_credentials_get_specific_advice():
    cfg = HARDENED_CFG.replace("interface GigabitEthernet0/0\n", "interface Dialer1\n ppp chap hostname isp-user\n"
                               " ppp chap password 0 Sup3rS3cret\n ppp pap sent-username dnurdiansyah password 0 Sup3rS3cret\n!\n"
                               "interface GigabitEthernet0/0\n")
    fs = audit_mod.audit_config(cfg, "rtr-231")
    ppp = [f for f in fs if f.rule == "ppp_cleartext"]
    assert len(ppp) == 1 and ppp[0].severity == "high" and len(ppp[0].evidence) == 2
    assert "service password-encryption" in ppp[0].fix and "CHAP" in ppp[0].detail
    assert not any(f.rule == "plaintext_passwords" for f in fs)           # no misleading "use secret" advice
    assert all("Sup3rS3cret" not in e for f in fs for e in f.evidence)
    enc = cfg.replace("password 0 Sup3rS3cret", "password 7 0822455D0A16")
    fs7 = audit_mod.audit_config(enc, "rtr-231")
    assert [f.severity for f in fs7 if f.rule == "ppp_credentials"] == ["low"]
    assert not any(f.rule in ("ppp_cleartext", "type7_passwords") for f in fs7)
