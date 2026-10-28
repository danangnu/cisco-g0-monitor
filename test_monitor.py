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
        if cmd.startswith("show ip route"):
            return "Routing entry for 0.0.0.0/0, supernet\n  Known via \"dhcp\"\n  * 192.168.1.1\n      Route metric is 0, via 192.168.1.1"
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
    assert kw["tool_choice"] == {"type": "tool", "name": "report_diagnosis"}
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
    assert b["model"] == "claude-test" and b["tool_choice"] == {"type": "tool", "name": "report_diagnosis"}
    assert b["tools"][0]["name"] == "report_diagnosis" and "senior network engineer" in b["system"]
    assert d.scope == "upstream" and d.input_tokens == 900 and d.model == "claude-test"
