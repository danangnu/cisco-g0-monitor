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

    def send(self, events):
        self.sent.extend(e for e in events if e.notify)


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
