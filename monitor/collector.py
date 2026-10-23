"""SSH into a device and collect G0/0 address + internet reachability."""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Callable, Optional

from .config import Device
from .parsers import ParseError, parse_ping, parse_show_ip_interface

log = logging.getLogger(__name__)


@dataclass
class CheckResult:
    device: str
    host: str
    interface: str
    timestamp: str
    reachable: bool = False            # SSH login + command succeeded
    error: Optional[str] = None
    intf_status: Optional[str] = None
    intf_protocol: Optional[str] = None
    ip: Optional[str] = None
    network: Optional[str] = None
    addr_method: Optional[str] = None
    ping: dict = field(default_factory=dict)   # target -> success %
    internet_ok: Optional[bool] = None
    reason: Optional[str] = None               # why internet_ok is False

    def to_dict(self) -> dict:
        return asdict(self)


def build_ping_command(target: str, interface: str, vrf: Optional[str], count: int, timeout: int) -> str:
    vrf_part = f"vrf {vrf} " if vrf else ""
    return f"ping {vrf_part}{target} source {interface} repeat {count} timeout {timeout}"


def _default_connect(device: Device, ssh_timeout: int):
    from netmiko import ConnectHandler  # imported lazily so tests don't need a device

    params = {
        "device_type": device.device_type,
        "host": device.host,
        "port": device.port,
        "username": device.username,
        "password": device.password,
        "conn_timeout": ssh_timeout,
        "auth_timeout": ssh_timeout,
        "banner_timeout": ssh_timeout,
        "fast_cli": False,
    }
    if device.secret:
        params["secret"] = device.secret
    conn = ConnectHandler(**params)
    if device.secret and not conn.check_enable_mode():
        conn.enable()
    return conn


def check_device(
    device: Device,
    settings: dict,
    connect: Callable = _default_connect,
) -> CheckResult:
    ping_cfg = settings["ping"]
    result = CheckResult(
        device=device.name,
        host=device.host,
        interface=device.interface,
        timestamp=datetime.now().astimezone().isoformat(timespec="seconds"),
    )
    conn = None
    try:
        conn = connect(device, settings["ssh_timeout"])
        out = conn.send_command(f"show ip interface {device.interface}", read_timeout=30)
        info = parse_show_ip_interface(out)
        result.reachable = True
        result.intf_status = info.status
        result.intf_protocol = info.protocol
        result.ip = info.ip
        result.network = info.network
        result.addr_method = info.method

        if not info.is_up:
            result.internet_ok = False
            result.reason = f"{device.interface} is {info.status}, line protocol is {info.protocol}"
            return result
        if not info.ip:
            result.internet_ok = False
            result.reason = f"{device.interface} has no IP address"
            return result

        read_timeout = ping_cfg["count"] * ping_cfg["timeout"] + 20
        for target in device.ping_targets:
            cmd = build_ping_command(target, device.interface, device.vrf,
                                     ping_cfg["count"], ping_cfg["timeout"])
            try:
                pct = parse_ping(conn.send_command(cmd, read_timeout=read_timeout))
            except ParseError as e:
                log.warning("%s: could not parse ping to %s: %s", device.name, target, e)
                pct = 0
            result.ping[target] = pct
            if pct >= ping_cfg["min_success_percent"]:
                break  # one good target is enough; skip the rest to save time

        result.internet_ok = any(p >= ping_cfg["min_success_percent"] for p in result.ping.values())
        if not result.internet_ok:
            summary = ", ".join(f"{t} {p}%" for t, p in result.ping.items())
            result.reason = f"ping from {device.interface} failed ({summary})"
    except Exception as e:  # noqa: BLE001 - any failure here means "could not check"
        # Netmiko errors are multi-line; keep the headline, plus the cause when the headline ends in ':'
        lines = [l.strip() for l in str(e).splitlines() if l.strip()]
        msg = lines[0] if lines else ""
        if msg.endswith(":") and len(lines) > 1:
            msg = f"{msg} {lines[1]}"
        if e.__cause__ and str(e.__cause__) not in msg:
            msg = f"{msg} ({e.__cause__})"
        if not result.reachable:
            result.error = f"{type(e).__name__}: {msg}"[:300]
        else:
            # Logged in fine but something mid-check broke; don't guess internet state.
            result.internet_ok = None
            result.error = f"check incomplete: {type(e).__name__}: {msg}"[:300]
        log.debug("%s: check error", device.name, exc_info=True)
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
    return result
