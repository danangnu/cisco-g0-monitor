"""Parsers for Cisco IOS / IOS-XE command output."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional


class ParseError(Exception):
    pass


@dataclass
class InterfaceInfo:
    name: str
    status: str            # up | down | administratively down
    protocol: str          # up | down
    ip: Optional[str]      # e.g. "203.0.113.5/29"
    network: Optional[str] # e.g. "203.0.113.0/29"
    method: Optional[str]  # dhcp | static | negotiated | unnumbered | None

    @property
    def is_up(self) -> bool:
        return self.status == "up" and self.protocol == "up"


_STATUS_RE = re.compile(
    r"^(?P<intf>\S+) is (?P<status>administratively down|up|down)[^,\n]*,\s*"
    r"line protocol is (?P<proto>up|down)",
    re.M,
)
_ADDR_RE = re.compile(r"Internet address is (?P<addr>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})")
_ADDR_MASK_RE = re.compile(
    r"Internet address is (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) (?P<mask>\d{1,3}(?:\.\d{1,3}){3})"
)
_SUCCESS_RE = re.compile(r"Success rate is (?P<pct>\d+) percent \((?P<ok>\d+)/(?P<total>\d+)\)")
_CLI_ERROR_RE = re.compile(r"^%\s*(Invalid|Incomplete|Ambiguous|Unrecognized)", re.M | re.I)


def parse_show_ip_interface(output: str) -> InterfaceInfo:
    """Parse `show ip interface <intf>`."""
    if _CLI_ERROR_RE.search(output):
        raise ParseError(f"Device rejected command: {output.strip().splitlines()[-1]}")

    m = _STATUS_RE.search(output)
    if not m:
        raise ParseError("Could not find interface status line")

    ip = network = method = None
    a = _ADDR_RE.search(output)
    if a:
        iface = ipaddress.ip_interface(a.group("addr"))
    else:
        a = _ADDR_MASK_RE.search(output)
        iface = ipaddress.ip_interface(f"{a.group('ip')}/{a.group('mask')}") if a else None

    if iface is not None:
        ip = str(iface)
        network = str(iface.network)
        if "determined by DHCP" in output:
            method = "dhcp"
        elif "determined by IPCP" in output or "negotiated" in output.lower():
            method = "negotiated"
        else:
            method = "static"
    elif "unnumbered" in output.lower():
        method = "unnumbered"

    return InterfaceInfo(
        name=m.group("intf"),
        status=m.group("status"),
        protocol=m.group("proto"),
        ip=ip,
        network=network,
        method=method,
    )


def parse_ping(output: str) -> int:
    """Return ping success percentage (0-100) from IOS ping output."""
    m = _SUCCESS_RE.search(output)
    if m:
        return int(m.group("pct"))
    # e.g. "% Invalid source address- IP address not on this router" / unresolved host
    if _CLI_ERROR_RE.search(output) or output.strip().startswith("%"):
        return 0
    raise ParseError("Could not find ping success rate")
