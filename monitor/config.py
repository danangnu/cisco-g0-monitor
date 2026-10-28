"""Load settings.yaml and devices.yaml, expanding ${ENV_VAR} / ${ENV_VAR:-default}."""
from __future__ import annotations

import copy
import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

_ENV_RE = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}")

DEFAULT_SETTINGS: dict[str, Any] = {
    "interval_seconds": 300,
    "max_workers": 10,
    "ssh_timeout": 20,
    "state_dir": "/data",
    "log_level": "INFO",
    "ping": {"count": 5, "timeout": 2, "min_success_percent": 60},
    "thresholds": {"failure": 2, "recovery": 2},
    "alerts": {
        "on_ip_change_same_subnet": False,
        "on_device_unreachable": True,
        "send_recovery": True,
        "repeat_every_minutes": 60,
    },
    "ai": {
        "enabled": False,
        "api_key": "",                       # or ANTHROPIC_API_KEY in the environment
        "model": "claude-sonnet-5-5",
        "max_tokens": 1500,
        "timeout_seconds": 90,
        "max_per_hour": 6,                   # hard cap on API calls; alerts still go out without diagnosis
        "diagnose_reminders": False,         # also diagnose hourly STILL_DOWN reminders
        "collect_timeout_seconds": 120,
    },
    "notify": {
        "trackit": {"enabled": False, "db_host": "", "db_port": 3306, "db_user": "", "db_password": "",
                    "db_name": "trackitlive", "to": [], "from": "", "from_name": "Cisco G0/0 Monitor",
                    "priority": 1},
        "email": {"enabled": False, "host": "", "port": 587, "security": "starttls",
                  "username": "", "password": "", "from": "", "to": []},
        "teams": {"enabled": False, "webhook_url": ""},
        "slack": {"enabled": False, "webhook_url": ""},
    },
}

DEVICE_DEFAULTS: dict[str, Any] = {
    "device_type": "cisco_ios",
    "port": 22,
    "username": "",
    "password": "",
    "secret": "",
    "interface": "GigabitEthernet0/0",
    "vrf": None,
    "ping_targets": ["8.8.8.8", "1.1.1.1"],
    "expected_subnet": None,
    "enabled": True,
}

SUPPORTED_TYPES = {"cisco_ios", "cisco_xe"}


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            return os.environ.get(m.group("name"), m.group("default") or "")
        return _ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class Device:
    name: str
    host: str
    device_type: str
    port: int
    username: str
    password: str
    secret: str
    interface: str
    vrf: Optional[str]
    ping_targets: list[str] = field(default_factory=list)
    expected_subnet: Optional[str] = None
    enabled: bool = True


def load_settings(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    settings = _deep_merge(DEFAULT_SETTINGS, _expand(raw))
    for channel in ("email", "trackit"):
        to = settings["notify"][channel].get("to") or []
        if isinstance(to, str):
            settings["notify"][channel]["to"] = [a.strip() for a in to.split(",") if a.strip()]
    return settings


def load_devices(path: str) -> list[Device]:
    with open(path, encoding="utf-8") as f:
        raw = _expand(yaml.safe_load(f) or {})
    defaults = {**DEVICE_DEFAULTS, **(raw.get("defaults") or {})}
    devices: list[Device] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw.get("devices") or []):
        d = {**defaults, **entry}
        if not d.get("host"):
            raise ValueError(f"devices[{i}] is missing 'host'")
        d.setdefault("name", d["host"])
        d["name"] = str(d.get("name") or d["host"])
        if d["name"] in seen:
            raise ValueError(f"Duplicate device name: {d['name']}")
        seen.add(d["name"])
        if d["device_type"] not in SUPPORTED_TYPES:
            raise ValueError(f"{d['name']}: device_type must be one of {sorted(SUPPORTED_TYPES)}")
        if d.get("expected_subnet"):
            d["expected_subnet"] = str(ipaddress.ip_network(d["expected_subnet"], strict=False))
        if isinstance(d.get("ping_targets"), str):
            d["ping_targets"] = [t.strip() for t in d["ping_targets"].split(",") if t.strip()]
        d["port"] = int(d["port"])
        d["vrf"] = d.get("vrf") or None
        devices.append(Device(**{k: d[k] for k in Device.__dataclass_fields__}))
    if not devices:
        raise ValueError("No devices defined in devices file")
    return devices
