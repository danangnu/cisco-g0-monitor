"""Persist per-device state and an event log under state_dir."""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone


class StateStore:
    def __init__(self, state_dir: str):
        self.dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.state_path = os.path.join(state_dir, "state.json")
        self.events_path = os.path.join(state_dir, "events.jsonl")
        self.heartbeat_path = os.path.join(state_dir, "heartbeat")

    def load(self) -> dict:
        try:
            with open(self.state_path, encoding="utf-8") as f:
                return json.load(f).get("devices", {})
        except FileNotFoundError:
            return {}

    def save(self, devices: dict) -> None:
        payload = {"updated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "devices": devices}
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".state-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp, self.state_path)  # atomic: never leaves a half-written state file

    def append_events(self, events: list) -> None:
        if not events:
            return
        with open(self.events_path, "a", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e.to_dict()) + "\n")

    def heartbeat(self) -> None:
        with open(self.heartbeat_path, "w", encoding="utf-8") as f:
            f.write(datetime.now(timezone.utc).isoformat(timespec="seconds"))
