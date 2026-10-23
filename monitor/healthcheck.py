"""Docker HEALTHCHECK: healthy if a monitoring cycle finished recently."""
import os
import sys
import time

from .config import load_settings

settings = load_settings(os.environ.get("SETTINGS_PATH", "/config/settings.yaml"))
interval = int(settings["interval_seconds"])
heartbeat = os.path.join(settings["state_dir"], "heartbeat")
# Allow up to 3 intervals (+2 min for slow SSH) before declaring the monitor stuck.
limit = interval * 3 + 120
try:
    age = time.time() - os.path.getmtime(heartbeat)
except FileNotFoundError:
    age = time.time() - os.path.getmtime("/proc/1")  # no cycle yet: measure from container start
sys.exit(0 if age < limit else 1)
