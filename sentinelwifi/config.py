"""SentinelWiFi — user configuration (~/.sentinelwifi/config.json).

For auditing networks you own or are authorized to test.

All settings are local. Sensible defaults ship with the tool; users override
by editing the JSON file or passing CLI flags.
"""

from __future__ import annotations

import json
import os
import re
import tempfile

from .lan_scan import DATA_DIR

CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

DEFAULTS: dict = {
    "watch_interval": 60,        # seconds between watch-mode sweeps
    "port_scan_timeout": 0.5,    # TCP connect timeout for service scan
    "port_scan_enabled": True,   # set False to skip the services section
    "notify": False,             # desktop notifications in watch mode
    "trusted_bssids": [],        # your own APs' BSSIDs (lowers evil-twin noise)
    "preferred_iface": "",       # force an interface name
}

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def _valid_value(key: str, value: object) -> bool:
    """Reject malformed user settings instead of letting them fail at runtime."""
    if key == "watch_interval":
        return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 3600
    if key == "port_scan_timeout":
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and 0 < value <= 10)
    if key in ("port_scan_enabled", "notify"):
        return isinstance(value, bool)
    if key == "trusted_bssids":
        return (isinstance(value, list)
                and all(isinstance(item, str) and _MAC_RE.fullmatch(item)
                        for item in value))
    if key == "preferred_iface":
        return isinstance(value, str) and len(value) < 16 and "\0" not in value
    return False


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE) as f:
            user = json.load(f)
        if isinstance(user, dict):
            cfg.update({k: v for k, v in user.items() if k in DEFAULTS and _valid_value(k, v)})
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    # env override for CI/headless
    if os.environ.get("SENTINELWIFI_NO_NOTIFY"):
        cfg["notify"] = False
    return cfg


def save_config(cfg: dict) -> None:
    directory = os.path.dirname(CONFIG_FILE) or "."
    os.makedirs(directory, exist_ok=True)
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in cfg.items() if k in DEFAULTS and _valid_value(k, v)})

    # A unique same-directory temp file avoids collisions between concurrent
    # writers; fsync before replace so readers never see a partial JSON file.
    fd, tmp = tempfile.mkstemp(prefix=".sentinelwifi-config-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CONFIG_FILE)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
