"""User configuration and preferences persistence manager for HFS-Sentry Suite.

Zero external dependencies (Python 3 standard library only).
Saves and loads preferences to a local JSON file.
"""

import json
import os
from typing import Any, Dict

CONFIG_FILE = "sentry_config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "default_duration_seconds": 30.0,
    "default_timeout_seconds": 3.0,
    "sound_alerts_enabled": True,
    "theme": "dark",
    "last_target_host": "google.com",
    "last_target_subnet": "192.168.1.0/24",
    "ssh_failure_threshold": 5,
}


def load_config() -> Dict[str, Any]:
    """Load configuration from file or return defaults."""
    if not os.path.isfile(CONFIG_FILE):
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
            merged = dict(DEFAULT_CONFIG)
            merged.update(user_cfg)
            return merged
    except Exception:
        return dict(DEFAULT_CONFIG)


def save_config(config: Dict[str, Any]) -> bool:
    """Save configuration dictionary to local JSON file."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False


def get_config_val(key: str, default: Any = None) -> Any:
    """Retrieve single configuration value."""
    cfg = load_config()
    return cfg.get(key, default)


def set_config_val(key: str, val: Any) -> bool:
    """Update and persist a single configuration value."""
    cfg = load_config()
    cfg[key] = val
    return save_config(cfg)
