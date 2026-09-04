"""
core/config.py
===============
YAML/JSON configuration file support.

Search order (first found wins):
  1. --config <file>
  2. $ATTACK_SURFACE_CONFIG
  3. ~/.config/attack-surface/config.yaml (or .json)

CLI flags still override the config file.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict

logger = logging.getLogger("AttackSurface.Config")

DEFAULT_PATHS = [
    os.path.expanduser("~/.config/attack-surface/config.yaml"),
    os.path.expanduser("~/.config/attack-surface/config.json"),
]


def _load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        out: Dict[str, Any] = {}
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip().strip("'\"")
                if v.lower() in ("true", "false"):
                    out[k] = v.lower() == "true"
                elif v.isdigit():
                    out[k] = int(v)
                else:
                    out[k] = v
        return out
    except Exception as e:
        logger.warning("config parse failed: %s", e)
        return {}


def _load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("config parse failed: %s", e)
        return {}


def load_config(explicit: str | None = None) -> Dict[str, Any]:
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("ATTACK_SURFACE_CONFIG")
    if env:
        candidates.append(env)
    candidates.extend(DEFAULT_PATHS)
    for path in candidates:
        if path and os.path.isfile(path):
            data = (_load_json(path) if path.endswith(".json")
                    else _load_yaml(path))
            if data:
                logger.info("config loaded: %s (%d keys)", path, len(data))
                return data
    return {}


def apply_to_args(args, config: Dict[str, Any]) -> None:
    """Apply config values to argparse namespace - CLI flags win."""
    for key, value in config.items():
        norm = key.lstrip("-").lower().replace("_", "-")
        attr = norm.replace("-", "_")
        current = getattr(args, attr, None)
        if isinstance(current, bool):
            provided = current is True
        else:
            provided = current is not None
        if not provided and value is not None:
            setattr(args, attr, value)
