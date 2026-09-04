"""
core/term.py
============
ANSI terminal helpers - Kali-style colored CLI output.
Zero dependencies; respects NO_COLOR and non-TTY stdout.
"""
from __future__ import annotations

import os
import sys

_ENABLED = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

_RESET = "\033[0m"
_BOLD = "\033[1m"
_COLOR_MAP = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "white": "\033[37m", "gray": "\033[90m",
}


def _paint(text: str, code: str, bold: bool = False) -> str:
    if not _ENABLED:
        return text
    b = _BOLD if bold else ""
    return f"{b}{code}{text}{_RESET}"


def banner(version: str) -> str:
    art = r"""
    ___                         ___ _  _   _
   / _ | __ _ _ __  ___ _ _   / __| || | /_\  __ ___ _
  / _ | / _` | '  \/ -_) '_| | (__| __ |/ _  \/ _/ _` |
 /_/ |_\__,_|_|_|_\___|_|    \___|_||_/_/ \_\__\__,_|
"""
    if not _ENABLED:
        return art + f" Attack Surface Scanner {version}\n"
    return _paint(art, _COLOR_MAP["green"], bold=True) + \
        _paint(f" {version} - blue-team recon & monitoring", _COLOR_MAP["gray"]) + "\n"


def ok(msg: str) -> str:
    return _paint("[OK]", _COLOR_MAP["green"], True) + " " + msg


def warn(msg: str) -> str:
    return _paint("[!!]", _COLOR_MAP["yellow"], True) + " " + msg


def crit(msg: str) -> str:
    return _paint("[XX]", _COLOR_MAP["red"], True) + " " + _paint(msg, _COLOR_MAP["red"], True)


def info(msg: str) -> str:
    return _paint("[**]", _COLOR_MAP["blue"], True) + " " + msg


def finding(severity: str, msg: str) -> str:
    color = {"critical": "red", "high": "red", "medium": "yellow",
             "low": "cyan", "info": "gray"}.get(severity.lower(), "white")
    tag = _paint(f"[{severity.upper():8}]", _COLOR_MAP[color], True)
    return f"{tag} {msg}"


def risk_bar(score: float, max_score: float = 100.0, width: int = 24) -> str:
    filled = int(round(width * min(score, max_score) / max_score))
    bar = "|" * filled + "." * (width - filled)
    if not _ENABLED:
        return f"{bar} {score:.0f}"
    color = "green" if score < 25 else "yellow" if score < 50 else "red"
    return _paint(bar, _COLOR_MAP[color]) + _paint(f" {score:.0f}", _COLOR_MAP[color], True)
