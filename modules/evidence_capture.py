"""Lightweight screenshot / evidence capture helper.

Uses any locally available headless browser (chromium / google-chrome /
firefox) — optional dependency, gracefully skips when none is installed.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import List

BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
            "firefox", "wkhtmltoimage")


def available() -> str | None:
    for b in BROWSERS:
        p = shutil.which(b)
        if p:
            return p
    return None


def capture(url: str, out_path: str, timeout: int = 20) -> bool:
    """Capture a screenshot of `url` to `out_path`. Returns success."""
    browser = available()
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not browser:
        return False
    bname = os.path.basename(browser)
    try:
        if "chrome" in bname or "chromium" in bname:
            subprocess.run(
                [browser, "--headless", "--disable-gpu", "--no-sandbox",
                 f"--screenshot={out}", url],
                timeout=timeout, check=True, capture_output=True,
            )
        elif "firefox" in bname:
            subprocess.run(
                [browser, "--headless", "--screenshot", str(out), url],
                timeout=timeout, check=True, capture_output=True,
            )
        return out.exists() and out.stat().st_size > 0
    except Exception:
        return False


def capture_many(urls: List[str], out_dir: str = "reports/evidence",
                 timeout: int = 20) -> List[str]:
    outd = Path(out_dir)
    outd.mkdir(parents=True, exist_ok=True)
    saved: List[str] = []
    for i, url in enumerate(urls):
        p = outd / f"shot_{i}_{hashlib.sha256(url.encode()).hexdigest()[:8]}.png"
        if capture(url, str(p), timeout=timeout):
            saved.append(str(p))
    return saved
