import requests
import subprocess
import os
import sys

GITHUB_REPO = "https://api.github.com/repos/USERNAME/attack-surface/releases/latest"

def check_for_update(current_version):
    try:
        r = requests.get(GITHUB_REPO, timeout=5)
        if r.status_code != 200:
            return None

        latest = r.json()["tag_name"].lstrip("v")

        if latest != current_version:
            return latest

    except Exception:
        pass

    return None


def apply_update():
    print("[*] Updating tool...")
    try:
        subprocess.check_call(
            ["git", "pull"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print("[✓] Update completed. Restart the tool.")
        sys.exit(0)
    except Exception:
        print("[!] Update failed. Please update manually.")
