#!/bin/bash
# build-deb.sh — build the Kali/Debian .deb for attack-surface.
# Uses the pure-python builder (build_deb.py) so it works on Kali, Debian,
# Arch and any box with python3 — no dpkg-dev required to BUILD.
set -euo pipefail
cd "$(dirname "$0")"
python3 build_deb.py
