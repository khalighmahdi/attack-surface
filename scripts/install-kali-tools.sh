#!/usr/bin/env bash
# Optional helper for Kali/Debian boxes.
set -e
sudo apt-get update
sudo apt-get install -y nmap hydra sqlmap wpscan nikto testssl.sh tmux wordlists
# ProjectDiscovery tools (best-effort, optional):
if ! command -v httpx >/dev/null 2>&1; then
  echo "httpx (ProjectDiscovery) not installed; install manually if desired"
fi
