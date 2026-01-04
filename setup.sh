#!/bin/bash

echo "======================================"
echo " Attack Surface Scanner - Kali Setup "
echo "======================================"

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo ./setup.sh)"
  exit 1
fi

echo "[*] Updating system..."
apt update

echo "[*] Installing system tools..."
apt install -y \
    python3 \
    python3-pip \
    nmap \
    git

echo "[*] Installing Python libraries via APT (Kali-safe)..."
apt install -y \
    python3-requests \
    python3-jinja2 \
    python3-urllib3

echo "[*] Verifying Python imports..."
python3 - <<EOF
import requests, jinja2, urllib3
print("All Python dependencies OK")
EOF

echo "======================================"
echo "[✓] Installation complete"
echo
echo "Run with:"
echo "  sudo python3 scanner.py --help"
echo "======================================"

