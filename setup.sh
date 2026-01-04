#!/bin/bash

set -e

echo "======================================"
echo " Attack Surface Scanner - Setup Script"
echo "======================================"

# Root check (required for nmap -sS)
if [[ $EUID -ne 0 ]]; then
   echo "[!] Please run setup as root (sudo ./setup.sh)"
   exit 1
fi

echo "[*] Updating package list..."
apt update -y

echo "[*] Installing system dependencies..."
apt install -y \
    python3 \
    python3-pip \
    nmap \
    git

echo "[*] Installing python dependencies..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

echo "[✓] Setup completed successfully"
echo
echo "Usage:"
echo "  sudo python3 -m scanner -d example.com"

