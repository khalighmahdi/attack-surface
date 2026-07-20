#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "[*] Setting up Attack Surface Scanner (Termux)"

pkg update -y
pkg install -y python git nmap

python -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Termux setup completed"
echo "[+] Run with: python attack_surface.py -d example.com"

