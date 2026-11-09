---
name: attack-surface
description: >
  Scan and assess a domain or website attack surface for its owner or with written authorization.
  Use when the user asks to scan a domain, audit website security, map attack surface,
  run subdomain/port/admin scans, view the bug dashboard, or run a full scan.
metadata:
  version: "1.0"
  tool: "attack-surface"
  opencode/autoinvoke: "true"
disable-model-invocation: false
---

# Attack Surface Scanner Skill

When this skill is activated, execute the steps below **without extra questions**.

## Mandatory execution rules
1. Scan only domains the user owns or has explicit written permission to test.
2. Never run brute-force, exploits, or destructive payloads; the scan is strictly read-only.
3. Always resolve the project path first via `${ATTACK_SURFACE_HOME}`, `$(git rev-parse --show-toplevel)`, or `/opt/attack-surface`.
4. Always bring up a dashboard on `127.0.0.1:8443` after a scan and share the link.
5. If dependencies (nmap/python deps) are missing, install them with `pip` from `.venv` or use the Kali container.

## Step 1: Inspect the project
```bash
cd ${ATTACK_SURFACE_HOME:-$(git rev-parse --show-toplevel 2>/dev/null || echo /opt/attack-surface)} && git status --short && ls attack_surface.py
```

## Step 2: Run a full scan
```bash
cd ${ATTACK_SURFACE_HOME:-$(git rev-parse --show-toplevel 2>/dev/null || echo /opt/attack-surface)}
nohup .venv/bin/python attack_surface.py -d <DOMAIN> --rate 5 --max-subdomains 50 \
  --cves-deep --poc --mitre --redteam > "reports/scan_${DOMAIN}.log" 2>&1 &
echo "PID: $!"
```
Wait for completion (look for `Saved to database` / `HTML report` in the log).

## Step 3: If it hangs
- Disable critical web checks: `--no-critical-web`
- Or drop ASM/cloud phases to finish faster.

## Step 4: Open the dashboard
```bash
cd ${ATTACK_SURFACE_HOME:-$(git rev-parse --show-toplevel 2>/dev/null || echo /opt/attack-surface)}
nohup .venv/bin/python attack_surface.py serve --port 8443 --host 127.0.0.1 \
  > reports/dashboard.log 2>&1 &
sleep 2
curl -s -o /dev/null -w "HTTP %{http_code}" http://127.0.0.1:8443/
```
Then say:
`Dashboard ready: http://127.0.0.1:8443`

## Step 5: Report to the user (Markdown)
- Scan summary (alive hosts / subdomains / findings / attack paths)
- Criticals: sensitive ports, admin panels, email spoofing exposure
- Report path: `reports/report_<DOMAIN>.html`
- Next steps: fix misconfigurations, close ports 21/23/3306/3389, complete SPF/DKIM/DMARC.

## Kali container (optional)
If the user says "with Kali container":
```bash
docker run --rm --name kali-as -v ${ATTACK_SURFACE_HOME:-$(git rev-parse --show-toplevel 2>/dev/null || echo /opt/attack-surface)}:/home/attack/attack-surface \
  -v ${ATTACK_SURFACE_STATE:-$HOME/.attack_surface}:/home/attack/.attack_surface attack-surface-tools \
  sleep infinity
```
For scans inside the container, run the same commands via `docker exec kali-as`.
"""