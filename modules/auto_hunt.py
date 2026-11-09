"""auto_hunt.py — Auto-Hunt / Exploit Hand-off module.

When the scanner finds a vulnerability, map it to the specialized
attack/verification tool for that bug class and either:
  - generate an operator "hunt plan" (markdown + tool-ready files), or
  - auto-run only SAFE (non-destructive) verification actions.

Design rules (Kali-professional):
  * Plan-first: --hunt-plan always available; nothing fires without it.
  * Safe-only automation: --auto-hunt executes SAFE class only
    (nuclei safe templates, testssl, dig, http probes). Active tools
    (sqlmap, hydra, git-dumper...) are PLAN-ONLY — human fires them.
  * Scope enforced: every target passes through core.scope.ScopeFilter.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

# ---------------------------------------------------------------- actions

@dataclass
class HuntAction:
    tool: str            # binary name
    cmd: str             # full command line for the operator
    safe: bool           # True = non-destructive, can auto-run
    finding: str         # originating finding text
    host: str
    category: str = ""   # sqli / xss / takeover / tls / creds / ...

    def __str__(self) -> str:  # markdown line
        tag = "SAFE" if self.safe else "ACTIVE"
        return f"- [{tag}] `{self.cmd}`  ← _{self.finding[:80]}_"


# pattern → (tool builder, safe?, category)
_PATTERNS: list[tuple[str, str, object, bool, str]] = [
    # (regex on finding text, category, cmd-template fn, safe, tool)
    (r"sql\s*inj|sqli|sqlmap", "sqli", lambda u: f"sqlmap -u '{u}' --batch --level=2 --risk=2", False, "sqlmap"),
    (r"xss|reflected.*script|dalfox", "xss", lambda u: f"dalfox url '{u}'", False, "dalfox"),
    (r"takeover", "takeover", lambda u: f"subzy run --hide_fails --targets '{u}'", True, "subzy"),
    (r"admin\s*panel|/admin|adminer|administrator", "admin-exposure", lambda u: f"nuclei -target '{u}' -t exposures/configs/ -severity medium,high,critical", True, "nuclei"),
    (r"\.git\b|git\s*expos", "git-exposure", lambda u: f"git-dumper '{u}/.git' ./dump_{re.sub(r'[^a-z0-9]', '_', u.lower())}", False, "git-dumper"),
    (r"email\s*spoof|spf|dmarc|dkim", "email-spoof", lambda d: f"dig +short TXT {d} | grep -iE 'spf|dmarc'", True, "dig"),
    (r"hsts|csp|security\s*headers|x-frame", "headers", lambda u: f"curl -sIk '{u}' | grep -iE 'strict-transport|content-security|x-frame'", True, "curl"),
    (r"tls|ssl|certificat|https?", "tls", lambda h: f"testssl.sh --quiet {h}", True, "testssl"),
    (r"open\s*port|exposed\s*port|rce|redis|telnet|ftp", "ports", lambda h: f"nmap -sV --top-ports 100 {h}", False, "nmap"),
    (r"default\s*cred|weak\s*pass|brute", "creds", lambda u: f"hydra -L users.txt -P rock.txt '{u}' http-post-form", False, "hydra"),
    (r"directory\s*list|dir\s*list|index\s*of", "listing", lambda u: f"nuclei -target '{u}' -t http/exposures/ -silent", True, "nuclei"),

    # ---- expanded hunter toolkit (safe-by-default templates) ----
    (r"tech\s*fingerprint|technolog|wordpress|wp|joomla|drupal", "fingerprint",
     lambda u: f"whatweb --no-errors --color=never '{u}'", True, "whatweb"),
    (r"hsts|csp|x-frame|security\s*headers", "waf-fingerprint",
     lambda u: f"wafw00f '{u}'", True, "wafw00f"),
    (r"path|admin|login|api", "content-discovery",
     lambda u: f"ffuf -u '{u}/FUZZ' -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 40", False, "ffuf"),
    (r"xss|reflected", "xss-dalfox",
     lambda u: f"dalfox url '{u}' --silence --output-format json", False, "dalfox"),
    (r"takeover|github pages|s3|azure.*pages", "takeover",
     lambda u: f"subzy run --hide_fails --targets '{u}'", True, "subzy"),
    (r"sql|sqli", "sqli-sqlmap",
     lambda u: f"sqlmap -u '{u}' --batch --level=1 --risk=1 --random-agent", False, "sqlmap"),
    (r"ssl|tls|cipher|certificate", "tls-testssl",
     lambda h: f"testssl.sh --quiet --sneaky {h}", True, "testssl"),
    (r"email.*spoof|spf|dmarc", "email-spoof",
     lambda d: f"dig +short TXT {d} | grep -iE 'spf|dmarc'", True, "dig"),
]


def _normalize_url(host: str) -> str:
    return host if host.startswith("http") else f"https://{host}"


def map_findings(findings: dict, domain: str, scope) -> list[HuntAction]:
    """Convert scan findings → HuntActions. Every host passes ScopeFilter."""
    actions: list[HuntAction] = []
    seen: set[tuple[str, str]] = set()
    for host, flist in (findings or {}).items():
        if not scope.in_scope(host):
            continue  # out of scope → never hand off
        for f in flist or []:
            text = f if isinstance(f, str) else (f.get("title") or str(f))
            for pat, cat, tmpl, safe, tool in _PATTERNS:
                if re.search(pat, text, re.IGNORECASE):
                    key = (host, cat)
                    if key in seen:
                        continue
                    seen.add(key)
                    target = host if cat in ("ports", "tls") else _normalize_url(host)
                    cmd = tmpl(target) if cat not in ("email-spoof",) else tmpl(host)
                    actions.append(HuntAction(tool=tool, cmd=cmd, safe=safe,
                                              finding=text, host=host, category=cat))
                    break
    # domain-level fallback: nothing matched at all → generic recon
    if not actions:
        actions.append(HuntAction(
            tool="nuclei",
            cmd=f"nuclei -l hunt_targets_{domain}.txt -severity low,medium,high,critical -silent",
            safe=True, finding="generic sweep (no specific class matched)",
            host=domain, category="generic"))
    return actions


# ---------------------------------------------------------------- exports

def write_hunt_plan(actions: list[HuntAction], domain: str, out_md: str) -> str:
    safe_a = [a for a in actions if a.safe]
    act_a = [a for a in actions if not a.safe]
    lines = [
        f"# 🎯 Hunt Plan — {domain}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  "
        f"{len(safe_a)} safe / {len(act_a)} active actions",
        "",
        "## ⚡ Safe (auto-runnable, non-destructive)",
    ]
    lines += [str(a) for a in safe_a] or ["- (none)"]
    lines += ["", "## 🔥 Active (PLAN-ONLY — operator decides)"]
    lines += [str(a) for a in act_a] or ["- (none)"]
    lines += ["",
              "## ⚠️ Rules",
              "- Active tools fire ONLY with explicit operator consent.",
              "- All targets must remain in-scope (ScopeFilter enforced).",
              "- Stop immediately if authorization is unclear."]
    with open(out_md, "w") as fh:
        fh.write("\n".join(lines))
    return out_md


def write_nuclei_targets(subdomains: list[str], out_txt: str) -> str:
    with open(out_txt, "w") as fh:
        for s in subdomains or []:
            fh.write((s if s.startswith("http") else f"https://{s}") + "\n")
    return out_txt


def write_msf_rc(actions: list[HuntAction], out_rc: str) -> str:
    """Metasploit resource script scaffold for active hand-off (commented)."""
    lines = ["# Auto-generated MSF resource script — review before use",
             "# setg RHOSTS <target>", ""]
    for a in actions:
        if a.category == "ports":
            lines.append(f"# from: {a.finding[:60]}")
            lines.append("# use auxiliary/scanner/portscan/tcp")
            lines.append("# run; ")
            lines.append("")
    with open(out_rc, "w") as fh:
        fh.write("\n".join(lines))
    return out_rc


def run_safe(actions: list[HuntAction], timeout: int = 120) -> list[dict]:
    """Execute ONLY safe actions; returns structured results. Never raises."""
    import subprocess
    results = []
    for a in actions:
        if not a.safe:
            continue
        try:
            p = subprocess.run(a.cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
            results.append({"tool": a.tool, "cmd": a.cmd, "category": a.category,
                            "rc": p.returncode,
                            "output": (p.stdout + p.stderr)[-2000:]})
        except Exception as e:
            results.append({"tool": a.tool, "cmd": a.cmd, "category": a.category,
                            "rc": -1, "output": f"error: {e}"})
    return results
