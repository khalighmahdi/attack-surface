# modules/risk_scoring.py

import logging

try:
    from core.stream import ndjson_emit
except Exception:
    ndjson_emit = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# ==========================================================
# Calibrated risk weights (aligned with v0.2.0)
# ==========================================================
FINDING_WEIGHTS = {
    "MISSING_HSTS": 6,
    "MISSING_CSP": 6,
    "MISSING_X_FRAME_OPTIONS": 4,
    "MISSING_X_CONTENT_TYPE_OPTIONS": 4,
    "MISSING_REFERRER_POLICY": 3,
    "ADMIN_PANEL_EXPOSED": 12,
    "SETUP_PAGE_EXPOSED": 30,   # half-installed CMS = site takeover
}

SEVERITY_MULTIPLIER = {
    "info": 0.5,
    "low": 0.8,
    "medium": 1.0,
    "high": 1.2,
    "critical": 1.4,
}

HIGH_RISK_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# ==========================================================
def _risk_level(score: float) -> str:
    if score >= 75:
        return "Critical"
    elif score >= 40:
        return "High"
    elif score >= 20:
        return "Medium"
    return "Low"

# ==========================================================
def calculate_risk(events: list) -> dict:
    """
    Risk engine – calibrated to match v0.2.0 behavior
    while keeping modern normalized logic.
    """

    logging.info("Calculating risk scores...")

    per_domain = {}
    seen_findings = set()
    seen_admin_exposed = set()

    # ------------------------------------------------------
    # PASS 1: Normalized findings
    # ------------------------------------------------------
    for e in events:
        if not isinstance(e, dict):
            continue

        etype = e.get("type")
        domain = e.get("domain")
        severity = e.get("severity", "medium")

        if not etype or not domain:
            continue
        if etype not in FINDING_WEIGHTS:
            continue

        key = (domain, etype)
        if key in seen_findings:
            continue
        seen_findings.add(key)

        if etype == "ADMIN_PANEL_EXPOSED":
            if domain in seen_admin_exposed:
                continue
            seen_admin_exposed.add(domain)

        base = FINDING_WEIGHTS[etype]
        score = int(base * SEVERITY_MULTIPLIER.get(severity, 1.0))

        d = per_domain.setdefault(
            domain, {"score": 0, "reasons": [], "attack_types": set()}
        )

        d["score"] += score
        d["reasons"].append(f"{etype} ({severity})")
        d["attack_types"].add("misconfiguration")

    # ------------------------------------------------------
    # PASS 2: Legacy modules
    # ------------------------------------------------------
    for e in events:
        if not isinstance(e, dict):
            continue

        etype = e.get("type")
        domain = e.get("domain")
        if not etype or not domain:
            continue

        d = per_domain.setdefault(
            domain, {"score": 0, "reasons": [], "attack_types": set()}
        )

        if etype == "OPEN_PORT":
            port = e.get("port")
            if port in HIGH_RISK_PORTS:
                d["score"] += 10
                d["reasons"].append(f"High-risk service on port {port}")
                d["attack_types"].add("service_exposure")
            elif port not in (80, 443):
                d["score"] += 3
                d["reasons"].append(f"Non-standard open port {port}")
                d["attack_types"].add("non_standard_port")

        elif etype == "admin_panel":
            if not e.get("protected", True):
                if domain not in seen_admin_exposed:
                    seen_admin_exposed.add(domain)
                    d["score"] += FINDING_WEIGHTS["ADMIN_PANEL_EXPOSED"]
                    d["reasons"].append("ADMIN_PANEL_EXPOSED (unprotected)")
                    d["attack_types"].add("admin_exposure")

    # ------------------------------------------------------
    # Finalization
    # ------------------------------------------------------
    for domain, d in per_domain.items():
        if d["score"] == 0:
            d["score"] = 5
            d["reasons"].append("Baseline risk applied")

        d["score"] = min(d["score"], 100)
        d["level"] = _risk_level(d["score"])
        d["attack_types"] = sorted(d["attack_types"])

        if ndjson_emit:
            ndjson_emit(
                {
                    "type": "risk_score",
                    "domain": domain,
                    "score": d["score"],
                    "level": d["level"],
                    "reasons": d["reasons"],
                }
            )

    overall = round(
        sum(d["score"] for d in per_domain.values()) / len(per_domain)
        if per_domain else 0,
        2,
    )

    logging.info(f"Risk scoring completed. Overall score: {overall:.2f}")

    return {
        "per_domain": per_domain,
        "overall_score": overall,
        "overall_level": _risk_level(overall),
    }

