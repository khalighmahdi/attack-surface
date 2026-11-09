"""PDF report generator — executive-grade English report.

Pure stdlib (no deps): minimal but *valid* PDF 1.4 writer.
Object layout (sequential, xref-correct):
  1 = Catalog
  2 = Pages tree
  3,4 = (page1, stream1) ... 2 objs per page
  then font F1 (Helvetica), font F2 (Helvetica-Bold)
Content streams reference /F1 /F2 — defined in each page's /Resources.
"""
from __future__ import annotations

import re
from datetime import datetime

_SEV_COLORS = {
    "critical": "0.75 0.10 0.10",
    "high": "0.85 0.35 0.10",
    "medium": "0.80 0.60 0.05",
    "low": "0.15 0.45 0.70",
    "info": "0.30 0.30 0.30",
}

# "(critical)" / "(high)" … suffix in plain-string findings
_SEV_IN_TEXT = re.compile(r"\((critical|high|medium|low|info)\)\s*$", re.IGNORECASE)


def _wrap(text: str, width: int = 95) -> list[str]:
    out = []
    for para in str(text).splitlines() or [""]:
        line = ""
        for word in para.split():
            if len(line) + len(word) + 1 > width:
                out.append(line)
                line = word
            else:
                line = (line + " " + word).strip()
        out.append(line)
    return out or [""]


def _pdf_escape(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def build_pdf(results: dict, domain: str, out_path: str) -> str:
    """Produce a clean, one-column PDF. Handles dict AND plain-string findings."""
    risk = results.get("risk") or {}
    score = risk.get("overall_score", 0)
    level = risk.get("overall_level", "Low")
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines: list[tuple[str, str]] = []  # (style, text)
    lines.append(("title", "Attack Surface Report"))
    lines.append(("sub", f"Domain: {domain}    Date: {now}"))
    lines.append(("rule", ""))
    lines.append(("h2", "Executive Summary"))
    lines.append(("body", f"Overall risk: {level} ({score}/100)."))

    findings = results.get("findings") or {}
    # Normalize: string findings -> (title=str, sev parsed from "(sev)" suffix)
    norm: dict[str, list[tuple[str, str, str]]] = {}  # host -> [(sev, title, detail)]
    for host, flist in findings.items():
        for f in flist or []:
            if isinstance(f, dict):
                sev = (f.get("severity") or "info").lower()
                title = f.get("title") or "Finding"
                detail = f.get("detail") or f.get("description") or ""
            else:
                m = _SEV_IN_TEXT.search(str(f))
                sev = m.group(1).lower() if m else "info"
                title = _SEV_IN_TEXT.sub("", str(f)).strip() or str(f)
                detail = ""
            norm.setdefault(host, []).append((sev, title, detail))

    sev_count: dict[str, int] = {}
    for flist in norm.values():
        for sev, _, _ in flist:
            sev_count[sev] = sev_count.get(sev, 0) + 1
    if sev_count:
        parts = [f"{k.title()}: {v}" for k, v in sorted(sev_count.items())]
        lines.append(("body", "Findings — " + ", ".join(parts)))
    else:
        lines.append(("body", "No findings recorded in this scan."))

    lines.append(("h2", "Findings Detail"))
    if not norm:
        lines.append(("body", "-"))
    for host, flist in norm.items():
        for sev, title, detail in flist:
            lines.append(("h3", f"[{sev.upper()}] {host} — {title}", sev))
            for ln in _wrap(detail, 92):
                lines.append(("body", ln))

    lines.append(("h2", "Discovered Hosts"))
    hosts = results.get("hosts") or []
    if hosts:
        for h in hosts:
            lines.append(("body",
                          f"{h.get('host')}   IP={h.get('ip') or '-'}   proto={h.get('protocol') or '-'}"))
    else:
        lines.append(("body", "No live hosts confirmed in this scan."))

    lines.append(("h2", "Subdomains"))
    subs = results.get("subdomains") or []
    if subs:
        # 2 columns of subdomains per line to save space
        row = []
        for s in subs[:120]:
            row.append(s)
            if len(row) == 2:
                lines.append(("body", f"  {row[0]:<45} {row[1]}"))
                row = []
        if row:
            lines.append(("body", f"  {row[0]}"))
        lines.append(("body", f"Total: {len(subs)}"))
    else:
        lines.append(("body", "-"))

    return _write_pdf(lines, out_path)


def _write_pdf(lines, out_path: str) -> str:
    styles = {
        "title": ("F2", 20, 40, "0.10 0.15 0.30"),
        "sub":   ("F1", 11, 22, "0.35 0.35 0.35"),
        "rule":  (None, 0, 14, None),          # horizontal rule
        "h2":    ("F2", 14, 30, "0.10 0.25 0.45"),
        "h3":    ("F2", 10.5, 18, None),       # color set per severity
        "body":  ("F1", 10, 14, "0.10 0.10 0.10"),
    }

    pages: list[list[str]] = []
    cur: list[str] = []
    y = 790.0

    def emit(op: str) -> None:
        nonlocal y
        if y < 50:
            pages.append(cur)
            cur.clear()
            y = 790.0
        cur.append(op)
        y -= 1  # placeholder, real decrement below

    # simpler: manual loop
    pages, cur, y = [], [], 790.0

    def newpage() -> None:
        nonlocal cur, y
        pages.append(cur)
        cur, y = [], 790.0

    for item in lines:
        st, text = item[0], item[1]
        sev = item[2] if len(item) > 2 else None
        fnt, size, lead, color = styles[st]

        wrapped = [text] if st in ("title", "sub", "h2", "rule") or not text else _wrap(text, 96)
        for ln in wrapped:
            if y < 50:
                newpage()
            if st == "rule":
                cur.append(f"0.70 0.70 0.70 RG 1 w 50 {y:.1f} m 545 {y:.1f} l S")
                y -= lead
                continue
            col = color or _SEV_COLORS.get(sev or "info", "0.10 0.10 0.10")
            safe = _pdf_escape(ln).encode("latin-1", "replace").decode("latin-1")
            cur.append(
                f"BT {col} rg /{fnt} {size} Tf 1 0 0 1 50 {y:.1f} Tm ({safe}) Tj ET"
            )
            y -= lead
    pages.append(cur)

    npages = max(len(pages), 1)
    total_objs = 4 + npages * 2  # catalog(1) + pages(2) + (page+stream)*n + font + font = 2 + 2n + 2
    fonts_start = 3 + npages * 2  # first font obj number; fonts occupy fonts_start, fonts_start+1
    # last obj = fonts_start+1 ; total must equal that
    assert fonts_start + 1 == total_objs

    out = bytearray()
    out += b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets: list[int] = [0]

    def add_obj(num: int, body: bytes) -> None:
        offsets.append(len(out))
        out.extend(f"{num} 0 obj\n".encode())
        out.extend(body)
        out.extend(b"\nendobj\n")

    add_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{3 + i*2} 0 R" for i in range(npages))
    add_obj(2, f"<< /Type /Pages /Kids [{kids}] /Count {npages} >>".encode())
    for i, page_lines in enumerate(pages):
        pid = 3 + i * 2
        sid = 4 + i * 2
        add_obj(pid, (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Contents {sid} 0 R /Resources << /Font << /F1 {fonts_start} 0 R "
            f"/F2 {fonts_start+1} 0 R >> >> >>"
        ).encode())
        data = "\n".join(page_lines).encode("latin-1", "replace")
        add_obj(sid, f"<< /Length {len(data)} >>\nstream\n".encode() + data + b"\nendstream")
    add_obj(fonts_start, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    add_obj(fonts_start + 1, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

    xref_pos = len(out)
    out += f"xref\n0 {total_objs + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {total_objs + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    ).encode()

    with open(out_path, "wb") as f:
        f.write(bytes(out))
    return out_path
