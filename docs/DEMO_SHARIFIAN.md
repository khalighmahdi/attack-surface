# Demo: authorized surface review for sharifianshop.com

## Read-only findings (verified)
- SPF present, DMARC missing -> email spoofing risk
- TLS grade A (TLS 1.2/1.3 only, FS yes)
- Multiple common ports exposed on shared IP (FTP/SSH/Telnet/MySQL/RDP/8080)
- HTTP security headers missing: HSTS, CSP (X-Frame-Options/X-Content-Type-Options present)
- cPanel/WHM admin endpoints publicly reachable (login forms)
- WP plugins disclosed (versions visible)

## Safe PoC (copy/paste, non-destructive)
```bash
curl -sI https://sharifianshop.com/ | grep -iE 'hsts|content-security'
curl -s -o /dev/null -w "%{http_code}\\n" https://sharifianshop.com/wp-content/debug.log
testssl.sh sharifianshop.com 2>&1 | tail
nmap -sV -p 21,22,23,25,80,110,443,3306,3389,8080 sharifianshop.com
```

## Remediation
- Restrict DB/RDP/FTP/SSH to VPN/internal.
- Add DMARC (_dmarc.sharifianshop.com) + harden SPF/ DKIM alignment.
- Add HSTS + CSP; keep XFO/XCTO/Referrer.
- Remove or protect debug.log; disable plugin listing if not needed.
