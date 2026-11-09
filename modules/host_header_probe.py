import ssl
import socket
import hashlib
from typing import Dict

TIMEOUT = 5


def _simple_request(ip: str, host: str, use_https: bool = True, timeout: int = TIMEOUT) -> Dict:
    """
    Low-level HTTP/HTTPS request with custom Host header
    """
    port = 443 if use_https else 80
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: origin-probe/0.1\r\n"
        f"Connection: close\r\n\r\n"
    )

    context = ssl.create_default_context() if use_https else None

    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)

        if use_https:
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        sock.sendall(request.encode())

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()

        body = response.split(b"\r\n\r\n", 1)[-1]
        body_hash = hashlib.sha256(body).hexdigest()

        return {
            "status": "ok",
            "length": len(body),
            "hash": body_hash,
            "sample": body[:200].decode(errors="ignore"),
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }


def host_header_probe(origin_ip: str, real_domain: str) -> Dict:
    """
    Detection-only Host Header probe against suspected origin IP
    """
    print(f"[+] Probing Origin IP via Host Header: {origin_ip}")

    results = {}
    hosts_to_test = {
        "real_domain": real_domain,
        "random_host": "does-not-exist.internal",
        "ip_as_host": origin_ip,
    }

    for label, host in hosts_to_test.items():
        results[label] = _simple_request(origin_ip, host)

    return {
        "type": "host_header_probe",
        "origin_ip": origin_ip,
        "real_domain": real_domain,
        "results": results,
    }


def probe_host_header(ip=None, domain=None, origin_ip=None, real_domain=None, **kwargs) -> Dict:
    """
    ✅ Public API expected by attack_surface.py
    Keyword-safe & backward-compatible wrapper
    """
    # Normalize parameter names
    final_ip = ip or origin_ip
    final_domain = domain or real_domain

    if not final_ip or not final_domain:
        return {
            "status": "error",
            "error": "Missing ip or domain for host header probe"
        }

    return host_header_probe(final_ip, final_domain)

