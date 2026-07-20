import ssl
import socket
import hashlib


def backend_fingerprint(origin_ip: str, host: str, timeout: int = 5):
    port = 443

    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])

    result = {
        "type": "backend_fingerprint",
        "origin_ip": origin_ip,
        "host": host,
        "tls": {},
        "http": {}
    }

    try:
        raw_sock = socket.create_connection((origin_ip, port), timeout=timeout)
        sock = context.wrap_socket(raw_sock, server_hostname=host)

        # -------- TLS Fingerprint --------
        result["tls"] = {
            "version": sock.version(),
            "cipher": sock.cipher()[0] if sock.cipher() else None,
            "alpn": sock.selected_alpn_protocol(),
            "peer_cert": "present" if sock.getpeercert() else "none",
        }

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: backend-fp/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        sock.sendall(request.encode())

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()

        header_blob, body = response.split(b"\r\n\r\n", 1)
        headers_text = header_blob.decode(errors="ignore")

        headers = {}
        for line in headers_text.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        result["http"] = {
            "status_code": headers_text.split("\r\n")[0],
            "headers": headers,
            "body_length": len(body),
            "body_hash": hashlib.sha256(body).hexdigest(),
            "body_sample": body[:160].decode(errors="ignore"),
        }

    except Exception as e:
        result["error"] = str(e)

    return result


def fingerprint_backend(origin_ip: str, host: str):
    """
    Public API expected by attack_surface.py
    """
    return backend_fingerprint(origin_ip, host)

