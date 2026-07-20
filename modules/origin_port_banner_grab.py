import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict


# List of well-known ports (used by deep scan / banner grabbing)
DEEP_SCAN_PORTS = [
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    110,    # POP3
    143,    # IMAP
    445,    # SMB
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    8080,   # HTTP Alternative
    8443,   # HTTPS Alternative
    10000,  # Webmin
    27017   # MongoDB
]


def grab_banner(ip: str, port: int) -> Dict:
    """
    Attempts to connect to a port and retrieve a banner.
    Handles plain TCP and SSL/TLS where applicable.
    """
    timeout = 3
    banner = ""
    error = None
    sock = None

    ssl_ports = [443, 8443, 993, 995, 465]
    is_ssl = port in ssl_ports

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if is_ssl:
            context = ssl.create_default_context()
            try:
                sock = context.wrap_socket(sock, server_hostname=ip)
            except ssl.SSLError:
                # Fallback to plain TCP if SSL handshake fails
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                is_ssl = False

        sock.connect((ip, port))

        # HTTP / HTTPS request
        if port in [80, 443, 8080, 8443]:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: AttackSurfaceScanner/0.4.1\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())

        # SSH sends banner immediately after connect
        data = sock.recv(1024).decode(errors="ignore").strip()

        if data:
            lines = data.split("\n")

            if port in [80, 443, 8080, 8443]:
                server_line = next(
                    (line for line in lines if line.lower().startswith("server:")),
                    None
                )
                banner = server_line.strip() if server_line else lines[0].strip()

            elif port == 22 and data.startswith("SSH-"):
                banner = lines[0].strip()

            else:
                banner = lines[0].strip()

    except socket.timeout:
        error = f"Connection to {ip}:{port} timed out"
    except ConnectionRefusedError:
        error = f"Connection to {ip}:{port} refused"
    except ssl.SSLError as e:
        error = f"SSL error on {ip}:{port}: {e}"
    except Exception as e:
        error = f"Unexpected error on {ip}:{port}: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    try:
        service = socket.getservbyport(port)
    except Exception:
        service = None

    return {
        "port": port,
        "service": service if not error else None,
        "banner": banner,
        "error": error
    }


def get_banners_for_open_ports(ip: str, open_ports_data: List[Dict]) -> List[Dict]:
    """
    Takes an IP and a list of open port dictionaries
    and attempts to grab banners concurrently.
    """
    banners = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(grab_banner, ip, port_data["port"]): port_data["port"]
            for port_data in open_ports_data
        }

        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                banners.append(result)
            except Exception as exc:
                banners.append({
                    "port": port,
                    "service": None,
                    "banner": "",
                    "error": f"Banner grab failed for port {port}: {exc}"
                })

    return banners

