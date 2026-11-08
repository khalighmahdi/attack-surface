import socket, ssl, msgpack

sock = socket.create_connection(("127.0.0.1", 55553), timeout=30)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(sock, server_hostname="127.0.0.1")
s.settimeout(30)

msgid = 1
request = [msgid, "auth.login", ["msf", "msfpass"]]
data = msgpack.packb(request, use_bin_type=True)
s.sendall(data)

resp = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
    try:
        result = msgpack.unpackb(resp, raw=False)
        print("Result:", result)
        break
    except msgpack.ExtraData:
        continue
    except Exception as e:
        print("Error:", e)
        break
s.close()