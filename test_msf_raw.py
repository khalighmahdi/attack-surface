import socket
import msgpack

# Try without SSL first - just raw msgpack over TCP
sock = socket.create_connection(("127.0.0.1", 55553), timeout=10)
msgid = 1
request = [msgid, "auth.login", ["msf", "msfpass"]]
data = msgpack.packb(request, use_bin_type=True)
sock.sendall(data)

resp = b""
while True:
    chunk = sock.recv(4096)
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
sock.close()