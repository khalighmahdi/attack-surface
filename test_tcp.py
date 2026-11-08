import socket
sock = socket.create_connection(("127.0.0.1", 55553), timeout=5)
print("TCP connected")
sock.send(b"test")
data = sock.recv(1024)
print("Received:", data)
sock.close()