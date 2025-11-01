import struct, socket

def send_blob(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_blob(sock: socket.socket) -> bytes:
    hdr = _recvn(sock, 4)
    if not hdr: 
        return b""
    (n,) = struct.unpack("!I", hdr)
    return _recvn(sock, n)

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf
