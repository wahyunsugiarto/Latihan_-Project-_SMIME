# ============================================================
# wire.py  —  Protokol berbingkai (framed) di atas TCP/TLS.
# Dipakai bersama oleh server pusat dan klien.
#
# Format bingkai:  [4-byte big-endian panjang][payload]
#   - panjang 0  = sentinel (mis. akhir stream chunk)
# JSON dikirim sebagai satu bingkai berisi UTF-8 JSON.
# ============================================================
import json
import struct


def send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("Koneksi terputus.")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock) -> bytes:
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, n) if n else b""


def send_json(sock, obj):
    send_frame(sock, json.dumps(obj).encode("utf-8"))


def recv_json(sock):
    return json.loads(recv_frame(sock).decode("utf-8"))


def human_speed(bps: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024:
            return f"{bps:.1f} {unit}"
        bps /= 1024
    return f"{bps:.1f} TB/s"
