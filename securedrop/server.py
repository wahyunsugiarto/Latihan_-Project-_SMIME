# ============================================================
# server.py  —  SERVER PUSAT SecureDrop (CA + Directory + Relay)
# ------------------------------------------------------------
# Jalankan:  python server.py
# Mendengarkan TCP+TLS di port 9000 (default).
#
# Peran server (satu proses, tiga fungsi):
#   1. CA (Certificate Authority) — menerbitkan sertifikat klien
#      dari CSR setelah login (username/password) berhasil.
#   2. DIRECTORY — daftar semua pengguna terdaftar beserta
#      sertifikatnya, supaya klien bisa menemukan & mengenkripsi
#      ke penerima TANPA mengetik IP/port.
#   3. RELAY (store-and-forward) — menyimpan file yang SUDAH
#      terenkripsi end-to-end (server tak bisa membacanya),
#      lalu meneruskannya ke penerima saat ia online.
#
# Otentikasi tiap permintaan: mutual TLS. Klien menyertakan
# sertifikat klien (ditandatangani CA); server memverifikasi
# rantainya lalu membaca CN = username. Operasi register/login/
# get_ca boleh tanpa sertifikat klien (bootstrap).
#
# Semua aktivitas dicatat ke AUDIT LOG (timestamp, pengirim,
# penerima, nama file, ukuran, status, hasil verifikasi, error).
# ============================================================
import os
import ssl
import json
import time
import uuid
import socket
import hashlib
import threading
import datetime

import pki
import wire

# ── Konfigurasi (via env) ──────────────────────────────────
HOST = os.environ.get("SECUREDROP_SERVER_HOST", "0.0.0.0")
PORT = int(os.environ.get("SECUREDROP_SERVER_PORT", "9000"))
SRV_DATA = os.environ.get("SECUREDROP_SERVER_DATA", "./server_data")
CA_DIR = os.path.join(SRV_DATA, "ca")
BLOB_DIR = os.path.join(SRV_DATA, "blobs")
USERS_PATH = os.path.join(SRV_DATA, "users.json")
MAILBOX_PATH = os.path.join(SRV_DATA, "mailbox.json")
AUDIT_PATH = os.path.join(SRV_DATA, "audit.json")

for d in (SRV_DATA, CA_DIR, BLOB_DIR):
    os.makedirs(d, exist_ok=True)


# ── Penyimpanan JSON aman-thread ───────────────────────────
_lock = threading.RLock()


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _hash_pw(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + dk.hex()


def _verify_pw(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 200_000)
        return dk.hex() == hash_hex
    except Exception:
        return False


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def audit(event: dict):
    with _lock:
        log = _load(AUDIT_PATH, [])
        rec = {"id": len(log) + 1, "timestamp": _now()}
        rec.update(event)
        log.append(rec)
        log = log[-5000:]
        _save(AUDIT_PATH, log)


# ============================================================
#  Handler koneksi
# ============================================================
class Server:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.ca = pki.load_or_create_ca(CA_DIR)
        self._sock = None
        self._running = False

    # ---- util akun/direktori ----
    def _users(self):
        return _load(USERS_PATH, {})

    def _save_users(self, u):
        _save(USERS_PATH, u)

    def _mailbox(self):
        return _load(MAILBOX_PATH, [])

    def _save_mailbox(self, m):
        _save(MAILBOX_PATH, m)

    # ---- TLS ----
    def _tls_context(self):
        p = pki.ca_paths(CA_DIR)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(p["srv_cert"], p["srv_key"])
        # Verifikasi sertifikat KLIEN bila disertakan (mutual TLS opsional):
        ctx.verify_mode = ssl.CERT_OPTIONAL
        ctx.load_verify_locations(p["cert"])   # percayai hanya cert yang ditandatangani CA kita
        return ctx

    def start(self):
        ctx = self._tls_context()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(32)
        self._running = True
        self._ctx = ctx
        print(f"  [server] CA siap. Root CA fingerprint: {pki.cert_fingerprint(self.ca.cert)[:47]}…")
        print(f"  [server] Mendengarkan TCP+TLS di {self.host}:{self.port}")
        while self._running:
            try:
                raw, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(raw, addr), daemon=True).start()

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except Exception:
            pass

    # ---- otentikasi klien via cert yang dipresentasikan ----
    def _client_username(self, conn):
        """Ambil username dari sertifikat klien (mTLS). None bila tak ada/valid."""
        try:
            der = conn.getpeercert(binary_form=True)
        except Exception:
            der = None
        if not der:
            return None
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        # ssl sudah memverifikasi rantai ke CA (CERT_OPTIONAL + load_verify_locations),
        # jadi cukup baca CN.
        return pki.cert_common_name(cert)

    def _handle(self, raw, addr):
        try:
            conn = self._ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError:
            try:
                raw.close()
            except Exception:
                pass
            return
        try:
            req = wire.recv_json(conn)
            op = req.get("op")
            if op == "get_ca":
                wire.send_json(conn, {"ok": True, "ca_cert": self.ca.cert_pem})
            elif op == "register":
                self._op_register(conn, req, addr)
            elif op == "login":
                self._op_login(conn, req, addr)
            elif op == "directory":
                self._auth_op(conn, addr, self._op_directory, req)
            elif op == "send":
                self._auth_op(conn, addr, self._op_send, req)
            elif op == "inbox":
                self._auth_op(conn, addr, self._op_inbox, req)
            elif op == "fetch":
                self._auth_op(conn, addr, self._op_fetch, req)
            elif op == "audit":
                self._auth_op(conn, addr, self._op_audit, req)
            elif op == "ack":
                self._auth_op(conn, addr, self._op_ack, req)
            else:
                wire.send_json(conn, {"ok": False, "error": f"operasi tak dikenal: {op}"})
        except Exception as e:
            try:
                wire.send_json(conn, {"ok": False, "error": str(e)})
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _auth_op(self, conn, addr, fn, req):
        user = self._client_username(conn)
        if not user:
            audit({"event": "access_denied", "actor": "?", "ip": addr[0],
                   "op": req.get("op"), "result": "tanpa sertifikat klien"})
            wire.send_json(conn, {"ok": False, "error": "Butuh sertifikat klien (login dulu)."})
            return
        users = self._users()
        if user not in users:
            wire.send_json(conn, {"ok": False, "error": "Akun tidak dikenal."})
            return
        fn(conn, req, user, addr)

    # ---- operasi ----
    def _op_register(self, conn, req, addr):
        username = (req.get("username") or "").strip()
        password = req.get("password") or ""
        csr = req.get("csr") or ""
        if not username or not password or not csr:
            return wire.send_json(conn, {"ok": False, "error": "username/password/csr wajib."})
        with _lock:
            users = self._users()
            if username in users:
                return wire.send_json(conn, {"ok": False, "error": "Username sudah dipakai."})
            try:
                cert_pem = pki.sign_csr(self.ca, csr, username)
            except Exception as e:
                return wire.send_json(conn, {"ok": False, "error": f"CSR ditolak: {e}"})
            fp = pki.cert_fingerprint(pki.load_cert(cert_pem))
            users[username] = {"password_hash": _hash_pw(password), "cert": cert_pem,
                               "fingerprint": fp, "created_at": _now()}
            self._save_users(users)
        audit({"event": "register", "actor": username, "ip": addr[0], "result": "sertifikat diterbitkan"})
        wire.send_json(conn, {"ok": True, "cert": cert_pem, "ca_cert": self.ca.cert_pem,
                              "fingerprint": fp})

    def _op_login(self, conn, req, addr):
        username = (req.get("username") or "").strip()
        password = req.get("password") or ""
        csr = req.get("csr") or ""
        with _lock:
            users = self._users()
            u = users.get(username)
            if not u or not _verify_pw(password, u["password_hash"]):
                audit({"event": "login", "actor": username, "ip": addr[0], "result": "GAGAL (kredensial salah)"})
                return wire.send_json(conn, {"ok": False, "error": "Username atau password salah."})
            # Bila klien mengirim CSR (identitas baru), terbitkan ulang sertifikat.
            if csr:
                try:
                    cert_pem = pki.sign_csr(self.ca, csr, username)
                    u["cert"] = cert_pem
                    u["fingerprint"] = pki.cert_fingerprint(pki.load_cert(cert_pem))
                    users[username] = u
                    self._save_users(users)
                except Exception as e:
                    return wire.send_json(conn, {"ok": False, "error": f"CSR ditolak: {e}"})
        audit({"event": "login", "actor": username, "ip": addr[0], "result": "OK"})
        wire.send_json(conn, {"ok": True, "cert": u["cert"], "ca_cert": self.ca.cert_pem,
                              "fingerprint": u["fingerprint"]})

    def _op_directory(self, conn, req, user, addr):
        users = self._users()
        out = [{"username": name, "cert": u["cert"], "fingerprint": u["fingerprint"],
                "me": name == user}
               for name, u in sorted(users.items())]
        wire.send_json(conn, {"ok": True, "users": out})

    def _op_send(self, conn, req, user, addr):
        to = (req.get("to") or "").strip()
        filename = os.path.basename(req.get("filename") or "file.bin")
        size = int(req.get("size") or 0)
        note = req.get("note") or ""
        transfer_id = req.get("transfer_id") or ""
        users = self._users()
        if to not in users:
            return wire.send_json(conn, {"ok": False, "error": "Penerima tidak terdaftar."})
        blob_id = uuid.uuid4().hex
        path = os.path.join(BLOB_DIR, blob_id + ".blob")
        wire.send_json(conn, {"ok": True, "ready": True, "blob_id": blob_id})
        # Terima stream terenkripsi (server hanya melihat ciphertext).
        h = hashlib.sha256()
        received = 0
        try:
            with open(path, "wb") as f:
                while True:
                    frame = wire.recv_frame(conn)
                    if frame == b"":
                        break
                    f.write(frame)
                    h.update(frame)
                    received += len(frame)
        except Exception as e:
            try:
                os.remove(path)
            except OSError:
                pass
            audit({"event": "transfer", "actor": user, "peer": to, "filename": filename,
                   "size": size, "status": "transfer", "result": f"GAGAL: {e}"})
            return wire.send_json(conn, {"ok": False, "error": f"Upload gagal: {e}"})
        enc_sha = h.hexdigest()
        with _lock:
            mb = self._mailbox()
            mb.append({"blob_id": blob_id, "from": user, "to": to, "filename": filename,
                       "size": size, "enc_size": received, "enc_sha256": enc_sha,
                       "transfer_id": transfer_id, "note": note,
                       "created_at": _now(), "fetched": False})
            self._save_mailbox(mb)
        audit({"event": "transfer", "actor": user, "peer": to, "filename": filename,
               "size": size, "status": "transfer", "result": "diterima server (relay)",
               "transfer_id": transfer_id, "enc_sha256": enc_sha})
        wire.send_json(conn, {"ok": True, "blob_id": blob_id, "enc_sha256": enc_sha,
                              "enc_size": received})

    def _op_inbox(self, conn, req, user, addr):
        mb = self._mailbox()
        items = [m for m in mb if m["to"] == user]
        wire.send_json(conn, {"ok": True, "items": items})

    def _op_fetch(self, conn, req, user, addr):
        blob_id = req.get("blob_id") or ""
        mb = self._mailbox()
        rec = next((m for m in mb if m["blob_id"] == blob_id and m["to"] == user), None)
        if not rec:
            return wire.send_json(conn, {"ok": False, "error": "Blob tak ada / bukan milik Anda."})
        path = os.path.join(BLOB_DIR, blob_id + ".blob")
        if not os.path.isfile(path):
            return wire.send_json(conn, {"ok": False, "error": "Data blob hilang di server."})
        wire.send_json(conn, {"ok": True, "meta": rec})
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                wire.send_frame(conn, chunk)
        wire.send_frame(conn, b"")  # sentinel
        audit({"event": "transfer", "actor": user, "peer": rec["from"], "filename": rec["filename"],
               "size": rec["size"], "status": "receive", "result": "diunduh penerima",
               "transfer_id": rec.get("transfer_id", "")})

    def _op_audit(self, conn, req, user, addr):
        log = _load(AUDIT_PATH, [])
        mine = [e for e in log if e.get("actor") == user or e.get("peer") == user]
        wire.send_json(conn, {"ok": True, "events": mine[-1000:]})

    def _op_ack(self, conn, req, user, addr):
        """Penerima melapor hasil verifikasi+dekripsi -> dicatat ke audit; blob dihapus."""
        blob_id = req.get("blob_id") or ""
        integrity = bool(req.get("integrity"))
        signature = bool(req.get("signature"))
        authenticated = bool(req.get("authenticated"))
        with _lock:
            mb = self._mailbox()
            rec = next((m for m in mb if m["blob_id"] == blob_id and m["to"] == user), None)
            if rec:
                rec["fetched"] = True
                mb = [m for m in mb if m["blob_id"] != blob_id]
                self._save_mailbox(mb)
                try:
                    os.remove(os.path.join(BLOB_DIR, blob_id + ".blob"))
                except OSError:
                    pass
        result = "verify OK" if (integrity and signature and authenticated) else "verify BERMASALAH"
        audit({"event": "verify", "actor": user, "peer": rec["from"] if rec else "?",
               "filename": rec["filename"] if rec else "", "size": rec["size"] if rec else 0,
               "status": "verify",
               "result": f"{result} (integrity={integrity}, signature={signature}, auth={authenticated})",
               "transfer_id": rec.get("transfer_id", "") if rec else ""})
        wire.send_json(conn, {"ok": True})


def main():
    srv = Server()
    print("=" * 62)
    print("  SecureDrop — SERVER PUSAT (CA + Directory + Relay)")
    print("=" * 62)
    try:
        srv.start()
    except KeyboardInterrupt:
        srv.stop()
        print("\n  [server] dihentikan.")


if __name__ == "__main__":
    main()
