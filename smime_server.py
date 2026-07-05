# ============================================================
# smime_server.py  —  Server surat S/MIME dengan transport mTLS
# ------------------------------------------------------------
# Menggabungkan DUA lapis keamanan yang berbeda:
#
#   • KANAL  (mTLS)   : tiap koneksi diamankan TLS, dan untuk operasi
#                       terautentikasi klien WAJIB mempresentasikan
#                       sertifikat klien yang ditandatangani CA.
#                       Server memverifikasi rantainya lalu membaca CN.
#
#   • OBJEK  (S/MIME) : muatan yang dikirim adalah email .eml yang
#                       SUDAH ditandatangani + dienkripsi S/MIME.
#                       Server HANYA melihat ciphertext — tak bisa
#                       membaca isi, sekalipun kanal TLS "berhenti"
#                       di server (TLS termination).
#
# Jalankan:  python smime_server.py         (default TCP+TLS :9500)
#
# Peran server: CA (menerbitkan sertifikat S/MIME) + Directory +
# kotak-surat store-and-forward untuk pesan .eml.
# ============================================================
import os
import ssl
import json
import uuid
import socket
import hashlib
import threading
import datetime

import pki
import wire

HOST = os.environ.get("SMIME_SERVER_HOST", "0.0.0.0")
PORT = int(os.environ.get("SMIME_SERVER_PORT", "9500"))
DATA = os.environ.get("SMIME_SERVER_DATA", "./smime_server_data")
MAIL_DOMAIN = os.environ.get("SMIME_MAIL_DOMAIN", "securedrop.local")

CA_DIR = os.path.join(DATA, "ca")
BLOB_DIR = os.path.join(DATA, "mailbox")
USERS_PATH = os.path.join(DATA, "users.json")
MAILBOX_PATH = os.path.join(DATA, "mailbox.json")
AUDIT_PATH = os.path.join(DATA, "audit.json")
for d in (DATA, CA_DIR, BLOB_DIR):
    os.makedirs(d, exist_ok=True)

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


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _hash_pw(pw):
    salt = os.urandom(16)
    return salt.hex() + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()


def _verify_pw(pw, stored):
    try:
        s, h = stored.split("$", 1)
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(s), 200_000).hex() == h
    except Exception:
        return False


def audit(**e):
    with _lock:
        log = _load(AUDIT_PATH, [])
        log.append({"id": len(log) + 1, "timestamp": _now(), **e})
        _save(AUDIT_PATH, log[-5000:])


class SmimeServer:
    def __init__(self, host=HOST, port=PORT):
        self.host, self.port = host, port
        self.ca = pki.load_or_create_ca(CA_DIR)
        self._running = False

    # ---- penyimpanan ----
    def _users(self): return _load(USERS_PATH, {})
    def _save_users(self, u): _save(USERS_PATH, u)
    def _mailbox(self): return _load(MAILBOX_PATH, [])
    def _save_mailbox(self, m): _save(MAILBOX_PATH, m)

    # ---- TLS + mTLS ----
    def _tls_context(self):
        p = pki.ca_paths(CA_DIR)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(p["srv_cert"], p["srv_key"])     # sertifikat server (ditandatangani CA)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # mTLS OPSIONAL: klien boleh tak menyertakan cert (untuk register),
        # tapi bila menyertakan, HARUS ditandatangani CA kita (kalau tidak,
        # handshake TLS langsung gagal). Operasi terautentikasi mewajibkannya.
        ctx.verify_mode = ssl.CERT_OPTIONAL
        ctx.load_verify_locations(p["cert"])
        return ctx

    def start(self):
        ctx = self._tls_context()
        self._ctx = ctx
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port)); s.listen(32)
        self._sock = s; self._running = True
        print(f"  [smime-server] Root CA fp: {pki.cert_fingerprint(self.ca.cert)[:47]}…")
        print(f"  [smime-server] TCP+TLS(mTLS) di {self.host}:{self.port}")
        while self._running:
            try:
                raw, addr = s.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(raw, addr), daemon=True).start()

    def stop(self):
        self._running = False
        try: self._sock.close()
        except Exception: pass

    # ---- identitas klien dari sertifikat mTLS ----
    def _client_cn(self, conn):
        der = conn.getpeercert(binary_form=True)
        if not der:
            return None
        from cryptography import x509
        # ssl sudah memverifikasi rantai ke CA (CERT_OPTIONAL + verify_locations)
        return pki.cert_common_name(x509.load_der_x509_certificate(der))

    def _handle(self, raw, addr):
        try:
            conn = self._ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError as e:
            # Handshake gagal — mis. klien mempresentasikan cert dari CA lain.
            audit(event="tls_handshake_gagal", ip=addr[0], result=str(e)[:80])
            try: raw.close()
            except Exception: pass
            return
        try:
            req = wire.recv_json(conn)
            op = req.get("op")
            if op == "get_ca":
                wire.send_json(conn, {"ok": True, "ca_cert": self.ca.cert_pem})
            elif op == "register":
                self._register(conn, req, addr)
            elif op == "login":
                self._login(conn, req, addr)
            elif op in ("directory", "send", "inbox", "fetch", "ack", "audit"):
                cn = self._client_cn(conn)
                if not cn or cn not in self._users():
                    audit(event="akses_ditolak", op=op, ip=addr[0],
                          result="tanpa sertifikat klien (mTLS)")
                    wire.send_json(conn, {"ok": False, "error": "Butuh sertifikat klien (mTLS)."})
                else:
                    tlsinfo = f"{conn.version()} · {conn.cipher()[0]}"
                    print(f"  [mTLS] {cn} @ {addr[0]}  op={op}  ({tlsinfo})")
                    getattr(self, "_" + op)(conn, req, cn, addr)
            else:
                wire.send_json(conn, {"ok": False, "error": f"op tak dikenal: {op}"})
        except Exception as e:
            try: wire.send_json(conn, {"ok": False, "error": str(e)})
            except Exception: pass
        finally:
            try: conn.close()
            except Exception: pass

    # ---- operasi ----
    def _register(self, conn, req, addr):
        u = (req.get("username") or "").strip()
        pw = req.get("password") or ""
        csr = req.get("csr") or ""
        if not (u and pw and csr):
            return wire.send_json(conn, {"ok": False, "error": "username/password/csr wajib."})
        email = f"{u}@{MAIL_DOMAIN}"
        with _lock:
            users = self._users()
            if u in users:
                return wire.send_json(conn, {"ok": False, "error": "Username sudah dipakai."})
            try:
                cert = pki.sign_csr(self.ca, csr, u, is_smime=True, email=email)
            except Exception as e:
                return wire.send_json(conn, {"ok": False, "error": f"CSR ditolak: {e}"})
            users[u] = {"password_hash": _hash_pw(pw), "cert": cert, "email": email,
                        "created_at": _now()}
            self._save_users(users)
        audit(event="register", actor=u, ip=addr[0], result="sertifikat S/MIME diterbitkan")
        wire.send_json(conn, {"ok": True, "cert": cert, "ca_cert": self.ca.cert_pem, "email": email})

    def _login(self, conn, req, addr):
        u = (req.get("username") or "").strip()
        pw = req.get("password") or ""
        csr = req.get("csr") or ""
        with _lock:
            users = self._users()
            rec = users.get(u)
            if not rec or not _verify_pw(pw, rec["password_hash"]):
                audit(event="login", actor=u, ip=addr[0], result="GAGAL")
                return wire.send_json(conn, {"ok": False, "error": "Kredensial salah."})
            if csr:
                try:
                    rec["cert"] = pki.sign_csr(self.ca, csr, u, is_smime=True, email=rec["email"])
                    users[u] = rec; self._save_users(users)
                except Exception as e:
                    return wire.send_json(conn, {"ok": False, "error": f"CSR ditolak: {e}"})
        audit(event="login", actor=u, ip=addr[0], result="OK")
        wire.send_json(conn, {"ok": True, "cert": rec["cert"], "ca_cert": self.ca.cert_pem,
                              "email": rec["email"]})

    def _directory(self, conn, req, cn, addr):
        users = self._users()
        out = [{"username": n, "email": r["email"], "cert": r["cert"], "me": n == cn}
               for n, r in sorted(users.items())]
        wire.send_json(conn, {"ok": True, "users": out})

    def _send(self, conn, req, cn, addr):
        to = (req.get("to") or "").strip()
        subject = req.get("subject") or "(tanpa subjek)"
        if to not in self._users():
            return wire.send_json(conn, {"ok": False, "error": "Penerima tidak terdaftar."})
        blob_id = uuid.uuid4().hex
        path = os.path.join(BLOB_DIR, blob_id + ".eml")
        wire.send_json(conn, {"ok": True, "ready": True, "blob_id": blob_id})
        # Terima .eml S/MIME (server hanya melihat ciphertext).
        h = hashlib.sha256(); size = 0
        with open(path, "wb") as f:
            while True:
                frame = wire.recv_frame(conn)
                if frame == b"":
                    break
                f.write(frame); h.update(frame); size += len(frame)
        with _lock:
            mb = self._mailbox()
            mb.append({"blob_id": blob_id, "from": cn, "to": to, "subject": subject,
                       "size": size, "sha256": h.hexdigest(), "created_at": _now()})
            self._save_mailbox(mb)
        audit(event="mail_relay", actor=cn, peer=to, subject=subject, size=size,
              status="stored", result="ciphertext .eml disimpan (server tak bisa membaca isi)")
        wire.send_json(conn, {"ok": True, "blob_id": blob_id, "size": size, "sha256": h.hexdigest()})

    def _inbox(self, conn, req, cn, addr):
        wire.send_json(conn, {"ok": True, "items": [m for m in self._mailbox() if m["to"] == cn]})

    def _fetch(self, conn, req, cn, addr):
        bid = req.get("blob_id") or ""
        rec = next((m for m in self._mailbox() if m["blob_id"] == bid and m["to"] == cn), None)
        if not rec:
            return wire.send_json(conn, {"ok": False, "error": "Pesan tak ada / bukan milik Anda."})
        path = os.path.join(BLOB_DIR, bid + ".eml")
        wire.send_json(conn, {"ok": True, "meta": rec})
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                wire.send_frame(conn, chunk)
        wire.send_frame(conn, b"")
        audit(event="mail_relay", actor=cn, peer=rec["from"], subject=rec["subject"],
              size=rec["size"], status="fetched", result="ciphertext diunduh penerima")

    def _ack(self, conn, req, cn, addr):
        bid = req.get("blob_id") or ""
        with _lock:
            mb = self._mailbox()
            rec = next((m for m in mb if m["blob_id"] == bid and m["to"] == cn), None)
            if rec:
                self._save_mailbox([m for m in mb if m["blob_id"] != bid])
                try: os.remove(os.path.join(BLOB_DIR, bid + ".eml"))
                except OSError: pass
        wire.send_json(conn, {"ok": True})

    def _audit(self, conn, req, cn, addr):
        log = _load(AUDIT_PATH, [])
        wire.send_json(conn, {"ok": True, "events": [e for e in log
                              if e.get("actor") == cn or e.get("peer") == cn][-500:]})


def main():
    srv = SmimeServer()
    print("=" * 60)
    print("  SecureDrop — SERVER SURAT S/MIME  (kanal mTLS + objek S/MIME)")
    print("=" * 60)
    try:
        srv.start()
    except KeyboardInterrupt:
        srv.stop(); print("\n  [smime-server] dihentikan.")


if __name__ == "__main__":
    main()
