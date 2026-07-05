# ============================================================
# smime_client.py  —  Klien surat S/MIME via transport mTLS
# ------------------------------------------------------------
# Sisi klien untuk smime_server.py. Menunjukkan dua lapis:
#   • objek : pesan disegel S/MIME (smime.seal_email) sebelum dikirim
#   • kanal : dikirim lewat koneksi TLS dengan sertifikat klien (mTLS)
#
# Dipakai lewat kode atau smime_mtls_demo.py.
# ============================================================
import os
import ssl
import json
import socket

import pki
import crypto_core as cc
import smime
import wire


class SmimeMailClient:
    def __init__(self, data_dir, server_host="127.0.0.1", server_port=9500):
        self.data_dir = data_dir
        self.server_host = server_host
        self.server_port = int(server_port)
        os.makedirs(data_dir, exist_ok=True)
        self.key_path = os.path.join(data_dir, "key.pem")
        self.cert_path = os.path.join(data_dir, "cert.pem")
        self.ca_path = os.path.join(data_dir, "ca_cert.pem")
        self.meta_path = os.path.join(data_dir, "meta.json")
        self.priv = self.cert_pem = self.ca_pem = None
        self.username = self.email = None
        self._load()

    # ---- persistensi ----
    def _load(self):
        if all(os.path.exists(p) for p in (self.key_path, self.cert_path, self.ca_path, self.meta_path)):
            self.priv = cc.load_private_pem(open(self.key_path, "rb").read())
            self.cert_pem = open(self.cert_path).read()
            self.ca_pem = open(self.ca_path).read()
            m = json.load(open(self.meta_path))
            self.username, self.email = m["username"], m["email"]

    def _save(self, username, email, priv, cert_pem, ca_pem):
        open(self.key_path, "wb").write(cc.private_to_pem(priv)); os.chmod(self.key_path, 0o600)
        open(self.cert_path, "w").write(cert_pem)
        open(self.ca_path, "w").write(ca_pem)
        json.dump({"username": username, "email": email}, open(self.meta_path, "w"))
        self.priv, self.cert_pem, self.ca_pem = priv, cert_pem, ca_pem
        self.username, self.email = username, email

    @property
    def logged_in(self): return self.priv is not None

    @property
    def cert(self): return pki.load_cert(self.cert_pem)

    # ---- koneksi (bootstrap vs mTLS) ----
    def _connect(self, authenticated):
        raw = socket.create_connection((self.server_host, self.server_port), timeout=20)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if authenticated:
            # Verifikasi SERVER terhadap CA + presentasikan sertifikat KLIEN (mTLS).
            ctx.load_verify_locations(cadata=self.ca_pem)
            ctx.check_hostname = True
            ctx.load_cert_chain(self.cert_path, self.key_path)
            return ctx.wrap_socket(raw, server_hostname=pki.SERVER_CN)
        # Bootstrap: belum punya sertifikat -> tak memverifikasi (hanya register/login).
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=pki.SERVER_CN)

    def _simple(self, obj, authenticated=True):
        conn = self._connect(authenticated)
        try:
            wire.send_json(conn, obj)
            resp = wire.recv_json(conn)
        finally:
            conn.close()
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "gagal"))
        return resp

    # ---- register / login ----
    def register(self, username, password):
        priv, _ = cc.generate_keypair(2048)
        csr = pki.make_csr(priv, username)
        r = self._simple({"op": "register", "username": username, "password": password,
                          "csr": csr}, authenticated=False)
        self._save(username, r["email"], priv, r["cert"], r["ca_cert"])
        return {"username": username, "email": r["email"]}

    def login(self, username, password):
        priv, _ = cc.generate_keypair(2048)
        csr = pki.make_csr(priv, username)
        r = self._simple({"op": "login", "username": username, "password": password,
                          "csr": csr}, authenticated=False)
        self._save(username, r["email"], priv, r["cert"], r["ca_cert"])
        return {"username": username, "email": r["email"]}

    # ---- directory ----
    def directory(self):
        users = self._simple({"op": "directory"})["users"]
        out = []
        for u in users:
            ok, reason = pki.verify_chain(u["cert"], self.ca_pem)
            out.append({**u, "trusted": ok, "trust_reason": reason})
        return out

    def _recipient(self, username):
        for u in self.directory():
            if u["username"] == username:
                if not u["trusted"]:
                    raise RuntimeError(f"Sertifikat penerima tak tepercaya: {u['trust_reason']}")
                return u["email"], pki.load_cert(u["cert"])
        raise RuntimeError("Penerima tak ada di direktori.")

    # ---- kirim surat (segel S/MIME -> alirkan via mTLS) ----
    def send_mail(self, to_username, subject, body, attachments=None):
        to_email, to_cert = self._recipient(to_username)
        eml = smime.seal_email(self.email, self.cert, self.priv,
                               [(to_email, to_cert)], subject, body, attachments or [])
        conn = self._connect(authenticated=True)
        try:
            wire.send_json(conn, {"op": "send", "to": to_username, "subject": subject})
            if not wire.recv_json(conn).get("ok"):
                raise RuntimeError("server menolak")
            for i in range(0, len(eml), 1024 * 1024):
                wire.send_frame(conn, eml[i:i + 1024 * 1024])
            wire.send_frame(conn, b"")
            resp = wire.recv_json(conn)
        finally:
            conn.close()
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "gagal"))
        return {"blob_id": resp["blob_id"], "size": resp["size"], "eml_size": len(eml)}

    # ---- inbox / ambil + buka ----
    def inbox(self):
        return self._simple({"op": "inbox"})["items"]

    def fetch_mail(self, blob_id):
        conn = self._connect(authenticated=True)
        try:
            wire.send_json(conn, {"op": "fetch", "blob_id": blob_id})
            head = wire.recv_json(conn)
            if not head.get("ok"):
                raise RuntimeError(head.get("error", "gagal ambil"))
            buf = bytearray()
            while True:
                frame = wire.recv_frame(conn)
                if frame == b"":
                    break
                buf += frame
        finally:
            conn.close()
        opened = smime.open_email(bytes(buf), self.cert, self.priv, self.ca_pem)
        opened["_meta"] = head["meta"]
        return opened

    def ack(self, blob_id):
        return self._simple({"op": "ack", "blob_id": blob_id})

    def audit(self):
        return self._simple({"op": "audit"})["events"]
