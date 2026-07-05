# ============================================================
# client_core.py  —  Sisi KLIEN SecureDrop
# ------------------------------------------------------------
# Menyimpan identitas ber-sertifikat (kunci privat + sertifikat
# yang ditandatangani CA + sertifikat CA) dan berkomunikasi
# dengan SERVER PUSAT melalui TCP+TLS:
#   - register / login   -> memperoleh sertifikat dari CA
#   - directory          -> daftar pengguna + sertifikat (untuk E2E)
#   - send               -> enkripsi lalu unggah ke relay
#   - inbox / fetch      -> unduh & dekripsi file untuk kita
#   - audit              -> ambil audit log dari server
#
# mTLS: untuk operasi terautentikasi, klien mempresentasikan
# sertifikat kliennya; server memverifikasi rantainya ke CA.
# ============================================================
import os
import ssl
import json
import time
import socket
from dataclasses import dataclass, field

import crypto_core as cc
import pki
import wire
import container


@dataclass
class ClientIdentity:
    username: str
    priv: object
    cert_pem: str
    ca_cert_pem: str

    @property
    def pub(self):
        return self.priv.public_key()

    @property
    def public_pem(self) -> str:
        return cc.public_to_pem(self.pub).decode()

    @property
    def fingerprint(self) -> str:
        return cc.fingerprint(self.pub)

    @property
    def short(self) -> str:
        return cc.short_fp(self.fingerprint)


class Client:
    def __init__(self, data_dir, server_host, server_port):
        self.data_dir = data_dir
        self.server_host = server_host
        self.server_port = int(server_port)
        os.makedirs(data_dir, exist_ok=True)
        self.key_path = os.path.join(data_dir, "client_key.pem")
        self.cert_path = os.path.join(data_dir, "client_cert.pem")
        self.ca_path = os.path.join(data_dir, "ca_cert.pem")
        self.meta_path = os.path.join(data_dir, "client_meta.json")
        self.identity: ClientIdentity | None = None
        self._load()

    # ── persistensi lokal ──────────────────────────────────
    def _load(self):
        if os.path.exists(self.key_path) and os.path.exists(self.cert_path) \
                and os.path.exists(self.ca_path) and os.path.exists(self.meta_path):
            priv = cc.load_private_pem(open(self.key_path, "rb").read())
            cert = open(self.cert_path).read()
            ca = open(self.ca_path).read()
            meta = json.load(open(self.meta_path))
            self.identity = ClientIdentity(meta["username"], priv, cert, ca)

    def _save_identity(self, username, priv, cert_pem, ca_pem):
        with open(self.key_path, "wb") as f:
            f.write(cc.private_to_pem(priv))
        os.chmod(self.key_path, 0o600)
        open(self.cert_path, "w").write(cert_pem)
        open(self.ca_path, "w").write(ca_pem)
        json.dump({"username": username}, open(self.meta_path, "w"))
        self.identity = ClientIdentity(username, priv, cert_pem, ca_pem)

    @property
    def logged_in(self) -> bool:
        return self.identity is not None

    def logout_local(self):
        for p in (self.key_path, self.cert_path, self.ca_path, self.meta_path):
            try:
                os.remove(p)
            except OSError:
                pass
        self.identity = None

    # ── koneksi TLS ────────────────────────────────────────
    def _connect(self, authenticated: bool):
        raw = socket.create_connection((self.server_host, self.server_port), timeout=20)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if authenticated and self.identity:
            # Verifikasi server terhadap CA + presentasikan sertifikat klien (mTLS)
            import tempfile
            ctx.load_verify_locations(cadata=self.identity.ca_cert_pem)
            ctx.check_hostname = True
            ctx.load_cert_chain(self.cert_path, self.key_path)
            conn = ctx.wrap_socket(raw, server_hostname=pki.SERVER_CN)
        else:
            # Bootstrap (register/login/get_ca): belum tentu punya CA -> tak verifikasi.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(raw, server_hostname=pki.SERVER_CN)
        return conn

    def _request(self, obj, authenticated=True):
        conn = self._connect(authenticated)
        try:
            wire.send_json(conn, obj)
            return wire.recv_json(conn), conn
        except Exception:
            conn.close()
            raise

    def _simple(self, obj, authenticated=True):
        resp, conn = self._request(obj, authenticated)
        conn.close()
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "gagal"))
        return resp

    # ── register / login ───────────────────────────────────
    def register(self, username, password):
        priv, pub = cc.generate_keypair()
        csr = pki.make_csr(priv, username)
        resp = self._simple({"op": "register", "username": username,
                             "password": password, "csr": csr}, authenticated=False)
        self._save_identity(username, priv, resp["cert"], resp["ca_cert"])
        return {"username": username, "fingerprint": resp["fingerprint"]}

    def login(self, username, password, new_key=False):
        priv = None
        csr = ""
        if new_key or not os.path.exists(self.key_path):
            priv, _ = cc.generate_keypair()
            csr = pki.make_csr(priv, username)
        resp = self._simple({"op": "login", "username": username,
                             "password": password, "csr": csr}, authenticated=False)
        if priv is None:   # pakai kunci lokal yang ada
            priv = cc.load_private_pem(open(self.key_path, "rb").read())
        self._save_identity(username, priv, resp["cert"], resp["ca_cert"])
        return {"username": username, "fingerprint": resp["fingerprint"]}

    # ── directory ──────────────────────────────────────────
    def directory(self):
        resp = self._simple({"op": "directory"})
        users = []
        for u in resp["users"]:
            ok, reason = pki.verify_chain(u["cert"], self.identity.ca_cert_pem)
            users.append({**u, "trusted": ok, "trust_reason": reason})
        return users

    def _recipient_pub(self, username):
        for u in self.directory():
            if u["username"] == username:
                if not u["trusted"]:
                    raise RuntimeError(f"Sertifikat penerima tidak tepercaya: {u['trust_reason']}")
                cert = pki.load_cert(u["cert"])
                return cert.public_key(), pki.cert_fingerprint(cert)
        raise RuntimeError("Penerima tidak ditemukan di direktori.")

    # ── kirim (enkripsi + unggah, streaming) ───────────────
    def send_file(self, to_username, src_path, note="", progress=None, keep_encrypted_path=None):
        recipient_pub, recipient_fp = self._recipient_pub(to_username)
        filesize = os.path.getsize(src_path)
        filename = os.path.basename(src_path)
        gen, info = container.encrypt_stream(src_path, self.identity, recipient_pub, recipient_fp)

        keep = open(keep_encrypted_path, "wb") if keep_encrypted_path else None
        conn = self._connect(authenticated=True)
        try:
            wire.send_json(conn, {"op": "send", "to": to_username, "filename": filename,
                                  "size": filesize, "note": note,
                                  "transfer_id": info["transfer_id"]})
            ready = wire.recv_json(conn)
            if not ready.get("ok"):
                raise RuntimeError(ready.get("error", "server menolak"))
            sent = 0
            t0 = time.time()
            for seg in gen:
                wire.send_frame(conn, seg)
                if keep:
                    keep.write(seg)
                sent += len(seg)
                if progress:
                    progress(sent, filesize, time.time() - t0)
            wire.send_frame(conn, b"")  # sentinel
            resp = wire.recv_json(conn)
            if not resp.get("ok"):
                raise RuntimeError(resp.get("error", "gagal simpan di server"))
            return {"transfer_id": info["transfer_id"], "sha256": info["sha256"],
                    "blob_id": resp.get("blob_id"), "enc_sha256": resp.get("enc_sha256"),
                    "enc_size": resp.get("enc_size"), "filename": filename, "size": filesize}
        finally:
            conn.close()
            if keep:
                keep.close()

    # ── inbox / fetch (unduh + dekripsi, streaming) ────────
    def inbox(self):
        return self._simple({"op": "inbox"})["items"]

    def fetch_to_temp(self, blob_id, tmp_path, progress=None):
        """Unduh blob terenkripsi ke file sementara (hemat memori)."""
        conn = self._connect(authenticated=True)
        try:
            wire.send_json(conn, {"op": "fetch", "blob_id": blob_id})
            head = wire.recv_json(conn)
            if not head.get("ok"):
                raise RuntimeError(head.get("error", "gagal ambil"))
            meta = head["meta"]
            got = 0
            t0 = time.time()
            with open(tmp_path, "wb") as f:
                while True:
                    frame = wire.recv_frame(conn)
                    if frame == b"":
                        break
                    f.write(frame)
                    got += len(frame)
                    if progress:
                        progress(got, meta.get("enc_size", 0), time.time() - t0)
            return meta
        finally:
            conn.close()

    def ack(self, blob_id, integrity, signature, authenticated):
        return self._simple({"op": "ack", "blob_id": blob_id, "integrity": integrity,
                             "signature": signature, "authenticated": authenticated})

    # ── audit ──────────────────────────────────────────────
    def audit(self):
        return self._simple({"op": "audit"})["events"]
