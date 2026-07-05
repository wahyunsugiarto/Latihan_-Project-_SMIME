# ============================================================
# container.py  —  Kontainer file terenkripsi E2E (.sdrop)
# ------------------------------------------------------------
# Membungkus enkripsi hibrida (crypto_core) menjadi satu stream
# mandiri berbingkai, dan MENYERTAKAN SERTIFIKAT PENGIRIM supaya
# penerima bisa memverifikasi identitas pengirim lewat CA (PKI),
# bukan lagi TOFU.
#
# Struktur (tiap bagian: [4-byte panjang][data]):
#   [header json] [chunk ...] [sentinel len=0] [trailer json]
#
# header memuat: wrapped_keys (RSA-OAEP), nonce_prefix, transfer_id,
#                sender_cert (PEM), sender_fingerprint, filename, filesize.
# trailer memuat: sha256 seluruh file + signature RSA-PSS pengirim.
# ============================================================
import os
import json
import struct

import crypto_core as cc
import pki

MAGIC = b"SDROP2\n"


def _pack(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _read_frame(f) -> bytes:
    raw = f.read(4)
    if len(raw) < 4:
        raise EOFError("stream terpotong")
    (n,) = struct.unpack(">I", raw)
    return f.read(n) if n else b""


# ============================================================
#  ENKRIPSI — sebagai generator segmen byte (hemat memori)
# ============================================================
def encrypt_stream(src_path, identity, recipient_pub, recipient_fp,
                   chunk_size=cc.DEFAULT_CHUNK):
    """
    Yield potongan byte kontainer terenkripsi satu-per-satu (magic, header,
    chunk..., sentinel, trailer). Cocok untuk dialirkan langsung ke socket
    tanpa memuat seluruh file. Mengembalikan metadata lewat atribut generator
    (transfer_id, sha256) setelah selesai — pakai lewat `info` dict.
    """
    filesize = os.path.getsize(src_path)
    filename = os.path.basename(src_path)
    enc = cc.HybridEncryptor(identity.priv, identity.pub, identity.fingerprint,
                             recipient_pub, recipient_fp, filename, filesize, chunk_size)
    header = enc.begin()
    header["sender_cert"] = identity.cert_pem       # <-- identitas PKI pengirim
    header["sender_username"] = identity.username

    info = {"transfer_id": header["transfer_id"], "filename": filename,
            "filesize": filesize, "sha256": None}

    def gen():
        yield MAGIC
        yield _pack(json.dumps(header).encode())
        n = (filesize + chunk_size - 1) // chunk_size or 1
        with open(src_path, "rb") as fin:
            for i in range(n):
                plain = fin.read(chunk_size)
                yield _pack(enc.encrypt_chunk(plain, is_last=(i == n - 1)))
        yield _pack(b"")                            # sentinel
        trailer = enc.finish()
        info["sha256"] = trailer["sha256"]
        yield _pack(json.dumps(trailer).encode())

    return gen(), info


def encrypt_to_file(src_path, dst_path, identity, recipient_pub=None, recipient_fp=None,
                    chunk_size=cc.DEFAULT_CHUNK):
    """Enkripsi src -> file .sdrop di disk (dipakai brankas). recipient default = diri sendiri."""
    r_pub = recipient_pub or identity.pub
    r_fp = recipient_fp or identity.fingerprint
    gen, info = encrypt_stream(src_path, identity, r_pub, r_fp, chunk_size)
    with open(dst_path, "wb") as out:
        for seg in gen:
            out.write(seg)
    return info


# ============================================================
#  DEKRIPSI — dari file .sdrop di disk (hemat memori)
# ============================================================
def decrypt_file(src_path, out_path, identity, ca_cert_pem=None):
    """
    Buka kontainer .sdrop -> tulis plaintext ke out_path. Verifikasi:
      - integritas (tag GCM tiap chunk + SHA-256 keseluruhan),
      - tanda tangan RSA-PSS pengirim (non-repudiation),
      - identitas pengirim via rantai sertifikat ke CA (authentication PKI).
    Mengembalikan dict indikator keamanan.
    """
    with open(src_path, "rb") as fin:
        if fin.read(len(MAGIC)) != MAGIC:
            raise ValueError("Bukan kontainer SecureDrop yang valid.")
        header = json.loads(_read_frame(fin).decode())
        dec = cc.HybridDecryptor(header, identity.priv, identity.fingerprint)
        filesize = header["filesize"]
        written = 0
        with open(out_path, "wb") as fout:
            while True:
                frame = _read_frame(fin)
                if frame == b"":
                    break
                is_last = (filesize - written - (len(frame) - cc.GCM_TAG_LEN)) <= 0
                plain = dec.decrypt_chunk(frame, is_last)
                fout.write(plain)
                written += len(plain)
        trailer = json.loads(_read_frame(fin).decode())

    sender_pub = cc.load_public_pem(header["sender_pubkey"].encode())
    result = dec.verify(trailer, sender_pub)        # integrity + signature

    # ── Authentication via PKI ──
    sender_cert = header.get("sender_cert")
    sender_username = header.get("sender_username", "")
    auth_ok = False
    auth_reason = "tanpa sertifikat pengirim"
    if sender_cert and ca_cert_pem:
        chain_ok, auth_reason = pki.verify_chain(sender_cert, ca_cert_pem)
        if chain_ok:
            cert = pki.load_cert(sender_cert)
            # kunci di sertifikat harus == kunci yang menandatangani file
            same_key = pki.cert_fingerprint(cert) == cc.fingerprint(sender_pub)
            cn = pki.cert_common_name(cert)
            if not same_key:
                auth_ok, auth_reason = False, "kunci sertifikat ≠ kunci penandatangan file"
            elif sender_username and cn != sender_username:
                auth_ok, auth_reason = False, "nama pada sertifikat tak cocok"
            else:
                auth_ok = True
                auth_reason = f"identitas '{cn}' terverifikasi via CA"
                sender_username = cn
    result.update({
        "out_path": out_path,
        "filename": os.path.basename(header["filename"]),
        "sender_username": sender_username,
        "authenticated": auth_ok,
        "auth_reason": auth_reason,
        "transfer_id": header["transfer_id"],
    })
    return result


def peek_header(src_path):
    """Baca header kontainer tanpa mendekripsi (untuk preview)."""
    with open(src_path, "rb") as fin:
        if fin.read(len(MAGIC)) != MAGIC:
            raise ValueError("Bukan kontainer SecureDrop.")
        return json.loads(_read_frame(fin).decode())
