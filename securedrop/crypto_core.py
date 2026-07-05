# ============================================================
# crypto_core.py
# ------------------------------------------------------------
# Inti kriptografi aplikasi. Semua operasi kunci publik/privat,
# enkripsi hibrida (RSA + AES-256-GCM), tanda tangan digital,
# dan verifikasi integritas ada di sini.
#
# Skema (gaya PGP / model WhatsApp end-to-end):
#   1. Tiap node punya sepasang kunci RSA (publik + privat).
#   2. Untuk tiap file, dibuat "kunci sesi" AES-256 acak.
#   3. File dienkripsi AES-256-GCM secara CHUNKED (potong-potong),
#      supaya file berapa pun besarnya (>3GB) tetap muat di memori
#      kecil — kita tidak pernah memuat seluruh file sekaligus.
#   4. Kunci sesi dibungkus (RSA-OAEP) DUA kali: dengan public key
#      penerima DAN public key pengirim. Jadi pengirim juga bisa
#      membuka kembali file terenkripsinya sendiri (poin "modelan WA").
#   5. Seluruh isi file di-hash SHA-256 lalu DITANDATANGANI RSA-PSS
#      oleh pengirim -> memberi Integrity + Non-repudiation.
#
# Kenapa RSA?  Satu pasang kunci untuk dua peran: OAEP (membungkus
#              kunci) dan PSS (menandatangani). Matang & mudah dijelaskan.
# Kenapa AES-256-GCM?  Cepat (AES-NI), sekaligus AEAD: menghasilkan
#              tag otentikasi -> integritas tiap chunk gratis.
# ============================================================

import os
import json
import struct
import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature

# ── Konstanta protokol ─────────────────────────────────────
RSA_KEY_SIZE = 2048          # ukuran kunci RSA (bit)
AES_KEY_LEN = 32             # 32 byte = AES-256
NONCE_PREFIX_LEN = 4         # 4 byte acak per-file + 8 byte counter = nonce 12 byte
GCM_TAG_LEN = 16
DEFAULT_CHUNK = 4 * 1024 * 1024   # 4 MB per chunk (kompromi kecepatan vs memori)

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# ── Manajemen kunci RSA ────────────────────────────────────
def generate_keypair(key_size: int = RSA_KEY_SIZE):
    """Buat pasangan kunci RSA baru (private, public)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return priv, priv.public_key()


def private_to_pem(priv, passphrase: str | None = None) -> bytes:
    enc = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase else serialization.NoEncryption()
    )
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def public_to_pem(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_pem(pem: bytes, passphrase: str | None = None):
    return serialization.load_pem_private_key(
        pem, password=passphrase.encode() if passphrase else None
    )


def load_public_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


def fingerprint(pub) -> str:
    """
    Fingerprint = SHA-256 dari DER SubjectPublicKeyInfo, ditampilkan
    berpasangan hex dipisah titik dua (mirip 'safety number' WhatsApp).
    Dipakai untuk verifikasi identitas peer secara out-of-band.
    """
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def short_fp(fp: str) -> str:
    """Ambil 8 grup pertama fingerprint untuk ditampilkan ringkas."""
    return ":".join(fp.split(":")[:8])


# ── Header & AAD ───────────────────────────────────────────
def _aad(transfer_id: bytes, counter: int, is_last: bool) -> bytes:
    """
    Additional Authenticated Data untuk tiap chunk. Mengikat chunk ke:
    - transfer_id (tak bisa dipindah ke transfer lain),
    - counter (urutan; mencegah chunk ditukar posisinya),
    - is_last (mencegah ekor stream dipotong tanpa ketahuan).
    Bila salah satu diutak-atik, verifikasi tag GCM gagal.
    """
    return transfer_id + struct.pack(">Q", counter) + (b"\x01" if is_last else b"\x00")


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">Q", counter)


@dataclass
class EncryptResult:
    header: dict
    sha256: str
    signature_b64: str


class HybridEncryptor:
    """
    Enkripsi file secara streaming. Pemakaian:
        enc = HybridEncryptor(sender_priv, sender_pub, sender_fp,
                              recipient_pub, recipient_fp, filename, filesize)
        header = enc.begin()                      # kirim header lebih dulu
        for plain_chunk in baca_file():
            frame = enc.encrypt_chunk(plain_chunk, is_last)  # kirim tiap frame
        trailer = enc.finish()                    # kirim trailer (sha256+signature)
    """

    def __init__(self, sender_priv, sender_pub, sender_fp,
                 recipient_pub, recipient_fp, filename, filesize,
                 chunk_size=DEFAULT_CHUNK):
        self.sender_priv = sender_priv
        self.sender_pub = sender_pub
        self.sender_fp = sender_fp
        self.recipient_fp = recipient_fp
        self.filename = filename
        self.filesize = filesize
        self.chunk_size = chunk_size

        # Rahasia per-file
        self.session_key = os.urandom(AES_KEY_LEN)
        self.nonce_prefix = os.urandom(NONCE_PREFIX_LEN)
        self.transfer_id = os.urandom(16)
        self._aes = AESGCM(self.session_key)
        self._counter = 0
        self._hash = hashlib.sha256()

        # Bungkus kunci sesi ke penerima DAN pengirim (encrypt-to-self)
        self.wrapped = {
            recipient_fp: b64e(recipient_pub.encrypt(self.session_key, OAEP)),
            sender_fp: b64e(sender_pub.encrypt(self.session_key, OAEP)),
        }

    def begin(self) -> dict:
        return {
            "version": 1,
            "transfer_id": self.transfer_id.hex(),
            "alg": "RSA-OAEP-SHA256 + AES-256-GCM + RSA-PSS-SHA256",
            "filename": self.filename,
            "filesize": self.filesize,
            "chunk_size": self.chunk_size,
            "nonce_prefix": self.nonce_prefix.hex(),
            "sender_fingerprint": self.sender_fp,
            "sender_pubkey": public_to_pem(self.sender_pub).decode(),
            "recipient_fingerprint": self.recipient_fp,
            "wrapped_keys": self.wrapped,
        }

    def encrypt_chunk(self, plaintext: bytes, is_last: bool) -> bytes:
        self._hash.update(plaintext)
        nonce = _nonce(self.nonce_prefix, self._counter)
        aad = _aad(self.transfer_id, self._counter, is_last)
        ct = self._aes.encrypt(nonce, plaintext, aad)  # ct berisi ciphertext+tag
        self._counter += 1
        return ct

    def finish(self) -> dict:
        digest = self._hash.digest()
        # Tanda tangan atas (transfer_id || sha256) supaya terikat ke transfer ini
        signature = self.sender_priv.sign(self.transfer_id + digest, PSS, hashes.SHA256())
        return {"sha256": digest.hex(), "signature": b64e(signature)}


class HybridDecryptor:
    """
    Dekripsi streaming di sisi penerima (atau pengirim yang membuka file
    terenkripsinya sendiri). Memverifikasi tag GCM tiap chunk, SHA-256
    keseluruhan, dan tanda tangan RSA-PSS pengirim.
    """

    def __init__(self, header: dict, my_priv, my_fp):
        self.header = header
        self.transfer_id = bytes.fromhex(header["transfer_id"])
        self.nonce_prefix = bytes.fromhex(header["nonce_prefix"])
        self.sender_fp = header["sender_fingerprint"]

        wrapped = header["wrapped_keys"]
        if my_fp not in wrapped:
            raise PermissionError("File ini tidak ditujukan untuk kunci Anda.")
        self.session_key = my_priv.decrypt(b64d(wrapped[my_fp]), OAEP)
        self._aes = AESGCM(self.session_key)
        self._counter = 0
        self._hash = hashlib.sha256()
        self.saw_last = False

    def prime_from_partial(self, plaintext: bytes, chunks_done: int):
        """Untuk RESUME: pulihkan state hash & counter dari data yang sudah diterima."""
        self._hash.update(plaintext)
        self._counter = chunks_done

    def decrypt_chunk(self, frame: bytes, is_last: bool) -> bytes:
        nonce = _nonce(self.nonce_prefix, self._counter)
        aad = _aad(self.transfer_id, self._counter, is_last)
        try:
            plain = self._aes.decrypt(nonce, frame, aad)   # raise InvalidTag bila rusak
        except InvalidTag:
            raise InvalidTag(f"Integritas chunk #{self._counter} gagal (tag GCM tidak cocok).")
        self._hash.update(plain)
        self._counter += 1
        if is_last:
            self.saw_last = True
        return plain

    def verify(self, trailer: dict, sender_pub) -> dict:
        """Verifikasi hash + tanda tangan. Kembalikan indikator keamanan."""
        if not self.saw_last:
            raise InvalidTag("Chunk terakhir tidak ada — stream terpotong.")
        digest = self._hash.digest()
        integrity_ok = (digest.hex() == trailer["sha256"])
        try:
            sender_pub.verify(
                b64d(trailer["signature"]),
                self.transfer_id + digest, PSS, hashes.SHA256(),
            )
            signature_ok = True
        except InvalidSignature:
            signature_ok = False
        return {
            "integrity_ok": integrity_ok,
            "signature_ok": signature_ok,
            "sha256": digest.hex(),
            "sender_fingerprint": self.sender_fp,
        }


# ── Delivery receipt (bukti terkirim, memperkuat non-repudiation) ──
def make_receipt(receiver_priv, transfer_id_hex: str, sha256_hex: str) -> str:
    msg = bytes.fromhex(transfer_id_hex) + bytes.fromhex(sha256_hex)
    sig = receiver_priv.sign(msg, PSS, hashes.SHA256())
    return b64e(sig)


def verify_receipt(receiver_pub, transfer_id_hex: str, sha256_hex: str, sig_b64: str) -> bool:
    msg = bytes.fromhex(transfer_id_hex) + bytes.fromhex(sha256_hex)
    try:
        receiver_pub.verify(b64d(sig_b64), msg, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False
