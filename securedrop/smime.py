# ============================================================
# smime.py  —  S/MIME (Secure/MIME) di atas PKI SecureDrop
# ------------------------------------------------------------
# S/MIME = memakai sertifikat X.509 untuk MENANDATANGANI dan
# MENGENKRIPSI pesan MIME memakai CMS/PKCS#7. Karena CA kita
# sudah menerbitkan sertifikat X.509 (lihat pki.py), sertifikat
# itu langsung dipakai untuk S/MIME yang ASLI & interoperabel
# (bisa dibuka OpenSSL, Outlook, Thunderbird, Apple Mail).
#
# Alur standar S/MIME "sign-then-encrypt":
#   pesan MIME  ──sign(kunci pengirim)──►  SignedData (CMS)
#               ──encrypt(sertifikat penerima)──►  EnvelopedData (CMS)
#               ──►  email .eml  (application/pkcs7-mime; enveloped-data)
#
# Empat aspek keamanan yang dipenuhi:
#   Kerahasiaan   : EnvelopedData (AES-256-CBC, kunci dibungkus RSA)
#   Integritas    : messageDigest dalam SignedData
#   Autentikasi   : sertifikat penanda-tangan diverifikasi ke CA
#   Nir-sangkal   : tanda tangan RSA pengirim atas signedAttrs
#
# Library `cryptography` menyediakan sign/encrypt/decrypt CMS,
# tapi TIDAK mengekspos verifikasi tanda tangan CMS. Maka di sini
# ada verifier CMS SignedData pure-python (parser DER minimal) —
# supaya modul mandiri tanpa openssl saat runtime.
# ============================================================
from __future__ import annotations

import email
import email.utils
from email.message import EmailMessage
from email import message_from_bytes
from email.policy import default as default_policy

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding

import pki

# ── OID yang dipakai ───────────────────────────────────────
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
HASH_BY_OID = {
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
    "1.3.14.3.2.26": hashes.SHA1,
}


# ============================================================
#  1) OPERASI CMS/PKCS#7  (memakai library — hasil asli)
# ============================================================
def sign(data: bytes, signer_cert, signer_key) -> bytes:
    """Tanda tangani `data` -> SignedData DER (attached, signer cert disertakan)."""
    return (pkcs7.PKCS7SignatureBuilder()
            .set_data(data)
            .add_signer(signer_cert, signer_key, hashes.SHA256())
            .sign(Encoding.DER, [pkcs7.PKCS7Options.Binary]))


def encrypt(data: bytes, recipient_certs: list) -> bytes:
    """Enkripsi `data` untuk satu/lebih penerima -> EnvelopedData DER (AES-256-CBC)."""
    b = pkcs7.PKCS7EnvelopeBuilder().set_data(data)
    for c in recipient_certs:
        b = b.add_recipient(c)
    b = b.set_content_encryption_algorithm(algorithms.AES256)
    return b.encrypt(Encoding.DER, [pkcs7.PKCS7Options.Binary])


def sign_and_encrypt(data: bytes, signer_cert, signer_key, recipient_certs: list) -> bytes:
    return encrypt(sign(data, signer_cert, signer_key), recipient_certs)


def decrypt(enveloped_der: bytes, cert, key) -> bytes:
    """Buka EnvelopedData dengan kunci privat penerima -> data di dalamnya."""
    return pkcs7.pkcs7_decrypt_der(enveloped_der, cert, key, [])


# ============================================================
#  2) VERIFIKASI SignedData  (parser DER minimal, pure-python)
# ============================================================
def _read_len(buf, i):
    first = buf[i]; i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    return int.from_bytes(buf[i:i + n], "big"), i + n


def _tlv(buf, i):
    tag = buf[i]
    length, j = _read_len(buf, i + 1)
    vstart, vend = j, j + length
    return {"tag": tag, "raw": buf[i:vend], "value": buf[vstart:vend]}, vend


def _children(value: bytes):
    out, i = [], 0
    while i < len(value):
        node, i = _tlv(value, i)
        out.append(node)
    return out


def _oid(value: bytes) -> str:
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    n = 0
    for c in value[1:]:
        n = (n << 7) | (c & 0x7F)
        if not (c & 0x80):
            parts.append(str(n)); n = 0
    return ".".join(parts)


def _hash(data: bytes, algo) -> bytes:
    h = hashes.Hash(algo()); h.update(data); return h.finalize()


def _match_signer(certs, sid_node):
    """Pilih sertifikat penanda-tangan berdasar issuerAndSerialNumber."""
    if len(certs) == 1:
        return certs[0]
    if sid_node["tag"] == 0x30:  # SEQUENCE issuerAndSerialNumber
        kids = _children(sid_node["value"])
        serial = int.from_bytes(kids[1]["value"], "big")
        for c in certs:
            if c.serial_number == serial:
                return c
    return certs[0] if certs else None


def verify_signed(signed_der: bytes, ca_cert_pem: str) -> dict:
    """
    Verifikasi CMS SignedData:
      - integritas (messageDigest == hash(konten)),
      - tanda tangan RSA pengirim (nir-sangkal),
      - rantai sertifikat penanda-tangan ke CA (autentikasi).
    Mengembalikan dict berisi konten + status keamanan.
    """
    ci, _ = _tlv(signed_der, 0)                       # ContentInfo SEQUENCE
    ci_kids = _children(ci["value"])
    if _oid(ci_kids[0]["value"]) != OID_SIGNED_DATA:
        raise ValueError("Bukan CMS SignedData.")
    sd_seq = _children(ci_kids[1]["value"])[0]        # [0] EXPLICIT -> SignedData SEQUENCE
    sd = _children(sd_seq["value"])

    # sd: version, digestAlgorithms SET, encapContentInfo, [0]certs?, [1]crls?, signerInfos SET
    encap = sd[2]
    signer_infos = None
    for node in sd[3:]:
        if node["tag"] == 0x31:
            signer_infos = node
    enc_kids = _children(encap["value"])
    content = b""
    if len(enc_kids) > 1 and enc_kids[1]["tag"] == 0xA0:   # [0] EXPLICIT OCTET STRING
        content = _children(enc_kids[1]["value"])[0]["value"]

    certs = pkcs7.load_der_pkcs7_certificates(signed_der)
    si = _children(_children(signer_infos["value"])[0]["value"])
    # si: version, sid, digestAlgorithm, [0]signedAttrs?, sigAlg, signature, [1]?
    sid = si[1]
    dalg_oid = _oid(_children(si[2]["value"])[0]["value"])
    algo = HASH_BY_OID.get(dalg_oid, hashes.SHA256)
    k = 3
    signed_attrs = None
    if si[k]["tag"] == 0xA0:
        signed_attrs = si[k]; k += 1
    sig_alg = si[k]; k += 1               # noqa: F841 (rsaEncryption diasumsikan)
    signature = si[k]["value"]

    signer_cert = _match_signer(certs, sid)
    if signer_cert is None:
        raise ValueError("Sertifikat penanda-tangan tidak ada dalam pesan.")

    # ── integritas: messageDigest attr == hash(content) ──
    digest = _hash(content, algo)
    integrity_ok = False
    if signed_attrs is not None:
        for attr in _children(signed_attrs["value"]):
            ac = _children(attr["value"])
            if _oid(ac[0]["value"]) == OID_MESSAGE_DIGEST:
                md = _children(ac[1]["value"])[0]["value"]
                integrity_ok = (md == digest)
        # tanda tangan dihitung atas DER signedAttrs yang di-tag ulang jadi SET OF (0x31)
        to_verify = bytearray(signed_attrs["raw"]); to_verify[0] = 0x31
        to_verify = bytes(to_verify)
    else:
        to_verify = content
        integrity_ok = True

    # ── nir-sangkal: verifikasi tanda tangan RSA pengirim ──
    signature_ok = False
    try:
        signer_cert.public_key().verify(signature, to_verify, padding.PKCS1v15(), algo())
        signature_ok = True
    except Exception:
        signature_ok = False

    # ── autentikasi: rantai sertifikat ke CA ──
    signer_pem = signer_cert.public_bytes(Encoding.PEM).decode()
    chain_ok, chain_reason = pki.verify_chain(signer_pem, ca_cert_pem)
    cn = pki.cert_common_name(signer_cert)
    email_san = _cert_email(signer_cert)

    return {
        "content": content,
        "signer_cn": cn,
        "signer_email": email_san,
        "integrity_ok": integrity_ok,
        "signature_ok": signature_ok,
        "authenticated": chain_ok,
        "auth_reason": chain_reason,
    }


def _cert_email(cert):
    try:
        from cryptography import x509
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        emails = san.get_values_for_type(x509.RFC822Name)
        return emails[0] if emails else ""
    except Exception:
        return ""


# ============================================================
#  3) LAPISAN MIME (email dengan lampiran)
# ============================================================
def build_mime(from_addr, to_addrs, subject, body_text, attachments=None) -> bytes:
    """Bangun satu pesan MIME (RFC 5322) berisi teks + lampiran."""
    m = EmailMessage()
    m["From"] = from_addr
    m["To"] = ", ".join(to_addrs)
    m["Subject"] = subject
    m["Date"] = email.utils.formatdate(localtime=True)
    m.set_content(body_text or "")
    for att in (attachments or []):
        name, data, mime = att["name"], att["data"], att.get("mime", "application/octet-stream")
        maintype, _, subtype = mime.partition("/")
        m.add_attachment(data, maintype=maintype or "application",
                         subtype=subtype or "octet-stream", filename=name)
    return m.as_bytes()


def parse_mime(raw: bytes) -> dict:
    """Uraikan pesan MIME -> header, body teks, dan lampiran."""
    m = message_from_bytes(raw, policy=default_policy)
    body, atts = "", []
    if m.is_multipart():
        for part in m.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_filename() or part.get_content_disposition() == "attachment":
                payload = part.get_content()
                if isinstance(payload, str):
                    payload = payload.encode()
                atts.append({"name": part.get_filename(),
                             "data": payload, "mime": part.get_content_type()})
            elif part.get_content_type() == "text/plain" and not body:
                body = part.get_content()
    else:
        body = m.get_content()
    return {"from": m["From"], "to": m["To"], "subject": m["Subject"],
            "date": m["Date"], "body": body, "attachments": atts}


# ============================================================
#  4) API TINGKAT-TINGGI: segel & buka email S/MIME (.eml)
# ============================================================
def seal_email(sender_email, sender_cert, sender_key,
               recipients, subject, body, attachments=None) -> bytes:
    """
    Hasilkan email S/MIME terenkripsi (.eml, application/pkcs7-mime;
    smime-type=enveloped-data). `recipients` = list of (email, cert).
    """
    to_addrs = [r[0] for r in recipients]
    recipient_certs = [r[1] for r in recipients]
    inner = build_mime(sender_email, to_addrs, subject, body, attachments)
    enveloped = sign_and_encrypt(inner, sender_cert, sender_key, recipient_certs)

    out = EmailMessage()
    out["From"] = sender_email
    out["To"] = ", ".join(to_addrs)
    out["Subject"] = subject
    out["Date"] = email.utils.formatdate(localtime=True)
    out.set_content(enveloped, maintype="application", subtype="pkcs7-mime",
                    cte="base64", disposition="attachment", filename="smime.p7m",
                    params={"smime-type": "enveloped-data", "name": "smime.p7m"})
    return out.as_bytes()


def open_email(eml_bytes: bytes, my_cert, my_key, ca_cert_pem: str) -> dict:
    """Buka email S/MIME: dekripsi -> verifikasi tanda tangan -> uraikan MIME dalam."""
    outer = message_from_bytes(eml_bytes, policy=default_policy)
    p7m = None
    for part in outer.walk():
        if part.get_content_type() in ("application/pkcs7-mime", "application/x-pkcs7-mime"):
            p7m = part.get_content()
            break
    if p7m is None:
        raise ValueError("Bukan email S/MIME (tidak ada bagian pkcs7-mime).")
    if isinstance(p7m, str):
        p7m = p7m.encode()

    signed = decrypt(p7m, my_cert, my_key)          # buka amplop
    ver = verify_signed(signed, ca_cert_pem)        # verifikasi tanda tangan
    inner = parse_mime(ver["content"])              # uraikan pesan asli

    return {
        **inner,
        "security": {
            "confidentiality": True,                # sampai di sini berarti amplop terbuka
            "integrity": ver["integrity_ok"],
            "authentication": ver["authenticated"],
            "non_repudiation": ver["signature_ok"],
            "signer_cn": ver["signer_cn"],
            "signer_email": ver["signer_email"],
            "reason": ver["auth_reason"],
        },
    }
