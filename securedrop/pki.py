# ============================================================
# pki.py  —  Public Key Infrastructure (menggantikan TOFU)
# ------------------------------------------------------------
# Inti PKI SecureDrop. Berbeda dengan model lama (TOFU: tukar
# public key manual lalu "tandai aman"), di sini kepercayaan
# didelegasikan ke sebuah CA (Certificate Authority):
#
#   Root CA (self-signed)
#      ├── menandatangani  sertifikat TLS SERVER  (CN=securedrop-server)
#      └── menandatangani  sertifikat tiap KLIEN  (CN=<username>)
#
# Sebuah sertifikat dianggap sah bila DAPAT DIVERIFIKASI rantainya
# sampai ke Root CA yang dipercaya. Tidak perlu lagi mencocokkan
# fingerprint manual: kalau CA menandatangani, identitasnya sah.
#
# Alur penerbitan (standar PKI):
#   1. Klien membuat pasangan kunci + CSR (Certificate Signing Request).
#   2. CSR dikirim ke CA (server) beserta bukti identitas (login).
#   3. CA memverifikasi & menandatangani  ->  mengembalikan sertifikat.
#   4. Klien memakai sertifikat itu untuk mTLS + sebagai identitas E2E.
# ============================================================
from __future__ import annotations

import os
import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import crypto_core as cc

ONE_DAY = datetime.timedelta(days=1)
CA_VALID_DAYS = 3650          # root CA berlaku 10 tahun
LEAF_VALID_DAYS = 825         # sertifikat daun (server/klien) ~2 tahun

SERVER_CN = "securedrop-server"


# ── Nama file standar di folder CA (server) ────────────────
def ca_paths(ca_dir: str) -> dict:
    return {
        "key": os.path.join(ca_dir, "ca_key.pem"),
        "cert": os.path.join(ca_dir, "ca_cert.pem"),
        "srv_key": os.path.join(ca_dir, "server_key.pem"),
        "srv_cert": os.path.join(ca_dir, "server_cert.pem"),
    }


# ============================================================
#  Sisi CA (dijalankan oleh SERVER)
# ============================================================
@dataclass
class CA:
    key: object          # private key CA (RSA)
    cert: x509.Certificate

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()


def create_root_ca(common_name: str = "SecureDrop Root CA") -> CA:
    """Buat Root CA baru (kunci + sertifikat self-signed dengan basicConstraints CA:TRUE)."""
    key, pub = cc.generate_keypair(key_size=3072)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDrop"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                      # self-signed
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - ONE_DAY)
        .not_valid_after(now + datetime.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          key_encipherment=False, content_commitment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .sign(key, hashes.SHA256())
    )
    return CA(key=key, cert=cert)


def load_or_create_ca(ca_dir: str) -> CA:
    """Muat Root CA + sertifikat TLS server dari disk; buat bila belum ada."""
    os.makedirs(ca_dir, exist_ok=True)
    p = ca_paths(ca_dir)
    if os.path.exists(p["key"]) and os.path.exists(p["cert"]):
        key = cc.load_private_pem(open(p["key"], "rb").read())
        cert = x509.load_pem_x509_certificate(open(p["cert"], "rb").read())
        ca = CA(key=key, cert=cert)
    else:
        ca = create_root_ca()
        with open(p["key"], "wb") as f:
            f.write(cc.private_to_pem(ca.key))
        os.chmod(p["key"], 0o600)
        with open(p["cert"], "wb") as f:
            f.write(ca.cert.public_bytes(serialization.Encoding.PEM))

    # Sertifikat TLS untuk server itu sendiri (ditandatangani CA)
    if not (os.path.exists(p["srv_key"]) and os.path.exists(p["srv_cert"])):
        srv_key, srv_pub = cc.generate_keypair(key_size=2048)
        srv_cert = issue_certificate(
            ca, srv_pub, common_name=SERVER_CN, is_server=True,
            san_dns=[SERVER_CN, "localhost"], san_ip=["127.0.0.1"],
        )
        with open(p["srv_key"], "wb") as f:
            f.write(cc.private_to_pem(srv_key))
        os.chmod(p["srv_key"], 0o600)
        with open(p["srv_cert"], "wb") as f:
            f.write(srv_cert.public_bytes(serialization.Encoding.PEM))
    return ca


def issue_certificate(ca: CA, subject_pub, common_name: str,
                      is_server: bool = False,
                      is_smime: bool = False,
                      email: str | None = None,
                      san_dns: list[str] | None = None,
                      san_ip: list[str] | None = None) -> x509.Certificate:
    """CA menandatangani sertifikat daun untuk sebuah public key + nama.

    is_smime=True menambahkan EKU emailProtection + SAN rfc822 (email),
    sehingga sertifikat sah dipakai untuk S/MIME (interoperabel dg OpenSSL,
    Outlook, Thunderbird, dsb).
    """
    import ipaddress
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDrop"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.cert.subject)
        .public_key(subject_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - ONE_DAY)
        .not_valid_after(now + datetime.timedelta(days=LEAF_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True,
                          content_commitment=True, data_encipherment=False,
                          key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_pub), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.cert.public_key()),
            critical=False,
        )
    )
    eku = []
    if is_server:
        eku += [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    else:
        eku += [ExtendedKeyUsageOID.CLIENT_AUTH]
    if is_smime:
        eku.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
    builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

    san = []
    for d in (san_dns or []):
        san.append(x509.DNSName(d))
    for ip in (san_ip or []):
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            pass
    if email:
        san.append(x509.RFC822Name(email))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)

    return builder.sign(ca.key, hashes.SHA256())


def sign_csr(ca: CA, csr_pem: str, common_name: str,
             is_smime: bool = False, email: str | None = None) -> str:
    """
    Verifikasi CSR (tanda tangan pemohon atas kunci publiknya sendiri),
    lalu terbitkan sertifikat klien. CN dipaksa ke `common_name` (username
    hasil login) supaya pemohon tak bisa mengklaim identitas orang lain.
    Bila is_smime, sertifikat juga sah untuk S/MIME.
    """
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("CSR tidak sah (tanda tangan pemohon tidak valid).")
    cert = issue_certificate(ca, csr.public_key(), common_name=common_name,
                             is_smime=is_smime, email=email)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ============================================================
#  Sisi KLIEN
# ============================================================
def make_csr(priv, common_name: str) -> str:
    """Klien membuat CSR untuk kunci privatnya (ditandatangani sendiri)."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(priv, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


# ============================================================
#  Verifikasi rantai (dipakai kedua sisi) — INTI kepercayaan PKI
# ============================================================
def load_cert(cert_pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_pem.encode())


def cert_common_name(cert: x509.Certificate) -> str:
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return ""


def cert_public_key(cert: x509.Certificate):
    return cert.public_key()


def cert_fingerprint(cert: x509.Certificate) -> str:
    """Fingerprint = SHA-256 SPKI kunci publik di sertifikat (identitas E2E)."""
    return cc.fingerprint(cert.public_key())


def verify_chain(cert_pem: str, ca_cert_pem: str) -> tuple[bool, str]:
    """
    Verifikasi bahwa `cert_pem` ditandatangani oleh CA `ca_cert_pem` dan
    masih berlaku. Mengembalikan (ok, alasan). Inilah pengganti TOFU:
    kalau CA menandatangani, kita percaya identitasnya.
    """
    try:
        cert = load_cert(cert_pem)
        ca = load_cert(ca_cert_pem)
    except Exception as e:
        return False, f"Sertifikat rusak: {e}"

    # 1) Masa berlaku
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        nvb = cert.not_valid_before_utc
        nva = cert.not_valid_after_utc
    except AttributeError:  # cryptography lama
        nvb = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        nva = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if now < nvb:
        return False, "Sertifikat belum berlaku."
    if now > nva:
        return False, "Sertifikat kedaluwarsa."

    # 2) Issuer harus subject CA
    if cert.issuer != ca.subject:
        return False, "Penerbit sertifikat bukan CA yang dipercaya."

    # 3) Tanda tangan CA atas sertifikat (verifikasi kriptografis)
    try:
        ca_pub = ca.public_key()
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"Tanda tangan CA tidak valid: {e}"

    return True, "Rantai sertifikat sah (ditandatangani CA)."
