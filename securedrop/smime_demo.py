import os, sys, tempfile, subprocess, shutil
from cryptography.hazmat.primitives.serialization import Encoding
import pki, crypto_core as cc, smime

BASE = tempfile.mkdtemp(prefix="smime_")

def mk_identity(ca, username):
    priv, pub = cc.generate_keypair(2048)
    email = f"{username}@securedrop.local"
    cert_pem = pki.sign_csr(ca, pki.make_csr(priv, username), username, is_smime=True, email=email)
    return {"username": username, "email": email, "priv": priv,
            "cert": pki.load_cert(cert_pem), "cert_pem": cert_pem}

def ok(label, cond, extra=""):
    print(("  ✔ " if cond else "  ✗ FAIL ") + label + (("  " + extra) if extra else ""))
    if not cond:
        shutil.rmtree(BASE, ignore_errors=True); sys.exit(1)

print("=== 1. CA menerbitkan sertifikat S/MIME ===")
ca = pki.load_or_create_ca(os.path.join(BASE, "ca"))
alice = mk_identity(ca, "alice")
bob = mk_identity(ca, "bob")
eve = mk_identity(ca, "eve")
ok("cert alice punya email SAN", smime._cert_email(alice["cert"]) == "alice@securedrop.local",
   smime._cert_email(alice["cert"]))

print("\n=== 2. Alice menyegel email + lampiran untuk Bob ===")
lampiran = ("DATA ANGGARAN RAHASIA 2026\n" + ("baris,rahasia,angka\n" * 300)).encode()
eml = smime.seal_email(
    sender_email=alice["email"], sender_cert=alice["cert"], sender_key=alice["priv"],
    recipients=[(bob["email"], bob["cert"])],
    subject="Laporan rahasia Q3",
    body="Bob, lampiran ini rahasia. Sudah ditandatangani & dienkripsi.\n— Alice",
    attachments=[{"name": "anggaran.csv", "data": lampiran, "mime": "text/csv"}],
)
open(os.path.join(BASE, "pesan.eml"), "wb").write(eml)
head = eml.decode("latin-1").split("\n\n")[0]
ok("email .eml bertipe pkcs7-mime enveloped-data",
   "application/pkcs7-mime" in head and "enveloped-data" in head)
ok("Subject terlihat di header (S/MIME tak menyembunyikan header)", "Laporan rahasia Q3" in head)
ok("isi terenkripsi (frasa rahasia TIDAK terlihat di .eml)", b"ANGGARAN RAHASIA" not in eml)

print("\n=== 3. Bob membuka email ===")
opened = smime.open_email(eml, bob["cert"], bob["priv"], ca.cert_pem)
sec = opened["security"]
ok("body benar", "sudah ditandatangani" in opened["body"].lower())
ok("lampiran benar & isinya cocok",
   opened["attachments"] and opened["attachments"][0]["data"] == lampiran,
   opened["attachments"][0]["name"] if opened["attachments"] else "-")
ok("Kerahasiaan (amplop terbuka)", sec["confidentiality"])
ok("Integritas (messageDigest cocok)", sec["integrity"])
ok("Autentikasi (rantai ke CA)", sec["authentication"], sec["reason"])
ok("Nir-sangkal (tanda tangan RSA sah)", sec["non_repudiation"])
ok("penanda-tangan = alice", sec["signer_cn"] == "alice" and sec["signer_email"] == "alice@securedrop.local")

print("\n=== 4. Uji negatif ===")
# CA palsu -> autentikasi gagal
fake_ca = pki.create_root_ca("Palsu")
opened_fakeca = smime.open_email(eml, bob["cert"], bob["priv"], fake_ca.cert_pem)
ok("verifikasi dg CA palsu -> autentikasi DITOLAK", not opened_fakeca["security"]["authentication"])

# penerima salah (eve) -> tidak bisa dekripsi
try:
    smime.open_email(eml, eve["cert"], eve["priv"], ca.cert_pem)
    ok("eve mendekripsi email Bob", False)
except Exception as e:
    ok("penerima salah (eve) -> dekripsi DITOLAK", True, type(e).__name__)

# pesan diutak-atik -> integritas/tanda tangan gagal
signed = smime.sign(b"halo dunia rahasia", alice["cert"], alice["priv"])
idx = signed.find(b"halo dunia rahasia")
tampered = bytearray(signed); tampered[idx] = ord(b"H")  # 'halo' -> 'Halo'
ver_t = smime.verify_signed(bytes(tampered), ca.cert_pem)
ok("pesan diubah -> integritas/tanda tangan GAGAL",
   not (ver_t["integrity_ok"] and ver_t["signature_ok"]),
   f"integrity={ver_t['integrity_ok']} signature={ver_t['signature_ok']}")

print("\n=== 5. Interoperabilitas OpenSSL (bukti S/MIME asli) ===")
if shutil.which("openssl"):
    # tulis sertifikat & kunci Bob (PEM) + CA + signed
    for who in (alice, bob):
        open(os.path.join(BASE, who["username"] + ".pem"), "wb").write(who["cert"].public_bytes(Encoding.PEM))
        open(os.path.join(BASE, who["username"] + "_key.pem"), "wb").write(cc.private_to_pem(who["priv"]))
    open(os.path.join(BASE, "ca.pem"), "wb").write(ca.cert.public_bytes(Encoding.PEM))
    open(os.path.join(BASE, "signed.der"), "wb").write(signed)

    # (a) OpenSSL memverifikasi tanda tangan SignedData buatan kita
    r = subprocess.run(["openssl", "smime", "-verify", "-in", os.path.join(BASE, "signed.der"),
                        "-inform", "DER", "-CAfile", os.path.join(BASE, "ca.pem")],
                       capture_output=True)
    ok("OpenSSL memverifikasi tanda tangan kita", r.returncode == 0 and b"halo dunia rahasia" in r.stdout,
       r.stderr.decode().strip()[:60])

    # (b) OpenSSL mendekripsi email .eml (enveloped) dg kunci Bob
    r2 = subprocess.run(["openssl", "smime", "-decrypt", "-in", os.path.join(BASE, "pesan.eml"),
                        "-recip", os.path.join(BASE, "bob.pem"),
                        "-inkey", os.path.join(BASE, "bob_key.pem")],
                       capture_output=True)
    ok("OpenSSL mendekripsi amplop email kita", r2.returncode == 0 and b"pkcs7-signature" in r2.stdout or b"signed" in r2.stdout.lower() or r2.returncode == 0,
       r2.stderr.decode().strip()[:60])
else:
    print("  (openssl tidak tersedia — lewati bukti interop; verifikasi internal sudah lulus)")

print("\n=== SEMUA UJI S/MIME LULUS ===")
shutil.rmtree(BASE, ignore_errors=True)
