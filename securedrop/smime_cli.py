#!/usr/bin/env python3
# ============================================================
# smime_cli.py  —  Alat baris-perintah S/MIME SecureDrop
# ------------------------------------------------------------
# Contoh alur:
#   python smime_cli.py init
#   python smime_cli.py issue alice
#   python smime_cli.py issue bob
#   python smime_cli.py seal --from alice --to bob \
#          --subject "Halo" --body "pesan rahasia" \
#          --attach anggaran.csv --out pesan.eml
#   python smime_cli.py open --as bob --in pesan.eml --save-dir ./keluar
#
# Semua data (CA + identitas) disimpan di ./smime_data/.
# File .eml yang dihasilkan adalah S/MIME ASLI (bisa dibuka
# OpenSSL/Outlook/Thunderbird bila diberi sertifikat penerima).
# ============================================================
import os
import sys
import json
import argparse

from cryptography.hazmat.primitives.serialization import Encoding

import pki
import crypto_core as cc
import smime

DATA = os.environ.get("SMIME_DATA", "./smime_data")
CA_DIR = os.path.join(DATA, "ca")


def _idir(name):
    return os.path.join(DATA, "id", name)


def _load_ca():
    if not os.path.exists(pki.ca_paths(CA_DIR)["cert"]):
        sys.exit("CA belum ada. Jalankan: python smime_cli.py init")
    return pki.load_or_create_ca(CA_DIR)


def _load_identity(name):
    d = _idir(name)
    kp = os.path.join(d, "key.pem")
    cp = os.path.join(d, "cert.pem")
    if not (os.path.exists(kp) and os.path.exists(cp)):
        sys.exit(f"Identitas '{name}' tidak ada. Jalankan: python smime_cli.py issue {name}")
    priv = cc.load_private_pem(open(kp, "rb").read())
    cert = pki.load_cert(open(cp).read())
    meta = json.load(open(os.path.join(d, "meta.json")))
    return {"name": name, "email": meta["email"], "priv": priv, "cert": cert}


def cmd_init(args):
    os.makedirs(DATA, exist_ok=True)
    ca = pki.load_or_create_ca(CA_DIR)
    print("CA siap di", os.path.abspath(CA_DIR))
    print("Fingerprint Root CA:", pki.cert_fingerprint(ca.cert))


def cmd_issue(args):
    ca = _load_ca()
    name = args.username
    email = args.email or f"{name}@securedrop.local"
    d = _idir(name)
    os.makedirs(d, exist_ok=True)
    priv, _ = cc.generate_keypair(2048)
    cert_pem = pki.sign_csr(ca, pki.make_csr(priv, name), name, is_smime=True, email=email)
    open(os.path.join(d, "key.pem"), "wb").write(cc.private_to_pem(priv))
    os.chmod(os.path.join(d, "key.pem"), 0o600)
    open(os.path.join(d, "cert.pem"), "w").write(cert_pem)
    open(os.path.join(d, "meta.json"), "w").write(json.dumps({"email": email}))
    print(f"Identitas S/MIME '{name}' <{email}> diterbitkan.")
    print("Fingerprint:", pki.cert_fingerprint(pki.load_cert(cert_pem)))


def cmd_seal(args):
    sender = _load_identity(getattr(args, "from"))
    recips = []
    for to in args.to:
        r = _load_identity(to)
        recips.append((r["email"], r["cert"]))
    attachments = []
    for path in (args.attach or []):
        attachments.append({"name": os.path.basename(path),
                            "data": open(path, "rb").read(),
                            "mime": "application/octet-stream"})
    body = args.body
    if args.body_file:
        body = open(args.body_file, encoding="utf-8").read()
    eml = smime.seal_email(sender["email"], sender["cert"], sender["priv"],
                           recips, args.subject or "(tanpa subjek)", body or "", attachments)
    open(args.out, "wb").write(eml)
    print(f"Email S/MIME tersegel -> {args.out} ({len(eml)} byte)")
    print(f"Dari {sender['email']}  ke {', '.join(t for t in args.to)}  · {len(attachments)} lampiran")


def cmd_open(args):
    me = _load_identity(getattr(args, "as"))
    ca = _load_ca()
    eml = open(args.__dict__["in"], "rb").read()
    res = smime.open_email(eml, me["cert"], me["priv"], ca.cert_pem)
    s = res["security"]
    def mark(b): return "✔" if b else "✗"
    print("─" * 52)
    print("Dari    :", res["from"])
    print("Ke      :", res["to"])
    print("Subjek  :", res["subject"])
    print("Tanggal :", res["date"])
    print("─" * 52)
    print(res["body"])
    print("─" * 52)
    print(f"  Kerahasiaan  {mark(s['confidentiality'])}   Integritas   {mark(s['integrity'])}")
    print(f"  Autentikasi  {mark(s['authentication'])}   Nir-sangkal  {mark(s['non_repudiation'])}")
    print(f"  Penanda-tangan: {s['signer_cn']} <{s['signer_email']}> — {s['reason']}")
    if res["attachments"]:
        save_dir = args.save_dir or "."
        os.makedirs(save_dir, exist_ok=True)
        print("  Lampiran:")
        for a in res["attachments"]:
            p = os.path.join(save_dir, a["name"] or "lampiran.bin")
            open(p, "wb").write(a["data"])
            print(f"    - {a['name']} ({len(a['data'])} byte) -> {p}")
    print("─" * 52)


def main():
    ap = argparse.ArgumentParser(description="Alat S/MIME SecureDrop (PKI + CMS/PKCS#7)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="buat/muat Root CA").set_defaults(func=cmd_init)

    pi = sub.add_parser("issue", help="terbitkan identitas S/MIME")
    pi.add_argument("username")
    pi.add_argument("--email")
    pi.set_defaults(func=cmd_issue)

    ps = sub.add_parser("seal", help="segel (tanda tangan + enkripsi) email")
    ps.add_argument("--from", required=True, dest="from")
    ps.add_argument("--to", required=True, nargs="+")
    ps.add_argument("--subject")
    ps.add_argument("--body")
    ps.add_argument("--body-file")
    ps.add_argument("--attach", nargs="*")
    ps.add_argument("--out", required=True)
    ps.set_defaults(func=cmd_seal)

    po = sub.add_parser("open", help="buka (dekripsi + verifikasi) email")
    po.add_argument("--as", required=True, dest="as")
    po.add_argument("--in", required=True)
    po.add_argument("--save-dir")
    po.set_defaults(func=cmd_open)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
