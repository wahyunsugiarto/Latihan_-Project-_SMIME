#!/usr/bin/env python3
# ============================================================
# smime_mail_cli.py — CLI klien surat S/MIME via mTLS
# ------------------------------------------------------------
# Butuh smime_server.py menyala lebih dulu.
#
# Contoh (jalankan di terminal berbeda per pengguna):
#   python smime_server.py                                  # terminal 1
#   python smime_mail_cli.py --data ./alice register --user alice --password a
#   python smime_mail_cli.py --data ./bob   register --user bob   --password b
#   python smime_mail_cli.py --data ./alice send --to bob \
#        --subject "Halo" --body "rahasia" --attach berkas.pdf
#   python smime_mail_cli.py --data ./bob   inbox
#   python smime_mail_cli.py --data ./bob   fetch --id <blob_id> --save-dir ./keluar
#
# --data  : folder identitas klien (beda pengguna beda folder)
# --host/--port : alamat server (default 127.0.0.1:9500)
# ============================================================
import os
import argparse

from smime_client import SmimeMailClient


def _client(args):
    host = args.host or os.environ.get("SMIME_SERVER_HOST", "127.0.0.1")
    port = args.port or int(os.environ.get("SMIME_SERVER_PORT", "9500"))
    return SmimeMailClient(args.data, host, port)


def cmd_register(args):
    c = _client(args)
    print("Terdaftar:", c.register(args.user, args.password))


def cmd_login(args):
    c = _client(args)
    print("Masuk:", c.login(args.user, args.password))


def cmd_directory(args):
    c = _client(args)
    for u in c.directory():
        tag = "  (anda)" if u["me"] else ("" if u["trusted"] else "  [TAK TEPERCAYA]")
        print(f"  {u['username']:12} {u['email']:28} {'tepercaya' if u['trusted'] else '-'}{tag}")


def cmd_send(args):
    c = _client(args)
    atts = []
    for p in (args.attach or []):
        atts.append({"name": os.path.basename(p), "data": open(p, "rb").read(),
                     "mime": "application/octet-stream"})
    body = args.body
    if args.body_file:
        body = open(args.body_file, encoding="utf-8").read()
    r = c.send_mail(args.to, args.subject or "(tanpa subjek)", body or "", atts)
    print(f"Terkirim ke {args.to}: blob={r['blob_id']} (eml {r['eml_size']} B, {len(atts)} lampiran)")


def cmd_inbox(args):
    c = _client(args)
    items = c.inbox()
    if not items:
        print("  (kosong)"); return
    for m in items:
        print(f"  [{m['created_at']}] dari {m['from']:10} · {m['subject']:30} · {m['size']} B · id={m['blob_id']}")


def cmd_fetch(args):
    c = _client(args)
    res = c.fetch_mail(args.id)
    s = res["security"]
    mark = lambda b: "✔" if b else "✗"
    print("─" * 52)
    print("Dari    :", res["from"]); print("Subjek  :", res["subject"])
    print("─" * 52); print(res["body"]); print("─" * 52)
    print(f"  Kerahasiaan {mark(s['confidentiality'])}  Integritas {mark(s['integrity'])}  "
          f"Autentikasi {mark(s['authentication'])}  Nir-sangkal {mark(s['non_repudiation'])}")
    print(f"  Penanda-tangan: {s['signer_cn']} <{s['signer_email']}> — {s['reason']}")
    if res["attachments"]:
        sd = args.save_dir or "."
        os.makedirs(sd, exist_ok=True)
        for a in res["attachments"]:
            p = os.path.join(sd, a["name"] or "lampiran.bin")
            open(p, "wb").write(a["data"])
            print(f"  Lampiran disimpan: {p} ({len(a['data'])} B)")
    print("─" * 52)
    if args.ack:
        c.ack(args.id); print("  (pesan di-ack & dihapus dari server)")


def main():
    ap = argparse.ArgumentParser(description="Klien surat S/MIME via mTLS")
    ap.add_argument("--data", required=True, help="folder identitas klien")
    ap.add_argument("--host"); ap.add_argument("--port", type=int)
    sub = ap.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("register"); pr.add_argument("--user", required=True); pr.add_argument("--password", required=True); pr.set_defaults(func=cmd_register)
    pl = sub.add_parser("login"); pl.add_argument("--user", required=True); pl.add_argument("--password", required=True); pl.set_defaults(func=cmd_login)
    sub.add_parser("directory").set_defaults(func=cmd_directory)
    ps = sub.add_parser("send"); ps.add_argument("--to", required=True); ps.add_argument("--subject"); ps.add_argument("--body"); ps.add_argument("--body-file"); ps.add_argument("--attach", nargs="*"); ps.set_defaults(func=cmd_send)
    sub.add_parser("inbox").set_defaults(func=cmd_inbox)
    pf = sub.add_parser("fetch"); pf.add_argument("--id", required=True); pf.add_argument("--save-dir"); pf.add_argument("--ack", action="store_true"); pf.set_defaults(func=cmd_fetch)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
