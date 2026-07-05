import os, sys, ssl, time, socket, threading, tempfile, shutil

BASE = tempfile.mkdtemp(prefix="smtls_")
PORT = 9577
os.environ["SMIME_SERVER_DATA"] = os.path.join(BASE, "server")
os.environ["SMIME_SERVER_PORT"] = str(PORT)

import pki, crypto_core as cc, wire
import smime_server, smime_client

def ok(label, cond, extra=""):
    print(("  ✔ " if cond else "  ✗ FAIL ") + label + (("  " + extra) if extra else ""))
    if not cond:
        shutil.rmtree(BASE, ignore_errors=True); sys.exit(1)

# 1) start server (thread)
srv = smime_server.SmimeServer(host="127.0.0.1", port=PORT)
threading.Thread(target=srv.start, daemon=True).start()
time.sleep(0.6)

def mk(name): return smime_client.SmimeMailClient(os.path.join(BASE, name), "127.0.0.1", PORT)

print("=== 1. Register (bootstrap TLS, belum ada sertifikat klien) ===")
alice = mk("alice"); bob = mk("bob")
print("  alice:", alice.register("alice", "pw-alice"))
print("  bob  :", bob.register("bob", "pw-bob"))
ok("alice dapat sertifikat S/MIME + email", alice.email == "alice@securedrop.local")

print("\n=== 2. Directory via mTLS ===")
d = alice.directory()
ok("bob tepercaya (rantai ke CA)", any(u["username"] == "bob" and u["trusted"] for u in d))

print("\n=== 3. KANAL mTLS aktif — tampilkan parameter TLS yang dinegosiasikan ===")
raw = socket.create_connection(("127.0.0.1", PORT), timeout=10)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations(cadata=alice.ca_pem); ctx.check_hostname = True
ctx.load_cert_chain(alice.cert_path, alice.key_path)
c = ctx.wrap_socket(raw, server_hostname=pki.SERVER_CN)
print(f"  TLS versi   : {c.version()}")
print(f"  Cipher      : {c.cipher()[0]}")
print(f"  Sertifikat server terverifikasi thd CA: ya (check_hostname + verify)")
ok("kanal terenkripsi TLS >= 1.2", c.version() in ("TLSv1.2", "TLSv1.3"), c.version())
c.close()

print("\n=== 4. Alice menyegel S/MIME lalu mengirim lewat mTLS ===")
lampiran = ("NOMINAL RAHASIA: 4.200.000.000\n" + ("rincian,angka\n" * 200)).encode()
res = alice.send_mail("bob", subject="Anggaran Q3 (rahasia)",
                      body="Bob, terlampir angka rahasia. Ditandatangani & dienkripsi.\n— Alice",
                      attachments=[{"name": "anggaran.csv", "data": lampiran, "mime": "text/csv"}])
ok("terkirim ke relay", "blob_id" in res, f"eml={res['eml_size']}B")

print("\n=== 5. OBJEK aman — server HANYA menyimpan ciphertext ===")
blob_path = os.path.join(BASE, "server", "mailbox", res["blob_id"] + ".eml")
stored = open(blob_path, "rb").read()
ok("Subject terlihat di header (S/MIME tak menyembunyikan header)", b"Anggaran Q3" in stored)
ok("isi rahasia TIDAK terbaca di blob server", b"NOMINAL RAHASIA" not in stored and lampiran not in stored)
ok("blob bertipe pkcs7-mime enveloped-data", b"enveloped-data" in stored)
print("     → server melihat metadata (pengirim/penerima/subjek/ukuran) + ciphertext, bukan isi.")

print("\n=== 6. Bob mengambil (mTLS) lalu membuka (S/MIME) ===")
inbox = bob.inbox()
ok("inbox bob berisi 1", len(inbox) == 1)
opened = bob.fetch_mail(inbox[0]["blob_id"])
s = opened["security"]
ok("body benar", "ditandatangani" in opened["body"].lower())
ok("lampiran cocok", opened["attachments"] and opened["attachments"][0]["data"] == lampiran)
ok("Kerahasiaan/Integritas/Autentikasi/Nir-sangkal semua ✔",
   s["confidentiality"] and s["integrity"] and s["authentication"] and s["non_repudiation"],
   f"signer={s['signer_cn']}")
bob.ack(inbox[0]["blob_id"])

print("\n=== 7. Uji negatif KANAL (penegakan mTLS) ===")
# (a) tanpa sertifikat klien -> ditolak di lapisan aplikasi
raw = socket.create_connection(("127.0.0.1", PORT), timeout=10)
nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); nctx.check_hostname = False; nctx.verify_mode = ssl.CERT_NONE
nc = nctx.wrap_socket(raw, server_hostname=pki.SERVER_CN)
wire.send_json(nc, {"op": "directory"})
resp = wire.recv_json(nc); nc.close()
ok("tanpa sertifikat klien -> operasi DITOLAK", not resp.get("ok"), resp.get("error", ""))

# (b) sertifikat klien dari CA PALSU -> handshake TLS gagal (ditolak di lapisan kanal)
evil = pki.create_root_ca("Evil CA")
ek, _ = cc.generate_keypair(2048)
efake = pki.sign_csr(evil, pki.make_csr(ek, "mallory"), "mallory", is_smime=True, email="m@x")
fkey = os.path.join(BASE, "fkey.pem"); fcert = os.path.join(BASE, "fcert.pem")
open(fkey, "wb").write(cc.private_to_pem(ek)); open(fcert, "w").write(efake)
handshake_failed = False
try:
    raw = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    fctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); fctx.check_hostname = False; fctx.verify_mode = ssl.CERT_NONE
    fctx.load_cert_chain(fcert, fkey)
    fc = fctx.wrap_socket(raw, server_hostname=pki.SERVER_CN)
    wire.send_json(fc, {"op": "directory"}); wire.recv_json(fc); fc.close()
except ssl.SSLError as e:
    handshake_failed = True; err = str(e)[:60]
ok("sertifikat klien dari CA palsu -> HANDSHAKE mTLS GAGAL", handshake_failed,
   err if handshake_failed else "")

print("\n=== RINGKAS: dua lapis keamanan bekerja bersama ===")
print("  • KANAL (mTLS)  : hanya klien ber-sertifikat CA yang bisa terhubung & beroperasi.")
print("  • OBJEK (S/MIME): isi tetap terenkripsi & tertanda-tangan; server tak bisa membacanya.")
print("\n=== SEMUA UJI mTLS + S/MIME LULUS ===")
srv.stop()
shutil.rmtree(BASE, ignore_errors=True)
