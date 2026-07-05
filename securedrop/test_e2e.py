import os, sys, time, threading, tempfile, shutil

BASE = tempfile.mkdtemp(prefix="sdtest_")
os.environ["SECUREDROP_SERVER_DATA"] = os.path.join(BASE, "server_data")
PORT = 9911
os.environ["SECUREDROP_SERVER_PORT"] = str(PORT)

import server, client_core, container, pki, crypto_core as cc

# 1) start server
srv = server.Server(host="127.0.0.1", port=PORT)
t = threading.Thread(target=srv.start, daemon=True)
t.start()
time.sleep(0.6)

def mkclient(name):
    return client_core.Client(os.path.join(BASE, name), "127.0.0.1", PORT)

bro = mkclient("bro"); salman = mkclient("salman"); tri = mkclient("try")

# 2) register
print("register bro   :", bro.register("bro", "pw-bro"))
print("register salman:", salman.register("salman", "pw-salman"))
print("register try   :", tri.register("try", "pw-try"))

# 3) directory (from bro's view) — semua harus trusted (ditandatangani CA)
d = bro.directory()
print("\ndirectory (dilihat bro):")
for u in d:
    print(f"  - {u['username']:8} trusted={u['trusted']}  fp={u['fingerprint'][:23]}…")
assert all(u["trusted"] for u in d), "ada cert tak tepercaya!"

# 4) bro -> salman kirim file
src = os.path.join(BASE, "laporan.txt")
open(src, "w").write("RAHASIA NEGARA: anggaran Q3 2026.\n" * 5000)
print("\nukuran file :", os.path.getsize(src), "byte")
res = bro.send_file("salman", src, note="tolong dicek ya")
print("kirim bro->salman:", {k: res[k] for k in ("filename","size","blob_id")})

# 5) salman inbox + fetch + decrypt + verify
inbox = salman.inbox()
print("\ninbox salman:", [(m["from"], m["filename"], m["size"]) for m in inbox])
assert len(inbox) == 1
blob = inbox[0]["blob_id"]
tmp = os.path.join(BASE, "dl.sdrop")
meta = salman.fetch_to_temp(blob, tmp)
outdir = os.path.join(BASE, "salman_out"); os.makedirs(outdir, exist_ok=True)
out = os.path.join(outdir, meta["filename"])
r = container.decrypt_file(tmp, out, salman.identity, salman.identity.ca_cert_pem)
print("hasil dekripsi salman:")
print("   integrity_ok :", r["integrity_ok"])
print("   signature_ok :", r["signature_ok"])
print("   authenticated:", r["authenticated"], "-", r["auth_reason"])
print("   pengirim     :", r["sender_username"])
assert r["integrity_ok"] and r["signature_ok"] and r["authenticated"]
assert open(out).read() == open(src).read(), "isi file tidak sama!"
salman.ack(blob, r["integrity_ok"], r["signature_ok"], r["authenticated"])
print("   isi cocok    : True")

# 6) 'try' tidak boleh bisa membuka blob milik salman (bukan penerima)
#    (server menolak fetch blob yang bukan miliknya)
try:
    tri.fetch_to_temp(blob, os.path.join(BASE, "steal.sdrop"))
    print("\n[!] try BISA mengambil blob — BUG"); sys.exit(1)
except Exception as e:
    print("\ntry mencuri blob : DITOLAK ✔ (", str(e)[:50], ")")

# 7) MITM: cert ditandatangani CA palsu ditolak saat verifikasi direktori
#    (disimulasikan: verify_chain cert acak)
evil = pki.create_root_ca("Evil")
epriv, _ = cc.generate_keypair(2048)
efake = pki.sign_csr(evil, pki.make_csr(epriv, "salman"), "salman")
okf, why = pki.verify_chain(efake, bro.identity.ca_cert_pem)
print("cert MITM ditolak:", (not okf), "-", why)
assert not okf

# 8) audit log dari server
print("\naudit (dilihat salman):")
for e in salman.audit()[-6:]:
    print(f"  [{e['timestamp']}] {e.get('event'):9} {e.get('actor'):8} -> {e.get('peer','-'):8} "
          f"{e.get('filename','')[:18]:18} {e.get('status','')}: {e.get('result','')[:40]}")

srv.stop()
print("\n=== SEMUA UJI LULUS ===")
shutil.rmtree(BASE, ignore_errors=True)
