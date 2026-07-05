import os, sys, time, subprocess, tempfile, signal, textwrap
import httpx

BASE = tempfile.mkdtemp(prefix="sdweb_")
SRV_PORT = 9922
SRV_DATA = os.path.join(BASE, "server_data")
procs = []

def spawn(cmd, env, log):
    f = open(log, "w")
    p = subprocess.Popen(cmd, env=env, stdout=f, stderr=subprocess.STDOUT, cwd="/home/claude/sd2")
    procs.append((p, f)); return p

base_env = dict(os.environ)
base_env["SECUREDROP_SERVER_PORT"] = str(SRV_PORT)
base_env["SECUREDROP_SERVER_HOST"] = "127.0.0.1"

# 1) server
senv = dict(base_env); senv["SECUREDROP_SERVER_DATA"] = SRV_DATA
senv["SECUREDROP_SERVER_HOST"] = "127.0.0.1"
spawn([sys.executable, "server.py"], senv, os.path.join(BASE, "server.log"))
time.sleep(1.5)

# 2) dua klien web
def client_env(name, port):
    e = dict(base_env)
    e["SECUREDROP_DATA"] = os.path.join(BASE, name)
    e["SECUREDROP_WEB_PORT"] = str(port)
    e["SECUREDROP_WEB_HOST"] = "127.0.0.1"
    e["SECUREDROP_SECRET"] = "test-secret-123"
    return e

spawn([sys.executable, "app.py"], client_env("bro", 8801), os.path.join(BASE, "bro.log"))
spawn([sys.executable, "app.py"], client_env("salman", 8802), os.path.join(BASE, "salman.log"))
time.sleep(3.5)

BRO = "http://127.0.0.1:8801"
SAL = "http://127.0.0.1:8802"
bro = httpx.Client(base_url=BRO, timeout=30)
sal = httpx.Client(base_url=SAL, timeout=30)

def ok(label, cond, extra=""):
    print(("  ✔ " if cond else "  �’ FAIL ")+label+(("  "+extra) if extra else ""))
    if not cond:
        for _, f in procs: f.flush()
        print("---- server.log ----"); print(open(os.path.join(BASE,'server.log')).read()[-1500:])
        print("---- bro.log ----"); print(open(os.path.join(BASE,'bro.log')).read()[-1500:])
        print("---- salman.log ----"); print(open(os.path.join(BASE,'salman.log')).read()[-1500:])
        cleanup(); sys.exit(1)

def cleanup():
    for p, f in procs:
        try: p.send_signal(signal.SIGINT); p.wait(timeout=3)
        except Exception:
            try: p.kill()
            except Exception: pass
        f.close()

try:
    # register kedua user
    r = bro.post("/api/register", json={"username":"bro","password":"pw-bro"}); ok("register bro", r.status_code==200, str(r.status_code))
    r = sal.post("/api/register", json={"username":"salman","password":"pw-salman"}); ok("register salman", r.status_code==200)

    # identity
    r = bro.get("/api/identity").json(); ok("identity bro server_ok", r.get("server_ok") is True, r.get("fingerprint","")[:24])

    # directory bro melihat salman tepercaya
    d = bro.get("/api/directory").json()
    sal_row = next((u for u in d if u["username"]=="salman"), None)
    ok("directory: salman tepercaya", bool(sal_row and sal_row["trusted"]))

    # bro upload + kirim ke salman
    payload = ("RAHASIA "*4000).encode()
    r = bro.post("/api/upload", files={"file":("rahasia.txt", payload, "text/plain")}); ok("upload", r.status_code==200 and r.json()["name"]=="rahasia.txt")
    r = bro.post("/api/send", json={"to":"salman","filename":"rahasia.txt","note":"tolong cek"}); ok("send", r.status_code==200)

    # tunggu progres kirim selesai
    for _ in range(40):
        snap = bro.get("/api/progress").json()
        if snap and all(v["status"] in ("done","error") for v in snap.values()): break
        time.sleep(0.4)
    snap = bro.get("/api/progress").json()
    done = [v for v in snap.values() if v.get("status")=="done"]
    ok("kirim selesai + total_time", bool(done) and "total_time" in done[0], f"speed={done[0].get('speed') if done else '-'}")

    # salman inbox
    for _ in range(10):
        inbox = sal.get("/api/inbox").json()
        if inbox: break
        time.sleep(0.5)
    ok("inbox salman berisi 1", len(inbox)==1, inbox[0]["filename"] if inbox else "")
    blob = inbox[0]["blob_id"]

    # salman receive ke folder pilihan
    outdir = os.path.join(BASE, "salman_pilihan"); os.makedirs(outdir, exist_ok=True)
    r = sal.post("/api/receive", json={"blob_id":blob, "out_dir":outdir}); ok("receive mulai", r.status_code==200)
    for _ in range(40):
        snap = sal.get("/api/progress").json()
        if snap and all(v["status"] in ("done","error") for v in snap.values()): break
        time.sleep(0.4)
    snap = sal.get("/api/progress").json()
    recv = [v for v in snap.values() if v.get("direction")=="in"]
    ok("terima selesai C/I/A/N", bool(recv) and recv[0].get("integrity") and recv[0].get("authenticated") and recv[0].get("signature"),
       f"integrity={recv[0].get('integrity')},auth={recv[0].get('authenticated')},sig={recv[0].get('signature')}" if recv else "")

    # file terdekripsi ada di folder pilihan & isinya cocok
    got = None
    for fn in os.listdir(outdir):
        got = os.path.join(outdir, fn)
    ok("file tersimpan di folder pilihan", bool(got) and open(got,'rb').read()==payload, got or "")

    # riwayat keamanan salman (verify+decrypt tahap)
    tr = sal.get("/api/transfers").json()
    stages = [s["stage"] for s in tr[0]["stages"]] if tr else []
    ok("riwayat: tahap receive/verify/decrypt", set(["receive","verify","decrypt"]).issubset(set(stages)), str(stages))
    ok("riwayat: 4 indikator aktif", tr and tr[0]["confidentiality"] and tr[0]["integrity"] and tr[0]["authentication"] and tr[0]["non_repudiation"])

    # audit + ekspor
    au = sal.get("/api/audit").json(); ok("audit ada entri", len(au["local"])>0, f"{len(au['local'])} lokal / {len(au['server'])} server")
    rc = sal.get("/api/audit/export.csv"); ok("ekspor CSV", rc.status_code==200 and rc.headers["content-type"].startswith("text/csv") and len(rc.content)>50)
    rp = sal.get("/api/audit/export.pdf"); ok("ekspor PDF", rp.status_code==200 and rp.content[:4]==b"%PDF")

    # download terenkripsi (versi .sdrop) oleh penerima
    rd = sal.get("/api/download", params={"kind":"received_encrypted","name":"rahasia.txt.sdrop"})
    ok("unduh versi terenkripsi", rd.status_code==200 and rd.content[:6]==b"SDROP2")

    # brankas bro: enkripsi lalu buka ke folder pilihan
    r = bro.post("/api/vault/encrypt", json={"filename":"rahasia.txt"}); ok("vault encrypt", r.status_code==200)
    vout = os.path.join(BASE,"bro_vault_out"); os.makedirs(vout, exist_ok=True)
    r = bro.post("/api/vault/decrypt", json={"name":"rahasia.txt.sdrop","out_dir":vout})
    j = r.json() if r.status_code==200 else {}
    ok("vault decrypt ke folder pilihan", r.status_code==200 and j.get("integrity_ok") and j.get("authenticated"), j.get("auth_reason",""))
    ok("vault: isi cocok", os.path.isfile(j.get("out_path","")) and open(j["out_path"],"rb").read()==payload)

    print("\n=== SEMUA UJI INTEGRASI WEB LULUS ===")
finally:
    cleanup()
    import shutil; shutil.rmtree(BASE, ignore_errors=True)
