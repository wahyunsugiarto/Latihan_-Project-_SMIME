# ============================================================
# app.py  —  Web UI KLIEN SecureDrop (model PKI client-server)
#   Jalankan:  python app.py      (butuh server.py sudah menyala)
#   Web UI  :  http://localhost:8080
# ============================================================
import os
import json as _json
import time
import threading
import datetime

from fastapi import FastAPI, Depends, Request, HTTPException, UploadFile, File
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                               FileResponse, Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles

import config
import auth
import schemas
import crypto_core as cc
import pki
import container
import client_core
import history as histmod

# ── Folder tambahan ────────────────────────────────────────
RECV_ENC = os.path.join(config.DATA_DIR, "received_encrypted")
SENT_ENC = os.path.join(config.DATA_DIR, "sent_encrypted")
VAULT_OUT_DEFAULT = os.path.join(config.VAULT_DIR, "_decrypted")
for d in (RECV_ENC, SENT_ENC, VAULT_OUT_DEFAULT):
    os.makedirs(d, exist_ok=True)

CLIENT = client_core.Client(config.DATA_DIR, config.SERVER_HOST, config.SERVER_PORT)
HISTORY = histmod.History(config.HISTORY_PATH)

app = FastAPI(title="SecureDrop — PKI E2E", version="2.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Progres langsung ───────────────────────────────────────
PROGRESS = {}
_plock = threading.Lock()


def set_progress(key, **kw):
    with _plock:
        p = PROGRESS.get(key, {})
        p.update(kw)
        PROGRESS[key] = p


def progress_snapshot():
    with _plock:
        return {k: dict(v) for k, v in PROGRESS.items()}


def human_speed(bps):
    for u in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024:
            return f"{bps:.1f} {u}"
        bps /= 1024
    return f"{bps:.1f} TB/s"


# ── Sesi web ───────────────────────────────────────────────
def current_user(request: Request):
    token = request.cookies.get("session")
    user = auth.read_session_cookie(token) if token else None
    if not user or not CLIENT.logged_in or CLIENT.identity.username != user:
        raise HTTPException(status_code=401, detail="Belum login")
    return user


def page(name):
    return HTMLResponse(open(os.path.join("templates", name), encoding="utf-8").read())


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    token = request.cookies.get("session")
    u = auth.read_session_cookie(token) if token else None
    if not (u and CLIENT.logged_in and CLIENT.identity.username == u):
        return RedirectResponse("/login")
    return page("index.html")


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return page("login.html")


def _set_session(username):
    resp = JSONResponse({"ok": True, "username": username})
    resp.set_cookie("session", auth.make_session_cookie(username),
                    httponly=True, samesite="lax", max_age=auth.SESSION_MAX_AGE)
    return resp


@app.post("/api/register")
def api_register(body: schemas.AuthIn):
    try:
        info = CLIENT.register(body.username, body.password)
    except Exception as e:
        raise HTTPException(400, f"Registrasi gagal: {e}")
    HISTORY.log(stage="", status="ok", sender=body.username, result="registrasi + sertifikat CA")
    return _set_session(info["username"])


@app.post("/api/login")
def api_login(body: schemas.AuthIn):
    try:
        info = CLIENT.login(body.username, body.password)
    except Exception as e:
        raise HTTPException(401, f"Login gagal: {e}")
    return _set_session(info["username"])


@app.post("/api/logout")
def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session")
    return resp


# ── Identitas & status server ──────────────────────────────
@app.get("/api/identity")
def api_identity(user: str = Depends(current_user)):
    idy = CLIENT.identity
    cert = pki.load_cert(idy.cert_pem)
    try:
        exp = cert.not_valid_after_utc.strftime("%Y-%m-%d")
    except AttributeError:
        exp = cert.not_valid_after.strftime("%Y-%m-%d")
    ca_fp = pki.cert_fingerprint(pki.load_cert(idy.ca_cert_pem))
    server_ok = True
    try:
        CLIENT.directory()
    except Exception:
        server_ok = False
    return {"username": idy.username, "fingerprint": idy.fingerprint, "short": idy.short,
            "cert_expires": exp, "ca_fingerprint": ca_fp, "ca_short": cc.short_fp(ca_fp),
            "server_host": CLIENT.server_host, "server_port": CLIENT.server_port,
            "server_ok": server_ok}


# ── Direktori (pengganti daftar peer manual) ───────────────
@app.get("/api/directory")
def api_directory(user: str = Depends(current_user)):
    try:
        users = CLIENT.directory()
    except Exception as e:
        raise HTTPException(502, f"Tak bisa menghubungi server: {e}")
    return [{"username": u["username"], "fingerprint": u["fingerprint"],
             "short": cc.short_fp(u["fingerprint"]), "trusted": u["trusted"],
             "trust_reason": u["trust_reason"], "me": u["me"]} for u in users]


# ── Sertifikat: ekspor/impor (fitur cadangan point 4) ──────
@app.get("/api/cert/export")
def api_cert_export(user: str = Depends(current_user)):
    idy = CLIENT.identity
    bundle = {"type": "securedrop-pki-bundle", "username": idy.username,
              "cert": idy.cert_pem, "ca_cert": idy.ca_cert_pem,
              "fingerprint": idy.fingerprint}
    data = _json.dumps(bundle, ensure_ascii=False, indent=2)
    return Response(content=data, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{idy.username}.sdbundle"'})


# ── File: outbox & received ────────────────────────────────
def _list_dir(d):
    out = []
    if os.path.isdir(d):
        for name in sorted(os.listdir(d)):
            fp = os.path.join(d, name)
            if os.path.isfile(fp):
                out.append({"name": name, "size": os.path.getsize(fp)})
    return out


@app.get("/api/files")
def api_files(user: str = Depends(current_user)):
    return {"outbox": _list_dir(config.SHARE_DIR),
            "received": _list_dir(config.RECEIVED_DIR),
            "received_encrypted": _list_dir(RECV_ENC),
            "sent_encrypted": _list_dir(SENT_ENC),
            "share_dir": os.path.abspath(config.SHARE_DIR),
            "received_dir": os.path.abspath(config.RECEIVED_DIR)}


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...), user: str = Depends(current_user)):
    safe = os.path.basename(file.filename or "upload.bin")
    dst = os.path.join(config.SHARE_DIR, safe)
    with open(dst, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    return {"ok": True, "name": safe, "size": os.path.getsize(dst)}


@app.get("/api/download")
def api_download(name: str, kind: str = "received", user: str = Depends(current_user)):
    base = {"received": config.RECEIVED_DIR, "outbox": config.SHARE_DIR,
            "received_encrypted": RECV_ENC, "sent_encrypted": SENT_ENC}.get(kind, config.RECEIVED_DIR)
    safe = os.path.basename(name)
    path = os.path.join(base, safe)
    if not os.path.isfile(path):
        raise HTTPException(404, "File tidak ada")
    return FileResponse(path, filename=safe, media_type="application/octet-stream")


# ── Kirim file (enkripsi + relay) ──────────────────────────
def _send_worker(to, filepath, note):
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    key = f"out:{to}:{filename}:{int(time.time())}"
    set_progress(key, direction="out", filename=filename, peer=to, total=filesize,
                 done=0, percent=0, speed="0 B/s", eta="-", elapsed=0,
                 status="active", stage="encrypt", started=time.time())
    tid_holder = {}
    HISTORY.log(direction="out", stage="encrypt", status="ok", sender=CLIENT.identity.username,
                receiver=to, filename=filename, size=filesize, confidentiality=True,
                result="AES-256-GCM + RSA-OAEP (kunci sesi dibungkus ke penerima)")

    def prog(sent, total, elapsed):
        pct = round(min(sent, total) / max(total, 1) * 100, 1)
        spd = sent / max(elapsed, 1e-6)
        eta = (total - sent) / spd if spd > 0 else 0
        set_progress(key, done=min(sent, total), percent=pct, speed=human_speed(spd),
                     eta=f"{eta:.0f}s", elapsed=round(elapsed, 1), stage="transfer")

    try:
        enc_path = os.path.join(SENT_ENC, filename + ".sdrop")
        res = CLIENT.send_file(to, filepath, note=note, progress=prog, keep_encrypted_path=enc_path)
        total_time = time.time() - PROGRESS[key]["started"]
        set_progress(key, status="done", percent=100.0, done=filesize, speed="-", eta="0s",
                     stage="done", total_time=round(total_time, 1))
        HISTORY.log(direction="out", stage="transfer", status="ok", transfer_id=res["transfer_id"],
                    sender=CLIENT.identity.username, receiver=to, filename=filename, size=filesize,
                    confidentiality=True, integrity=True, non_repudiation=True, authentication=True,
                    result=f"terkirim via relay · enc_sha256={(res.get('enc_sha256') or '')[:16]}…")
        # perbarui transfer_id di progress
        set_progress(key, transfer_id=res["transfer_id"])
    except Exception as e:
        set_progress(key, status="error", error=str(e), stage="error")
        HISTORY.log(direction="out", stage="transfer", status="error", sender=CLIENT.identity.username,
                    receiver=to, filename=filename, size=filesize, error=str(e))


@app.post("/api/send")
def api_send(body: schemas.SendIn, user: str = Depends(current_user)):
    filepath = body.path if body.path else os.path.join(config.SHARE_DIR, body.filename or "")
    if not filepath or not os.path.isfile(filepath):
        raise HTTPException(404, f"File tidak ditemukan: {filepath}")
    threading.Thread(target=_send_worker, args=(body.to, filepath, body.note or ""),
                     daemon=True).start()
    return {"ok": True, "message": f"Mengenkripsi & mengirim {os.path.basename(filepath)} ke {body.to}"}


# ── Inbox (file terenkripsi menunggu) ──────────────────────
@app.get("/api/inbox")
def api_inbox(user: str = Depends(current_user)):
    try:
        items = CLIENT.inbox()
    except Exception as e:
        raise HTTPException(502, f"Tak bisa menghubungi server: {e}")
    return [{"blob_id": m["blob_id"], "from": m["from"], "filename": m["filename"],
             "size": m["size"], "enc_size": m.get("enc_size", 0),
             "enc_sha256": m.get("enc_sha256", ""), "note": m.get("note", ""),
             "created_at": m.get("created_at", "")} for m in items]


def _receive_worker(blob_id, out_dir):
    key = f"in:{blob_id}"
    set_progress(key, direction="in", filename="…", peer="", total=0, done=0, percent=0,
                 speed="0 B/s", eta="-", elapsed=0, status="active", stage="receive",
                 started=time.time())
    tmp = os.path.join(config.TMP_DIR, blob_id + ".sdrop")

    def prog(got, total, elapsed):
        pct = round(min(got, total) / max(total, 1) * 100, 1) if total else 0
        spd = got / max(elapsed, 1e-6)
        set_progress(key, done=got, total=total, percent=pct, speed=human_speed(spd),
                     elapsed=round(elapsed, 1), stage="receive")

    try:
        meta = CLIENT.fetch_to_temp(blob_id, tmp, progress=prog)
        fname = meta["filename"]
        set_progress(key, filename=fname, peer=meta["from"], stage="verify")
        HISTORY.log(direction="in", stage="receive", status="ok", transfer_id=meta.get("transfer_id", ""),
                    sender=meta["from"], receiver=CLIENT.identity.username, filename=fname,
                    size=meta["size"], result="blob terenkripsi diunduh dari relay")

        # simpan salinan terenkripsi (penerima boleh unduh versi terenkripsi)
        enc_keep = os.path.join(RECV_ENC, fname + ".sdrop")
        try:
            import shutil
            shutil.copyfile(tmp, enc_keep)
        except Exception:
            pass

        # dekripsi ke folder tujuan pilihan pengguna
        target_dir = out_dir if (out_dir and os.path.isdir(out_dir)) else config.RECEIVED_DIR
        os.makedirs(target_dir, exist_ok=True)
        out_path = _unique(os.path.join(target_dir, fname))
        r = container.decrypt_file(tmp, out_path, CLIENT.identity, CLIENT.identity.ca_cert_pem)
        set_progress(key, stage="decrypt")

        ok = r["integrity_ok"] and r["signature_ok"] and r["authenticated"]
        HISTORY.log(direction="in", stage="verify", status="ok" if ok else "error",
                    transfer_id=r["transfer_id"], sender=r["sender_username"] or meta["from"],
                    receiver=CLIENT.identity.username, filename=fname, size=meta["size"],
                    confidentiality=True, integrity=r["integrity_ok"],
                    authentication=r["authenticated"], non_repudiation=r["signature_ok"],
                    verify_result=r["auth_reason"],
                    result=f"integrity={r['integrity_ok']} signature={r['signature_ok']} auth={r['authenticated']}")
        HISTORY.log(direction="in", stage="decrypt", status="ok", transfer_id=r["transfer_id"],
                    sender=r["sender_username"] or meta["from"], receiver=CLIENT.identity.username,
                    filename=fname, size=meta["size"], confidentiality=True,
                    integrity=r["integrity_ok"], authentication=r["authenticated"],
                    non_repudiation=r["signature_ok"], result=f"disimpan di {out_path}")

        try:
            CLIENT.ack(blob_id, r["integrity_ok"], r["signature_ok"], r["authenticated"])
        except Exception:
            pass
        total_time = time.time() - PROGRESS[key]["started"]
        set_progress(key, status="done", percent=100.0, stage="done", saved=os.path.basename(out_path),
                     integrity=r["integrity_ok"], signature=r["signature_ok"],
                     authenticated=r["authenticated"], total_time=round(total_time, 1))
    except Exception as e:
        set_progress(key, status="error", error=str(e), stage="error")
        HISTORY.log(direction="in", stage="receive", status="error", filename="", error=str(e))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _unique(path):
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    n = 1
    while os.path.exists(f"{stem} ({n}){ext}"):
        n += 1
    return f"{stem} ({n}){ext}"


@app.post("/api/receive")
def api_receive(body: schemas.ReceiveIn, user: str = Depends(current_user)):
    threading.Thread(target=_receive_worker, args=(body.blob_id, body.out_dir or None),
                     daemon=True).start()
    return {"ok": True, "message": "Mengunduh, mendekripsi & memverifikasi…"}


# ── Progres ────────────────────────────────────────────────
@app.get("/api/progress")
def api_progress(user: str = Depends(current_user)):
    snap = progress_snapshot()
    now = time.time()
    for k, v in list(snap.items()):
        if v.get("status") in ("done", "error") and now - v.get("started", now) > 90:
            with _plock:
                PROGRESS.pop(k, None)
    return progress_snapshot()


@app.post("/api/progress/clear")
def api_progress_clear(user: str = Depends(current_user)):
    with _plock:
        for k in [k for k, v in PROGRESS.items() if v.get("status") in ("done", "error")]:
            PROGRESS.pop(k, None)
    return {"ok": True}


# ── Riwayat keamanan (per-transfer, berjenjang) ────────────
@app.get("/api/transfers")
def api_transfers(user: str = Depends(current_user)):
    return HISTORY.list_transfers()


# ── Audit log ──────────────────────────────────────────────
@app.get("/api/audit")
def api_audit(user: str = Depends(current_user)):
    local = HISTORY.list_audit()
    server = []
    try:
        server = CLIENT.audit()
    except Exception:
        pass
    return {"local": local, "server": server}


@app.get("/api/audit/export.csv")
def api_audit_csv(user: str = Depends(current_user)):
    data = HISTORY.to_csv()
    return Response(content=data, media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="securedrop-audit.csv"'})


@app.get("/api/audit/export.pdf")
def api_audit_pdf(user: str = Depends(current_user)):
    data = HISTORY.to_pdf(title=f"SecureDrop — Audit Log ({CLIENT.identity.username})")
    return Response(content=data, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="securedrop-audit.pdf"'})


@app.delete("/api/audit")
def api_audit_clear(user: str = Depends(current_user)):
    HISTORY.clear()
    return {"ok": True}


# ── Brankas (buka file sendiri) — dengan Browse Folder ─────
@app.get("/api/vault")
def api_vault(user: str = Depends(current_user)):
    files = _list_dir(config.VAULT_DIR)
    files = [f for f in files if f["name"].endswith(".sdrop")]
    return {"files": files, "vault_dir": os.path.abspath(config.VAULT_DIR),
            "default_out": os.path.abspath(VAULT_OUT_DEFAULT)}


@app.post("/api/vault/encrypt")
def api_vault_encrypt(body: schemas.VaultEncryptIn, user: str = Depends(current_user)):
    src = os.path.join(config.SHARE_DIR, body.filename)
    if not os.path.isfile(src):
        raise HTTPException(404, "File sumber tak ada di outbox")
    r_pub = r_fp = None
    if body.recipient:
        for u in CLIENT.directory():
            if u["username"] == body.recipient and u["trusted"]:
                cert = pki.load_cert(u["cert"])
                r_pub, r_fp = cert.public_key(), pki.cert_fingerprint(cert)
    dst = os.path.join(config.VAULT_DIR, body.filename + ".sdrop")
    info = container.encrypt_to_file(src, dst, CLIENT.identity, r_pub, r_fp)
    HISTORY.log(stage="encrypt", status="ok", transfer_id=info["transfer_id"],
                sender=CLIENT.identity.username, filename=body.filename,
                size=info["filesize"], confidentiality=True, result="dienkripsi ke brankas")
    return {"ok": True, "file": os.path.basename(dst)}


@app.post("/api/vault/decrypt")
def api_vault_decrypt(body: schemas.VaultDecryptIn, user: str = Depends(current_user)):
    src = os.path.join(config.VAULT_DIR, body.name)
    if not os.path.isfile(src):
        raise HTTPException(404, "File .sdrop tak ada")
    target = body.out_dir if (body.out_dir and os.path.isdir(body.out_dir)) else VAULT_OUT_DEFAULT
    os.makedirs(target, exist_ok=True)
    try:
        header = container.peek_header(src)
        out_path = _unique(os.path.join(target, os.path.basename(header["filename"])))
        r = container.decrypt_file(src, out_path, CLIENT.identity, CLIENT.identity.ca_cert_pem)
    except Exception as e:
        raise HTTPException(400, f"Gagal membuka: {e}")
    HISTORY.log(stage="decrypt", status="ok", transfer_id=r["transfer_id"],
                sender=r["sender_username"], filename=r["filename"],
                confidentiality=True, integrity=r["integrity_ok"],
                non_repudiation=r["signature_ok"], authentication=r["authenticated"],
                result=f"dibuka ke {out_path}")
    return {"ok": True, "filename": r["filename"], "out_path": os.path.abspath(out_path),
            "integrity_ok": r["integrity_ok"], "signature_ok": r["signature_ok"],
            "authenticated": r["authenticated"], "auth_reason": r["auth_reason"]}


if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  SecureDrop KLIEN — Web UI")
    print(f"  Web UI : http://localhost:{config.WEB_PORT}")
    print(f"  Server : {config.SERVER_HOST}:{config.SERVER_PORT} (CA + Directory + Relay)")
    print("=" * 60)
    uvicorn.run(app, host=config.WEB_HOST, port=config.WEB_PORT, reload=False)
