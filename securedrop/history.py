# ============================================================
# history.py  —  Riwayat keamanan & AUDIT LOG (sisi klien)
# ------------------------------------------------------------
# Menyimpan setiap PERISTIWA keamanan/transfer secara otomatis,
# dengan timestamp, dan mengelompokkannya per transfer sehingga UI
# bisa menampilkan status tiap TAHAP (encrypt, transfer, receive,
# verify, decrypt) beserta 4 indikator keamanan.
#
# Juga menyediakan ekspor ke CSV dan PDF (generator PDF minimal,
# tanpa dependensi eksternal).
# ============================================================
import os
import csv
import json
import io
import threading
import datetime

_lock = threading.Lock()

STAGES = ["encrypt", "transfer", "receive", "verify", "decrypt"]


class History:
    def __init__(self, path):
        self.path = path
        self._events = self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._events, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def log(self, **e):
        """Catat satu peristiwa keamanan/transfer."""
        with _lock:
            rec = {
                "id": (self._events[-1]["id"] + 1) if self._events else 1,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "transfer_id": e.get("transfer_id", ""),
                "direction": e.get("direction", ""),       # out | in
                "stage": e.get("stage", ""),               # encrypt|transfer|receive|verify|decrypt
                "status": e.get("status", ""),             # ok | error | progress
                "sender": e.get("sender", ""),
                "receiver": e.get("receiver", ""),
                "filename": e.get("filename", ""),
                "size": int(e.get("size", 0) or 0),
                "confidentiality": bool(e.get("confidentiality", False)),
                "integrity": bool(e.get("integrity", False)),
                "authentication": bool(e.get("authentication", False)),
                "non_repudiation": bool(e.get("non_repudiation", False)),
                "verify_result": e.get("verify_result", ""),
                "result": e.get("result", ""),
                "error": e.get("error", ""),
            }
            self._events.append(rec)
            self._events = self._events[-5000:]
            self._save()
            return rec

    def list_audit(self):
        with _lock:
            return list(reversed(self._events))

    def list_transfers(self):
        """Kelompokkan per transfer_id -> ringkasan + timeline tahap."""
        with _lock:
            groups = {}
            order = []
            for e in self._events:
                tid = e.get("transfer_id") or f"_{e['id']}"
                if tid not in groups:
                    groups[tid] = {
                        "transfer_id": tid, "direction": e.get("direction", ""),
                        "filename": e.get("filename", ""), "size": e.get("size", 0),
                        "sender": e.get("sender", ""), "receiver": e.get("receiver", ""),
                        "confidentiality": False, "integrity": False,
                        "authentication": False, "non_repudiation": False,
                        "stages": [], "last": e["timestamp"], "verify_result": "",
                    }
                    order.append(tid)
                g = groups[tid]
                for k in ("direction", "filename", "sender", "receiver"):
                    if e.get(k):
                        g[k] = e[k]
                if e.get("size"):
                    g["size"] = e["size"]
                for k in ("confidentiality", "integrity", "authentication", "non_repudiation"):
                    g[k] = g[k] or e.get(k, False)
                if e.get("verify_result"):
                    g["verify_result"] = e["verify_result"]
                g["stages"].append({"stage": e.get("stage", ""), "status": e.get("status", ""),
                                    "timestamp": e["timestamp"], "result": e.get("result", ""),
                                    "error": e.get("error", "")})
                g["last"] = e["timestamp"]
            return [groups[t] for t in reversed(order)]

    def clear(self):
        with _lock:
            self._events = []
            self._save()

    # ── Ekspor CSV ─────────────────────────────────────────
    def to_csv(self) -> bytes:
        with _lock:
            events = list(self._events)
        buf = io.StringIO()
        cols = ["timestamp", "transfer_id", "direction", "stage", "status", "sender",
                "receiver", "filename", "size", "confidentiality", "integrity",
                "authentication", "non_repudiation", "verify_result", "result", "error"]
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for e in events:
            w.writerow(e)
        return buf.getvalue().encode("utf-8")

    # ── Ekspor PDF (generator minimal, tanpa dependensi) ───
    def to_pdf(self, title="SecureDrop — Audit Log") -> bytes:
        with _lock:
            events = list(reversed(self._events))
        lines = [title, datetime.datetime.now().strftime("Dibuat: %Y-%m-%d %H:%M:%S"), ""]
        for e in events:
            ind = "".join([
                "C" if e.get("confidentiality") else "-",
                "I" if e.get("integrity") else "-",
                "A" if e.get("authentication") else "-",
                "N" if e.get("non_repudiation") else "-",
            ])
            line = (f"{e['timestamp']}  {e.get('stage',''):8} {e.get('status',''):7} "
                    f"{e.get('sender','') or '-'}->{e.get('receiver','') or '-'}  "
                    f"{(e.get('filename','') or '')[:22]:22} {_h(e.get('size',0)):>9}  [{ind}]  "
                    f"{(e.get('result','') or e.get('error',''))[:36]}")
            lines.append(line)
        return _simple_pdf(lines)


def _h(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


# ── Generator PDF minimal (Helvetica, multi-halaman) ───────
def _pdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _simple_pdf(lines, font_size=8, leading=11, margin=36,
                page_w=612, page_h=792) -> bytes:
    """Bangun PDF sederhana berisi baris teks monospace-ish (Courier)."""
    usable = page_h - 2 * margin
    per_page = int(usable // leading)
    pages = [lines[i:i + per_page] for i in range(0, len(lines), per_page)] or [[""]]

    objects = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)  # 1-based object number

    # Reserve: 1=Catalog, 2=Pages, font=3
    # We'll build content + page objects then assemble.
    font_obj_num = 3
    content_nums = []
    page_nums = []

    # placeholders for catalog(1) & pages(2) & font(3)
    objects.append(b"")  # 1 catalog
    objects.append(b"")  # 2 pages
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")  # 3 font

    for pg in pages:
        stream_lines = [b"BT", f"/F1 {font_size} Tf".encode(), f"{leading} TL".encode(),
                        f"{margin} {page_h - margin} Td".encode()]
        for ln in pg:
            stream_lines.append(b"(" + _pdf_escape(ln).encode("latin-1", "replace") + b") Tj")
            stream_lines.append(b"T*")
        stream_lines.append(b"ET")
        stream = b"\n".join(stream_lines)
        content = b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream)
        cnum = add(content)
        content_nums.append(cnum)

    for cnum in content_nums:
        page = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] "
                b"/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>"
                % (page_w, page_h, font_obj_num, cnum))
        pnum = add(page)
        page_nums.append(pnum)

    kids = b" ".join(b"%d 0 R" % n for n in page_nums)
    objects[1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(page_nums))
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"

    # Serialize with xref
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = [0] * (len(objects) + 1)
    for i, obj in enumerate(objects, start=1):
        offsets[i] = out.tell()
        out.write(b"%d 0 obj\n" % i)
        out.write(obj)
        out.write(b"\nendobj\n")
    xref_pos = out.tell()
    out.write(b"xref\n")
    out.write(b"0 %d\n" % (len(objects) + 1))
    out.write(b"0000000000 65535 f \n")
    for i in range(1, len(objects) + 1):
        out.write(b"%010d 00000 n \n" % offsets[i])
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objects) + 1))
    out.write(b"startxref\n%d\n%%%%EOF" % xref_pos)
    return out.getvalue()
