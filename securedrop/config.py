# ============================================================
# config.py  —  Pengaturan KLIEN (node web). Server pusat punya
# pengaturannya sendiri di server.py.
# ============================================================
import os

# Alamat SERVER PUSAT (CA + Directory + Relay). Inilah satu-satunya
# alamat yang perlu diketahui klien — tak ada lagi IP/port peer manual.
SERVER_HOST = os.environ.get("SECUREDROP_SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("SECUREDROP_SERVER_PORT", "9000"))

# Port WEB UI klien (dibuka di browser).
WEB_HOST = os.environ.get("SECUREDROP_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("SECUREDROP_WEB_PORT", "8080"))

# Folder data klien (identitas, outbox, hasil dekripsi, dll).
# Beda pengguna cukup pakai SECUREDROP_DATA berbeda.
DATA_DIR = os.environ.get("SECUREDROP_DATA", "./node_data")
SHARE_DIR = os.environ.get("SECUREDROP_SHARE", os.path.join(DATA_DIR, "outbox"))
RECEIVED_DIR = os.environ.get("SECUREDROP_RECEIVED", os.path.join(DATA_DIR, "received"))
VAULT_DIR = os.environ.get("SECUREDROP_VAULT", os.path.join(DATA_DIR, "vault"))
TMP_DIR = os.path.join(DATA_DIR, "tmp")
HISTORY_PATH = os.path.join(DATA_DIR, "history.json")
WEB_SETTINGS_PATH = os.path.join(DATA_DIR, "web_settings.json")

SECRET_KEY = os.environ.get("SECUREDROP_SECRET", "ganti-saya-di-produksi-please")

for d in (DATA_DIR, SHARE_DIR, RECEIVED_DIR, VAULT_DIR, TMP_DIR):
    os.makedirs(d, exist_ok=True)
