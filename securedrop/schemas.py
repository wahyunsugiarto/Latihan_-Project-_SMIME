# ============================================================
# schemas.py  —  Validasi data API (Pydantic).
# ============================================================
from pydantic import BaseModel
from typing import Optional


class AuthIn(BaseModel):
    username: str
    password: str


class SendIn(BaseModel):
    to: str                         # username penerima (dari direktori)
    filename: Optional[str] = None  # nama file di outbox
    path: Optional[str] = None      # atau path absolut (file besar)
    note: Optional[str] = None


class ReceiveIn(BaseModel):
    blob_id: str
    out_dir: Optional[str] = None   # folder tujuan hasil dekripsi (Browse Folder)


class VaultEncryptIn(BaseModel):
    filename: str
    recipient: Optional[str] = None  # username tambahan (opsional)


class VaultDecryptIn(BaseModel):
    name: str
    out_dir: Optional[str] = None


class CancelIn(BaseModel):
    key: str
