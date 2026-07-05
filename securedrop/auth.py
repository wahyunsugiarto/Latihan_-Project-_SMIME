# ============================================================
# auth.py  —  otentikasi web: hash password (PBKDF2) + sesi cookie.
# Ini bagian dari aspek keamanan "Authentication".
# ============================================================
import os
import hashlib
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import config

_serializer = URLSafeTimedSerializer(config.SECRET_KEY, salt="session")
SESSION_MAX_AGE = 8 * 3600


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 200_000)
        return dk.hex() == hash_hex
    except Exception:
        return False


def make_session_cookie(username: str) -> str:
    return _serializer.dumps({"u": username})


def read_session_cookie(token: str):
    try:
        data = _serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data.get("u")
    except (BadSignature, SignatureExpired):
        return None
