# utils.py
# funciones auxiliares: hashing PBKDF2, validación y logging básico (JSON)
import os
import hashlib
import base64
import json
from datetime import datetime, timedelta

DB_LOCK_SECONDS = 10  # (no usado; placeholder if se quiere x-lock)


def hash_password(password: str, salt: bytes = None, iterations: int = 200_000):
    """
    Devuelve (hash_b64, salt_b64)
    PBKDF2-HMAC-SHA256, base64 encodificado.
    """
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return base64.b64encode(dk).decode("utf-8"), base64.b64encode(salt).decode("utf-8")


def verify_password(password: str, hash_b64: str, salt_b64: str, iterations: int = 200_000):
    salt = base64.b64decode(salt_b64)
    h_new, _ = hash_password(password, salt, iterations)
    return h_new == hash_b64


# ---------------- Logging estructurado ----------------
LOGFILE = "security.log"


def log_event(event_type: str, details: dict):
    """
    Registra un evento security en JSON, appended al archivo LOGFILE.
    event_type: LOGIN_SUCCESS, LOGIN_FAIL, LOCKED, DB_ACTION, INFO
    details: diccionario con campos adicionales (usuario, ip, reason, etc.)
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": event_type,
        "details": details,
    }
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------------- Validadores simples ----------------
import re

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


def valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username))


def valid_password(password: str) -> bool:
    # mínimo 6 caracteres para esta demo (se puede ajustar)
    return isinstance(password, str) and len(password) >= 6
