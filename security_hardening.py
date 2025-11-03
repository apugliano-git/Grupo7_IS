# security_hardening.py
"""
Módulo de hardening: validaciones, hashing seguro, login con bloqueo, auditoría y rotación de logs.
Diseñado para integrarse con la app Tkinter existente.
"""

from pathlib import Path
import sqlite3
import secrets
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone, timedelta

# Rutas relativas al archivo
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "app.db"
AUDIT_LOG = DATA_DIR / "security.log"

# Políticas y parámetros
PWD_MIN_LEN = 8
LOCK_THRESHOLD = 5
LOCK_DURATION_SECONDS = 5 * 60  # 5 minutos
PBKDF2_ITERS = 200_000
SALT_BYTES = 16
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")

# Detección sencilla de payloads SQL maliciosos para la demo
SQL_INJECTION_PATTERNS = [
    r"(--)+", r"(\bOR\b)", r"(\bAND\b)", r";", r"/\*", r"\*/", r"'\s*or\s*'", r"'\s*OR\s*'",
    r"'\s*1\s*=\s*1", r"'\s*=\s*'"
]
SQL_INJECTION_RE = re.compile("|".join(SQL_INJECTION_PATTERNS), re.IGNORECASE)


def audit_event(event_type: str, details: dict):
    """Escribe evento JSON-line en AUDIT_LOG con timestamp UTC."""
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event_type, **details}
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # Best effort - no raise para no romper la app UI
        pass


# ---------- Hashing y verificación ----------
def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return salt.hex() + ":" + dk.hex()


def verify_password(stored: str, provided: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        candidate = hashlib.pbkdf2_hmac("sha256", provided.encode("utf-8"), salt, PBKDF2_ITERS)
        return hmac.compare_digest(expected, candidate)
    except Exception:
        return False


# ---------- Validaciones ----------
def valid_username_format(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


def valid_password_policy(password: str) -> (bool, str):
    if not password or len(password) < PWD_MIN_LEN:
        return False, f"Contraseña debe tener al menos {PWD_MIN_LEN} caracteres."
    if not re.search(r"[0-9]", password):
        return False, "Contraseña debe incluir al menos un dígito."
    return True, "OK"


def detect_sql_injection(value: str) -> bool:
    """Flaggea entradas sospechosas para la demo (bloqueo/alerta)."""
    if not value:
        return False
    return bool(SQL_INJECTION_RE.search(value))


# ---------- DB helpers ----------
def get_conn():
    conn = sqlite3.connect(str(DB_PATH), detect_types=sqlite3.PARSE_DECLTYPES, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def rotate_log_if_needed(max_bytes: int = 5 * 1024 * 1024):
    try:
        p = Path(AUDIT_LOG)
        if p.exists() and p.stat().st_size > max_bytes:
            bak = p.with_suffix(".log.bak")
            p.rename(bak)
            p.write_text("", encoding="utf-8")
            audit_event("LOG_ROTATED", {"rotated_to": str(bak)})
    except Exception:
        pass


# ---------- Login robusto (usa queries parametrizadas internamente) ----------
def secure_login(username: str, password: str, performed_by: str = None) -> (bool, str, dict):
    """
    Intenta loguear y aplica:
      - detección simple de patrones SQL (para demo)
      - bloqueo por intentos (LOCK_THRESHOLD)
      - verificación PBKDF2
    Devuelve (success, message, user_row_dict_or_None)
    """
    rotate_log_if_needed()

    if detect_sql_injection(username) or detect_sql_injection(password):
        audit_event("LOGIN_FAIL_INJECTION_DETECTED", {"user": username, "by": performed_by})
        return False, "Entrada con caracteres no permitidos.", None

    if not valid_username_format(username):
        audit_event("LOGIN_FAIL", {"user": username, "by": performed_by, "reason": "invalid_username_format"})
        return False, "Usuario inválido (formato).", None

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM usuarios WHERE nombre = ?", (username,))
        row = cur.fetchone()
        if row is None:
            audit_event("LOGIN_FAIL", {"user": username, "by": performed_by, "reason": "no_such_user"})
            return False, "Usuario o contraseña incorrectos.", None

        # revisar bloqueo
        blocked_until = row["bloqueado_hasta"]
        if blocked_until:
            try:
                dt = datetime.fromisoformat(blocked_until)
                if dt > datetime.now(timezone.utc):
                    audit_event("LOGIN_BLOCKED", {"user": username, "blocked_until": blocked_until, "by": performed_by})
                    return False, f"Cuenta bloqueada hasta {blocked_until}.", None
            except Exception:
                pass

        # verificar contraseña
        stored = row["pw_hash"]
        if verify_password(stored, password):
            # reset intentos y actualizar last_login / login_count
            now_iso = datetime.now(timezone.utc).isoformat()
            cur.execute("""
                UPDATE usuarios
                SET intentos_fallidos = 0, bloqueado_hasta = NULL, login_count = COALESCE(login_count,0) + 1, last_login = ?
                WHERE nombre = ?
            """, (now_iso, username))
            conn.commit()
            audit_event("LOGIN_SUCCESS", {"user": username, "by": performed_by})
            return True, "Login correcto.", dict(row)
        else:
            # incrementar intentos
            attempts = (row["intentos_fallidos"] or 0) + 1
            if attempts >= LOCK_THRESHOLD:
                until = (datetime.now(timezone.utc) + timedelta(seconds=LOCK_DURATION_SECONDS)).isoformat()
                cur.execute("UPDATE usuarios SET intentos_fallidos=?, bloqueado_hasta=? WHERE nombre=?", (attempts, until, username))
                conn.commit()
                audit_event("LOGIN_FAIL", {"user": username, "by": performed_by, "reason": "locked", "attempts": attempts, "blocked_until": until})
                return False, f"Cuenta bloqueada por múltiples intentos (hasta {until}).", None
            else:
                cur.execute("UPDATE usuarios SET intentos_fallidos=? WHERE nombre=?", (attempts, username))
                conn.commit()
                audit_event("LOGIN_FAIL", {"user": username, "by": performed_by, "reason": "bad_credentials", "attempts": attempts})
                return False, f"Usuario o contraseña incorrectos. Intentos: {attempts}", None


# ---------- Registro seguro ----------
def secure_register(username: str, password: str, rol: str = "user") -> (bool, str):
    if detect_sql_injection(username) or detect_sql_injection(password):
        return False, "Entrada con caracteres no permitidos."
    if not valid_username_format(username):
        return False, "Formato de usuario inválido."
    ok, msg = valid_password_policy(password)
    if not ok:
        return False, msg

    salt = generate_salt()
    pw_hash = hash_password(password, salt)
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO usuarios (nombre, pw_hash, rol) VALUES (?, ?, ?)", (username, pw_hash, rol))
            conn.commit()
            audit_event("USER_CREATED", {"user": username})
            return True, "Usuario creado."
        except sqlite3.IntegrityError:
            return False, "El usuario ya existe."
        except Exception as e:
            audit_event("DB_ERROR", {"action": "create_user", "error": str(e)})
            return False, "Error interno al crear usuario."
