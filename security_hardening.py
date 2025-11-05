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
from typing import Tuple, Optional, Dict, Any

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


def valid_password_policy(password: str) -> Tuple[bool, str]:
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
def secure_login(
    username: str,
    password: str,
    performed_by: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    rotate_log_if_needed()

    if detect_sql_injection(username) or detect_sql_injection(password):
        audit_event("LOGIN_FAIL_INJECTION_DETECTED", {"user": username, "by": performed_by})
        return False, "Entrada con caracteres no permitidos.", None

    if not valid_username_format(username):
        audit_event("LOGIN_FAIL", {"user": username, "by": performed_by, "reason": "invalid_username_format"})
        return False, "Usuario inválido (formato).", None

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(usuarios)")
        cols = {r[1] for r in cur.fetchall()}

        cur.execute("SELECT * FROM usuarios WHERE nombre = ?", (username,))
        row = cur.fetchone()
        if row is None:
            audit_event("LOGIN_FAIL", {"user": username, "by": performed_by, "reason": "no_such_user"})
            return False, "Usuario o contraseña incorrectos.", None

        # bloqueo activo
        bloqueado_hasta = row["bloqueado_hasta"] if "bloqueado_hasta" in row.keys() else None
        if bloqueado_hasta:
            try:
                dt = datetime.fromisoformat(bloqueado_hasta)
                if dt > datetime.now(timezone.utc):
                    audit_event("LOGIN_BLOCKED", {"user": username, "blocked_until": bloqueado_hasta, "by": performed_by})
                    return False, f"Cuenta bloqueada hasta {bloqueado_hasta}.", None
            except Exception:
                pass

        # compat: pw_salt separado o salt:hash en pw_hash
        stored = row["pw_hash"]
        if "pw_salt" in cols and row["pw_salt"]:
            stored = f"{row['pw_salt']}:{row['pw_hash']}"

        if verify_password(stored, password):
            now_iso = datetime.now(timezone.utc).isoformat()
            try:
                cur.execute("""
                    UPDATE usuarios
                    SET intentos_fallidos = 0,
                        bloqueado_hasta = NULL,
                        login_count = COALESCE(login_count,0) + 1,
                        last_login = ?
                    WHERE nombre = ?
                """, (now_iso, username))
                conn.commit()
            except Exception as e:
                audit_event("DB_ERROR", {"action": "login_update", "error": str(e)})
            audit_event("LOGIN_SUCCESS", {"user": username, "by": performed_by})
            return True, "Login correcto.", dict(row)
        else:
            intentos = (row["intentos_fallidos"] or 0) + 1 if "intentos_fallidos" in row.keys() else 1
            if "intentos_fallidos" in row.keys():
                if intentos >= LOCK_THRESHOLD:
                    until = (datetime.now(timezone.utc) + timedelta(seconds=LOCK_DURATION_SECONDS)).isoformat()
                    cur.execute("UPDATE usuarios SET intentos_fallidos=?, bloqueado_hasta=? WHERE nombre=?",
                                (intentos, until, username))
                    conn.commit()
                    audit_event("LOGIN_FAIL", {"user": username, "by": performed_by, "reason": "locked", "attempts": intentos, "blocked_until": until})
                    return False, f"Cuenta bloqueada por múltiples intentos (hasta {until}).", None
                else:
                    cur.execute("UPDATE usuarios SET intentos_fallidos=? WHERE nombre=?", (intentos, username))
                    conn.commit()
            audit_event("LOGIN_FAIL", {"user": username, "by": performed_by, "reason": "bad_credentials", "attempts": intentos})
            return False, f"Usuario o contraseña incorrectos. Intentos: {intentos}", None

# ---------- Registro seguro ----------
def secure_register(username: str, password: str, rol: str = "user") -> Tuple[bool, str]:
    if detect_sql_injection(username) or detect_sql_injection(password):
        return False, "Entrada con caracteres no permitidos."
    if not valid_username_format(username):
        return False, "Formato de usuario inválido."
    ok, msg = valid_password_policy(password)
    if not ok:
        return False, msg

    salt = generate_salt()
    # usamos el mismo KDF, pero preparamos dos formatos:
    #  - combinado "salt:hash" (para esquemas sin pw_salt)
    #  - separado (salt_hex + hash_hex) si existe pw_salt
    kdf = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    salt_hex = salt.hex()
    hash_hex = kdf.hex()
    combined = f"{salt_hex}:{hash_hex}"

    with get_conn() as conn:
        cur = conn.cursor()
        # detectar columnas
        cur.execute("PRAGMA table_info(usuarios)")
        cols = {r[1] for r in cur.fetchall()}
        try:
            if "pw_salt" in cols:
                # esquema viejo: columnas separadas
                cur.execute("INSERT INTO usuarios (nombre, pw_hash, pw_salt, rol) VALUES (?, ?, ?, ?)",
                            (username, hash_hex, salt_hex, rol))
            else:
                # esquema nuevo: todo en pw_hash
                cur.execute("INSERT INTO usuarios (nombre, pw_hash, rol) VALUES (?, ?, ?)",
                            (username, combined, rol))
            conn.commit()
            audit_event("USER_CREATED", {"user": username})
            return True, "Usuario creado."
        except sqlite3.IntegrityError:
            return False, "El usuario ya existe."
        except Exception as e:
            audit_event("DB_ERROR", {"action": "create_user", "error": str(e)})
            return False, "Error interno al crear usuario."

# --- helpers ---

def _get_user_table_cols(cur) -> Dict[str, Dict[str, Any]]:
    """
    Devuelve {colname: {notnull: 0/1, dflt_value: str|None, pk: 0/1, type: 'TEXT'|...}}
    """
    cur.execute("PRAGMA table_info(usuarios)")
    cols = {}
    for cid, name, ctype, notnull, dflt, pk in cur.fetchall():
        cols[name] = {"type": ctype, "notnull": notnull, "dflt": dflt, "pk": pk}
    return cols

def _defaults_for_missing_cols(cols: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Genera defaults seguros para columnas NOT NULL que no llenamos explícitamente.
    No toca PK autoincrement ni timestamps si tienen default.
    """
    defaults = {}
    for name, meta in cols.items():
        if name in {"id", "nombre", "pw_hash", "pw_salt", "rol"}:
            continue
        if meta["notnull"] and meta["dflt"] is None:
            # Default seguro por tipo
            t = (meta["type"] or "").upper()
            if "INT" in t or "NUM" in t:
                defaults[name] = 0
            else:
                defaults[name] = ""  # TEXT/otros
    return defaults
# --- fin helpers nuevos ---

def secure_register(username: str, password: str, rol: str = "user") -> Tuple[bool, str]:
    if detect_sql_injection(username) or detect_sql_injection(password):
        return False, "Entrada con caracteres no permitidos."
    if not valid_username_format(username):
        return False, "Formato de usuario inválido."
    ok, msg = valid_password_policy(password)
    if not ok:
        return False, msg

    # Derivamos hash/salt (formato dual)
    salt = generate_salt()
    kdf = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    salt_hex = salt.hex()
    hash_hex = kdf.hex()
    combined = f"{salt_hex}:{hash_hex}"

    with get_conn() as conn:
        cur = conn.cursor()
        try:
            cols = _get_user_table_cols(cur)
            # chequeo existencia usuario
            cur.execute("SELECT 1 FROM usuarios WHERE nombre = ?", (username,))
            if cur.fetchone():
                return False, "El usuario ya existe."

            # armamos el INSERT según esquema presente
            insert_cols = []
            insert_vals = []

            insert_cols.append("nombre");   insert_vals.append(username)
            if "pw_salt" in cols:  # esquema con columnas separadas
                insert_cols.extend(["pw_hash", "pw_salt"])
                insert_vals.extend([hash_hex, salt_hex])
            else:                   # esquema combinado
                insert_cols.append("pw_hash")
                insert_vals.append(combined)

            # rol si existe
            if "rol" in cols:
                insert_cols.append("rol")
                insert_vals.append(rol)

            # rellenar NOT NULL extra sin default
            extra = _defaults_for_missing_cols(cols)
            for k, v in extra.items():
                if k not in insert_cols:
                    insert_cols.append(k); insert_vals.append(v)

            sql = f"INSERT INTO usuarios ({', '.join(insert_cols)}) VALUES ({', '.join(['?']*len(insert_vals))})"
            cur.execute(sql, tuple(insert_vals))
            conn.commit()
            audit_event("USER_CREATED", {"user": username, "insert_cols": insert_cols})
            return True, "Usuario creado."

        except sqlite3.IntegrityError:
            return False, "El usuario ya existe."
        except Exception as e:
            audit_event("DB_ERROR", {"action": "create_user", "error": str(e)})
            return False, "Error interno al crear usuario."