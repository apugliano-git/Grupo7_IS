#!/usr/bin/env python3
# setup_db.py — Inicializa SQLite y siembra usuarios del Grupo 7

import sqlite3
from security_hardening import (
    DB_PATH,               # Path('data/app.db')
    audit_event,           # auditoría JSON-line
    generate_salt,         # salt seguro
    PBKDF2_ITERS           # mismas iteraciones PBKDF2
)
import hashlib

# ------------------------------------------------------------------ #
# Esquema base (compatible con formato separado pw_hash/pw_salt)
# ------------------------------------------------------------------ #
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS usuarios (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre            TEXT UNIQUE NOT NULL,
    pw_hash           TEXT NOT NULL,         -- hash hex (si hay pw_salt -> hash puro)
    pw_salt           TEXT NOT NULL,         -- salt hex (obligatorio en este esquema)
    rol               TEXT NOT NULL DEFAULT 'user',
    intentos_fallidos INTEGER NOT NULL DEFAULT 0,
    bloqueado_hasta   TEXT,
    login_count       INTEGER NOT NULL DEFAULT 0,
    last_login        TEXT
);
"""

def _ensure_db_dir():
    DB_PATH.parent.mkdir(exist_ok=True)

def _connect():
    conn = sqlite3.connect(str(DB_PATH), detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def _kdf(password: str):
    """Devuelve (hash_hex, salt_hex) usando las mismas params que security_hardening."""
    salt = generate_salt()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return dk.hex(), salt.hex()

def create_schema(conn: sqlite3.Connection):
    conn.executescript(SCHEMA_SQL)
    conn.commit()

def seed_user(conn: sqlite3.Connection, nombre: str, password: str, rol: str = "user"):
    """Crea o actualiza usuario semilla (idempotente)."""
    cur = conn.cursor()
    cur.execute("SELECT id FROM usuarios WHERE nombre = ?", (nombre,))
    pw_hash_hex, pw_salt_hex = _kdf(password)

    if cur.fetchone():
        cur.execute(
            "UPDATE usuarios SET pw_hash = ?, pw_salt = ?, rol = ? WHERE nombre = ?",
            (pw_hash_hex, pw_salt_hex, rol, nombre)
        )
        action = "update_user_seed"
    else:
        cur.execute(
            "INSERT INTO usuarios (nombre, pw_hash, pw_salt, rol) VALUES (?,?,?,?)",
            (nombre, pw_hash_hex, pw_salt_hex, rol)
        )
        action = "seed_user"

    conn.commit()
    audit_event("DB_ACTION", {"action": action, "user": nombre})

# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    _ensure_db_dir()
    conn = _connect()
    create_schema(conn)

    # Usuarios semilla Grupo 7 (password genérica)
    for u in ["augusto", "maite", "maximo", "pedro", "nicole"]:
        seed_user(conn, u, "grupo7", rol="user")

    conn.close()
    print(f"DB inicializada en {DB_PATH}")
