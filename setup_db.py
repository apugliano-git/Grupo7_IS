#!/usr/bin/env python3
# setup_db.py — Grupo 7 (siembra con admin)
import sqlite3, os
from utils import hash_password, log_event

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "app.db")

def ensure_db_dir():
    os.makedirs(DB_DIR, exist_ok=True)

def create_schema(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        pw_salt TEXT NOT NULL,
        rol   TEXT NOT NULL DEFAULT 'user',
        intentos_fallidos INTEGER NOT NULL DEFAULT 0,
        bloqueado_hasta   TEXT
    )
    """)
    conn.commit()

def upsert_user(conn, nombre, password, rol="user"):
    cur = conn.cursor()
    cur.execute("SELECT id FROM usuarios WHERE nombre = ?", (nombre,))
    pw_hash, pw_salt = hash_password(password)
    if cur.fetchone():
        cur.execute("UPDATE usuarios SET pw_hash=?, pw_salt=?, rol=? WHERE nombre=?",
                    (pw_hash, pw_salt, rol, nombre))
        print(f"[seed] usuario '{nombre}' actualizado (rol={rol})")
        log_event("DB_ACTION", {"action": "update_user_seed", "user": nombre, "role": rol})
    else:
        cur.execute("INSERT INTO usuarios (nombre,pw_hash,pw_salt,rol) VALUES (?,?,?,?)",
                    (nombre, pw_hash, pw_salt, rol))
        print(f"[seed] usuario '{nombre}' creado (rol={rol})")
        log_event("DB_ACTION", {"action": "seed_user", "user": nombre, "role": rol})
    conn.commit()

if __name__ == "__main__":
    ensure_db_dir()
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    create_schema(conn)

    # Grupo 7 — password común 'grupo7'; 'augusto' será admin
    users = [
        ("augusto", "grupo7", "admin"),
        ("maite",   "grupo7", "user"),
        ("maximo",  "grupo7", "user"),
        ("pedro",   "grupo7", "user"),
        ("nicole",  "grupo7", "user"),
    ]
    for u, p, r in users:
        upsert_user(conn, u, p, r)

    conn.close()
    print("DB inicializada en", DB_PATH)
