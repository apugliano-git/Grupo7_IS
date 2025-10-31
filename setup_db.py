#!/usr/bin/env python3
# setup_db.py
# Crea la DB SQLite con tablas necesarias y siembra varios usuarios
import sqlite3
import os
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
        rol TEXT NOT NULL DEFAULT 'user',
        intentos_fallidos INTEGER NOT NULL DEFAULT 0,
        bloqueado_hasta TEXT
    )
    """)
    conn.commit()


def seed_user(conn, nombre, password, rol="user"):
    cur = conn.cursor()
    cur.execute("SELECT id FROM usuarios WHERE nombre = ?", (nombre,))
    if cur.fetchone():
        print(f"[seed] usuario '{nombre}' ya existe. Se actualizará su contraseña a la nueva semilla.")
        # opcional: actualizar hash/salt si ya existía
        pw_hash, pw_salt = hash_password(password)
        cur.execute("UPDATE usuarios SET pw_hash = ?, pw_salt = ? WHERE nombre = ?", (pw_hash, pw_salt, nombre))
        conn.commit()
        log_event("DB_ACTION", {"action": "update_user_seed", "user": nombre})
        return
    pw_hash, pw_salt = hash_password(password)
    cur.execute(
        "INSERT INTO usuarios (nombre, pw_hash, pw_salt, rol) VALUES (?,?,?,?)",
        (nombre, pw_hash, pw_salt, rol),
    )
    conn.commit()
    print(f"[seed] usuario '{nombre}' creado (password = '{password}')")
    log_event("DB_ACTION", {"action": "seed_user", "user": nombre})


if __name__ == "__main__":
    ensure_db_dir()
    # Si querés forzar recrear la DB descomenta las siguientes dos líneas:
    # if os.path.exists(DB_PATH):
    #     os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    create_schema(conn)

    # Usuarios semilla Grupo 7: todos con password 'grupo7'
    usuarios = ["augusto", "maite", "maximo", "pedro", "nicole"]
    for u in usuarios:
        seed_user(conn, u, "grupo7", rol="user")

    conn.close()
    print("DB inicializada en", DB_PATH)
