#!/usr/bin/env python3
# migrate_db.py — actualiza la estructura de la DB si faltan columnas
from security_hardening import DB_PATH, audit_event
import sqlite3

def ensure_columns():
    """Agrega las columnas 'login_count' y 'last_login' si no existen."""
    if not DB_PATH.exists():
        print(f"[!] DB no encontrada en {DB_PATH}. Ejecutá primero setup_db.py.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(usuarios)")
    cols = [r[1] for r in cur.fetchall()]
    added = []

    if "login_count" not in cols:
        cur.execute("ALTER TABLE usuarios ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0")
        added.append("login_count")

    if "last_login" not in cols:
        cur.execute("ALTER TABLE usuarios ADD COLUMN last_login TEXT")
        added.append("last_login")

    conn.commit(); conn.close()

    if added:
        print(f"[✓] Columnas agregadas: {', '.join(added)}")
        audit_event("DB_MIGRATION", {"added_columns": added})
    else:
        print("[=] No se requerían cambios; estructura ya actualizada.")
        audit_event("DB_MIGRATION", {"added_columns": []})

if __name__ == "__main__":
    ensure_columns()
