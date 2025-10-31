#!/usr/bin/env python3
# migrate_db.py — agrega columnas login_count y last_login si no existen
import sqlite3, os

DB_PATH = os.path.join("data", "app.db")

def ensure_columns():
    if not os.path.exists(DB_PATH):
        print(f"DB no encontrada en {DB_PATH}. Ejecutá primero setup_db.py")
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(usuarios)")
    cols = [r[1] for r in cur.fetchall()]  # nombres de columnas
    if "login_count" not in cols:
        cur.execute("ALTER TABLE usuarios ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0")
        print("Añadida columna login_count")
    if "last_login" not in cols:
        cur.execute("ALTER TABLE usuarios ADD COLUMN last_login TEXT")
        print("Añadida columna last_login")
    conn.commit(); conn.close()
    print("Migración finalizada.")

if __name__ == "__main__":
    ensure_columns()
