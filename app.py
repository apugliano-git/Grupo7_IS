#!/usr/bin/env python3
# app.py
# Aplicación Tkinter + SQLite: login seguro con bloqueo por intentos y logging

import sqlite3
import os
import time
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox

from utils import (
    verify_password,
    valid_username,
    valid_password,
    log_event,
)

DB_PATH = os.path.join("data", "app.db")
LOCK_THRESHOLD = 5  # intentos fallidos antes de bloqueo
LOCK_DURATION_SECONDS = 60 * 5  # 5 minutos


def get_db_conn():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    return conn


class LoginApp:
    def __init__(self, master):
        self.master = master
        master.title("Grupo 9 — Demo Login Seguro")
        master.resizable(False, False)

        # Username
        tk.Label(master, text="Usuario:").grid(row=0, column=0, sticky="e")
        self.username_var = tk.StringVar()
        self.username_entry = tk.Entry(master, textvariable=self.username_var)
        self.username_entry.grid(row=0, column=1)

        # Password
        tk.Label(master, text="Contraseña:").grid(row=1, column=0, sticky="e")
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(master, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=1, column=1)

        # Buttons
        self.login_btn = tk.Button(master, text="Iniciar sesión", command=self.attempt_login)
        self.login_btn.grid(row=2, column=0, columnspan=2, pady=8)

        # Info label
        self.info_label = tk.Label(master, text="Demo: muestra mitigaciones contra SQLi y manejo de credenciales")
        self.info_label.grid(row=3, column=0, columnspan=2, pady=(6, 0))

    def attempt_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        # Validación básica de inputs
        if not valid_username(username) or not valid_password(password):
            messagebox.showerror("Error", "Credenciales inválidas (formato).")
            log_event("LOGIN_FAIL", {"user": username, "reason": "validation"})
            return

        conn = get_db_conn()
        cur = conn.cursor()
        # CONSULTA PARAMETRIZADA (EVITA SQLI)
        cur.execute("SELECT id, pw_hash, pw_salt, intentos_fallidos, bloqueado_hasta, rol FROM usuarios WHERE nombre = ?", (username,))
        row = cur.fetchone()

        if not row:
            # No dar pistas (no decir "usuario no existe")
            messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
            log_event("LOGIN_FAIL", {"user": username, "reason": "no_user"})
            conn.close()
            return

        uid, pw_hash, pw_salt, intentos_fallidos, bloqueado_hasta, rol = row

        # Manejar bloqueo temporal
        if bloqueado_hasta:
            try:
                blocked_until = datetime.fromisoformat(bloqueado_hasta)
            except Exception:
                blocked_until = None
            if blocked_until and blocked_until > datetime.utcnow():
                # bloqueado
                remaining = int((blocked_until - datetime.utcnow()).total_seconds())
                messagebox.showwarning("Bloqueado", f"Usuario bloqueado temporalmente. Intente en {remaining} s.")
                log_event("LOGIN_BLOCKED", {"user": username, "blocked_until": blocked_until.isoformat()})
                conn.close()
                return
            else:
                # desbloqueamos (el bloqueo expiró)
                cur.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?", (uid,))
                conn.commit()
                intentos_fallidos = 0

        # Verificamos la contraseña con PBKDF2
        ok = verify_password(password, pw_hash, pw_salt)
        if ok:
            # éxito: reset intentos
            cur.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?", (uid,))
            conn.commit()
            messagebox.showinfo("OK", f"Acceso concedido. Rol: {rol}")
            log_event("LOGIN_SUCCESS", {"user": username, "role": rol})
            conn.close()
            return
        else:
            # fallo: incrementar contador
            intentos_fallidos = (intentos_fallidos or 0) + 1
            blocked_until = None
            if intentos_fallidos >= LOCK_THRESHOLD:
                blocked_until = (datetime.utcnow() + timedelta(seconds=LOCK_DURATION_SECONDS)).isoformat()
                cur.execute("UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?", (intentos_fallidos, blocked_until, uid))
                conn.commit()
                messagebox.showwarning("Bloqueado", "Usuario bloqueado temporalmente por múltiples intentos fallidos.")
                log_event("LOGIN_FAIL", {"user": username, "reason": "too_many_attempts", "attempts": intentos_fallidos})
                log_event("LOGIN_BLOCKED", {"user": username, "blocked_until": blocked_until})
            else:
                cur.execute("UPDATE usuarios SET intentos_fallidos = ? WHERE id = ?", (intentos_fallidos, uid))
                conn.commit()
                messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
                log_event("LOGIN_FAIL", {"user": username, "reason": "bad_credentials", "attempts": intentos_fallidos})
            conn.close()
            return


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        messagebox.showerror("Error", f"DB no encontrada. Ejecutá setup_db.py primero. Ruta esperada: {DB_PATH}")
        # in case running from terminal:
        print("DB not found. Run setup_db.py first.")
    else:
        root = tk.Tk()
        app = LoginApp(root)
        root.mainloop()

