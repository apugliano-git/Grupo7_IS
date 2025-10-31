#!/usr/bin/env python3
# app.py (mejorada UI para Grupo 7)
# Interfaz Tkinter con: login, register, show/hide password, password strength, remember-me, log viewer

import os
import sqlite3
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from utils import (
    verify_password,
    valid_username,
    valid_password,
    log_event,
    LOGFILE,
    hash_password,
)

DB_PATH = os.path.join("data", "app.db")
LOCK_THRESHOLD = 5
LOCK_DURATION_SECONDS = 60 * 5  # 5 min

REMEMBER_FILE = "remember.txt"


def get_db_conn():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    return conn


# ---------------- Helpers ----------------
def read_remembered_user():
    try:
        if os.path.exists(REMEMBER_FILE):
            with open(REMEMBER_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return ""


def write_remembered_user(username):
    try:
        with open(REMEMBER_FILE, "w", encoding="utf-8") as f:
            f.write(username or "")
    except Exception:
        pass


def last_log_entries(n=50):
    if not os.path.exists(LOGFILE):
        return []
    lines = []
    with open(LOGFILE, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                lines.append(ln)
    return lines[-n:]


# ---------------- UI App ----------------
class SecureLoginUI:
    def __init__(self, root):
        self.root = root
        root.title("Grupo 7 — Demo Login Seguro")
        root.geometry("520x360")
        root.resizable(False, False)

        # Styling
        self.font_label = ("Segoe UI", 10)
        self.font_entry = ("Segoe UI", 10)
        self.font_btn = ("Segoe UI", 10, "bold")

        # Main container
        main = ttk.Frame(root, padding=(12, 10, 12, 8))
        main.pack(fill="both", expand=True)

        # --- Top: Title ---
        title = ttk.Label(main, text="Demo: Login seguro (Grupo 7)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, columnspan=3, pady=(0, 8), sticky="w")

        # --- Left frame: form ---
        form = ttk.LabelFrame(main, text="Acceso", padding=(10, 10))
        form.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        # Username
        ttk.Label(form, text="Usuario:", font=self.font_label).grid(row=0, column=0, sticky="e", pady=4)
        self.username_var = tk.StringVar(value=read_remembered_user())
        self.username_entry = ttk.Entry(form, textvariable=self.username_var, font=self.font_entry, width=28)
        self.username_entry.grid(row=0, column=1, pady=4, padx=(6, 0))
        # Password
        ttk.Label(form, text="Contraseña:", font=self.font_label).grid(row=1, column=0, sticky="e", pady=4)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(form, textvariable=self.password_var, font=self.font_entry, width=28, show="*")
        self.password_entry.grid(row=1, column=1, pady=4, padx=(6, 0))
        # Show password
        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, text="Mostrar contraseña", variable=self.show_pw_var, command=self.toggle_show_pw).grid(row=2, column=1, sticky="w", pady=(0, 6))
        # Remember me
        self.remember_var = tk.BooleanVar(value=bool(read_remembered_user()))
        ttk.Checkbutton(form, text="Recordarme", variable=self.remember_var).grid(row=3, column=1, sticky="w", pady=(0, 6))
        # Buttons
        btn_frame = ttk.Frame(form)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(6, 0))
        self.login_btn = ttk.Button(btn_frame, text="Iniciar sesión", command=self.attempt_login)
        self.login_btn.grid(row=0, column=0, padx=(0, 6))
        self.register_btn = ttk.Button(btn_frame, text="Registrarse", command=self.open_register_window)
        self.register_btn.grid(row=0, column=1, padx=(6, 0))

        # --- Right frame: info & logs ---
        info = ttk.LabelFrame(main, text="Información", padding=(10, 10))
        info.grid(row=1, column=1, sticky="nsew")
        # Info labels
        ttk.Label(info, text="Estado:", font=self.font_label).grid(row=0, column=0, sticky="w")
        self.status_msg = tk.StringVar(value="Listo")
        self.status_label = ttk.Label(info, textvariable=self.status_msg, font=self.font_label, foreground="#1f4b99")
        self.status_label.grid(row=0, column=1, sticky="w")
        # Log viewer button
        self.view_logs_btn = ttk.Button(info, text="Ver logs (últimas 50)", command=self.open_logs_window)
        self.view_logs_btn.grid(row=1, column=0, columnspan=2, pady=(8, 6), sticky="we")
        # Quick help text
        help_text = ("Prueba SQLi: intenta `pedro' OR '1'='1` en usuario/contraseña (debe fallar).\n"
                     "Force bloqueo: 6 intentos fallidos -> bloqueo temporal.")
        ttk.Label(info, text=help_text, wraplength=240, font=("Segoe UI", 9)).grid(row=2, column=0, columnspan=2)

        # Status bar bottom
        self.statusbar = ttk.Label(root, text=" ", relief="sunken", anchor="w")
        self.statusbar.pack(side="bottom", fill="x")

        # keyboard bindings
        root.bind("<Return>", lambda e: self.attempt_login())
        # initial focus
        self.username_entry.focus_set()

    def set_status(self, text, sticky=False):
        """Set lower statusbar temporarily (non-sticky shows for 6s)."""
        self.statusbar.config(text=text)
        if not sticky:
            self.root.after(6000, lambda: self.statusbar.config(text=" "))

    def toggle_show_pw(self):
        if self.show_pw_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def attempt_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        # Basic validation
        if not valid_username(username):
            messagebox.showerror("Error", "Usuario inválido (format).")
            log_event("LOGIN_FAIL", {"user": username, "reason": "validation_username"})
            self.set_status("Formato de usuario inválido.")
            return
        if not valid_password(password):
            messagebox.showerror("Error", "Contraseña inválida (mínimo 6 caracteres).")
            log_event("LOGIN_FAIL", {"user": username, "reason": "validation_password"})
            self.set_status("Formato de contraseña inválido.")
            return

        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, pw_hash, pw_salt, intentos_fallidos, bloqueado_hasta, rol FROM usuarios WHERE nombre = ?", (username,))
        row = cur.fetchone()

        if not row:
            messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
            log_event("LOGIN_FAIL", {"user": username, "reason": "no_user"})
            self.set_status("Login fallido.")
            conn.close()
            return

        uid, pw_hash, pw_salt, intentos_fallidos, bloqueado_hasta, rol = row

        # check lock
        if bloqueado_hasta:
            try:
                blocked_until = datetime.fromisoformat(bloqueado_hasta)
            except Exception:
                blocked_until = None
            if blocked_until and blocked_until > datetime.utcnow():
                remaining = int((blocked_until - datetime.utcnow()).total_seconds())
                messagebox.showwarning("Bloqueado", f"Usuario bloqueado. Intenta en {remaining} s.")
                log_event("LOGIN_BLOCKED", {"user": username, "blocked_until": blocked_until.isoformat()})
                self.set_status("Usuario bloqueado temporalmente.", sticky=True)
                conn.close()
                return
            else:
                cur.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?", (uid,))
                conn.commit()
                intentos_fallidos = 0

        ok = verify_password(password, pw_hash, pw_salt)
        if ok:
            cur.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?", (uid,))
            conn.commit()
            log_event("LOGIN_SUCCESS", {"user": username, "role": rol})
            self.set_status(f"Acceso concedido. Rol: {rol}", sticky=True)
            messagebox.showinfo("OK", f"Acceso concedido. Bienvenido {username}.")
            # remember user
            if self.remember_var.get():
                write_remembered_user(username)
            else:
                write_remembered_user("")
            conn.close()
            return
        else:
            intentos_fallidos = (intentos_fallidos or 0) + 1
            if intentos_fallidos >= LOCK_THRESHOLD:
                blocked_until = (datetime.utcnow() + timedelta(seconds=LOCK_DURATION_SECONDS)).isoformat()
                cur.execute("UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?", (intentos_fallidos, blocked_until, uid))
                conn.commit()
                log_event("LOGIN_FAIL", {"user": username, "reason": "too_many_attempts", "attempts": intentos_fallidos})
                log_event("LOGIN_BLOCKED", {"user": username, "blocked_until": blocked_until})
                messagebox.showwarning("Bloqueado", "Usuario bloqueado temporalmente por múltiples intentos.")
                self.set_status("Usuario bloqueado por intentos fallidos.", sticky=True)
            else:
                cur.execute("UPDATE usuarios SET intentos_fallidos = ? WHERE id = ?", (intentos_fallidos, uid))
                conn.commit()
                log_event("LOGIN_FAIL", {"user": username, "reason": "bad_credentials", "attempts": intentos_fallidos})
                messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
                self.set_status(f"Intentos fallidos: {intentos_fallidos}", sticky=False)
            conn.close()
            return

    # ---------------- Register window ----------------
    def open_register_window(self):
        win = tk.Toplevel(self.root)
        win.title("Registrarse - Nuevo usuario")
        win.resizable(False, False)
        frm = ttk.Frame(win, padding=(10, 10))
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Usuario:", font=self.font_label).grid(row=0, column=0, sticky="e", pady=4)
        uvar = tk.StringVar()
        uentry = ttk.Entry(frm, textvariable=uvar, width=28)
        uentry.grid(row=0, column=1, pady=4, padx=(6, 0))

        ttk.Label(frm, text="Contraseña:", font=self.font_label).grid(row=1, column=0, sticky="e", pady=4)
        pvar = tk.StringVar()
        pentry = ttk.Entry(frm, textvariable=pvar, width=28, show="*")
        pentry.grid(row=1, column=1, pady=4, padx=(6, 0))

        showvar = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Mostrar contraseña", variable=showvar, command=lambda: pentry.config(show="" if showvar.get() else "*")).grid(row=2, column=1, sticky="w")

        # password strength bar
        ttk.Label(frm, text="Fuerza contraseña:").grid(row=3, column=0, sticky="e", pady=(6, 0))
        strength = ttk.Progressbar(frm, orient="horizontal", length=180, mode="determinate")
        strength.grid(row=3, column=1, sticky="w", pady=(6, 0))

        # feedback label
        feedback = ttk.Label(frm, text="", font=("Segoe UI", 9))
        feedback.grid(row=4, column=0, columnspan=2, pady=(6, 0))

        def update_strength(*_):
            pw = pvar.get() or ""
            score = 0
            # length
            if len(pw) >= 6:
                score += 30
            if len(pw) >= 10:
                score += 20
            # variety
            if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
                score += 20
            if any(c.isdigit() for c in pw):
                score += 15
            if any(not c.isalnum() for c in pw):
                score += 15
            score = min(100, score)
            strength["value"] = score
            if score < 40:
                feedback.config(text="Débil")
            elif score < 70:
                feedback.config(text="Moderada")
            else:
                feedback.config(text="Fuerte")

        pvar.trace_add("write", update_strength)
        update_strength()

        def do_register():
            u = uvar.get().strip()
            p = pvar.get().strip()
            if not valid_username(u):
                messagebox.showerror("Error", "Usuario inválido. Solo letras, números, . _ - y entre 3-32 chars.")
                return
            if not valid_password(p):
                messagebox.showerror("Error", "Contraseña inválida. Mínimo 6 caracteres.")
                return
            conn = get_db_conn()
            cur = conn.cursor()
            try:
                # verify not exists
                cur.execute("SELECT id FROM usuarios WHERE nombre = ?", (u,))
                if cur.fetchone():
                    messagebox.showerror("Error", "Usuario ya existe.")
                    conn.close()
                    return
                pw_hash, pw_salt = hash_password(p)
                cur.execute("INSERT INTO usuarios (nombre, pw_hash, pw_salt, rol) VALUES (?,?,?,?)", (u, pw_hash, pw_salt, "user"))
                conn.commit()
                log_event("DB_ACTION", {"action": "register_user", "user": u})
                messagebox.showinfo("OK", "Usuario creado correctamente. Podés iniciar sesión.")
                win.destroy()
            except Exception as e:
                messagebox.showerror("Error", "Ocurrió un error al crear el usuario.")
            finally:
                conn.close()

        ttk.Button(frm, text="Crear cuenta", command=do_register).grid(row=5, column=0, columnspan=2, pady=(8, 0))
        uentry.focus_set()

    # ---------------- Log viewer ----------------
    def open_logs_window(self):
        lines = last_log_entries(50)
        win = tk.Toplevel(self.root)
        win.title("Últimas entradas de security.log")
        win.geometry("700x400")
        txt = scrolledtext.ScrolledText(win, wrap="none", font=("Consolas", 10))
        txt.pack(fill="both", expand=True)
        if not lines:
            txt.insert("end", "No hay registros aún.\n")
        else:
            for l in lines:
                txt.insert("end", l + "\n")
        txt.config(state="disabled")


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        messagebox.showerror("Error", f"DB no encontrada. Ejecutá setup_db.py primero. Ruta esperada: {DB_PATH}")
        print("DB not found. Run setup_db.py first.")
    else:
        root = tk.Tk()
        app = SecureLoginUI(root)
        root.mainloop()
