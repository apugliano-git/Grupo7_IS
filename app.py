# app.py
#!/usr/bin/env python3
# App integrada — versión reforzada con security_hardening
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import sqlite3
from pathlib import Path
from datetime import datetime
from security_hardening import secure_login, secure_register, rotate_log_if_needed, get_conn
from utils import read_remembered_user, write_remembered_user, forget_remembered_user, log_event, DB_PATH

# UI principal
class SecureLoginUI:
    def __init__(self, root):
        self.root = root
        root.title("Login — TP IS Grupo7")
        root.geometry("780x380")
        self.username_var = tk.StringVar(value=read_remembered_user())
        self.password_var = tk.StringVar()
        self.show_pw_var = tk.BooleanVar(value=False)
        self.remember_var = tk.BooleanVar(value=bool(read_remembered_user()))

        container = ttk.Frame(root, padding=(12,12))
        container.pack(expand=True, fill="both")

        left = ttk.Frame(container)
        left.grid(row=0, column=0, sticky="n")

        ttk.Label(left, text="Usuario:").grid(row=0, column=0, sticky="w")
        ttk.Entry(left, textvariable=self.username_var, width=30).grid(row=0, column=1, pady=(0,8))
        ttk.Label(left, text="Contraseña:").grid(row=1, column=0, sticky="w")
        self.password_entry = ttk.Entry(left, show="*", textvariable=self.password_var, width=30)
        self.password_entry.grid(row=1, column=1, pady=(0,8))

        ttk.Checkbutton(left, text="Mostrar contraseña", variable=self.show_pw_var,
                        command=lambda: self.password_entry.config(show="" if self.show_pw_var.get() else "*"))\
            .grid(row=2, column=1, sticky="w", pady=(0,4))

        ttk.Checkbutton(left, text="Recordarme", variable=self.remember_var).grid(row=3, column=1, sticky="w", pady=(0,8))

        # Botón "Olvidar recordarme"
        ttk.Button(left, text="Olvidar recordatorio", command=self.forget_remember).grid(row=3, column=0, sticky="w", pady=(0,8))

        btns = ttk.Frame(left); btns.grid(row=4, column=0, columnspan=2, pady=(2, 0))
        ttk.Button(btns, text="Iniciar sesión", command=self.attempt_login).grid(row=0, column=0, padx=(0,8))
        ttk.Button(btns, text="Registrarse", command=self.open_register_window).grid(row=0, column=1)

        # Panel info a la derecha
        right = ttk.LabelFrame(container, text="Información", padding=(12,10))
        right.grid(row=0, column=1, padx=(12,0), sticky="n")
        self.status = tk.StringVar(value="Listo.")
        ttk.Label(right, textvariable=self.status, width=40).pack()
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(right, text="Logs recientes:").pack(anchor="w")
        self.logs_txt = scrolledtext.ScrolledText(right, height=12, width=50, state="disabled")
        self.logs_txt.pack()

        root.bind("<Return>", lambda e: self.attempt_login())
        self.refresh_logs_view()

    def set_status(self, txt, error=False):
        self.status.set(txt)

    def refresh_logs_view(self):
        rotate_log_if_needed()
        logf = Path("data") / "security.log"
        lines = []
        if logf.exists():
            try:
                lines = logf.read_text(encoding="utf-8").splitlines()[-10:]
            except Exception:
                lines = []
        self.logs_txt.config(state="normal")
        self.logs_txt.delete("1.0", "end")
        self.logs_txt.insert("end", "\n".join(lines))
        self.logs_txt.config(state="disabled")

    def forget_remember(self):
        forget_remembered_user()
        self.username_var.set("")
        self.remember_var.set(False)
        messagebox.showinfo("Recordatorio", "Recordatorio eliminado.")
        self.set_status("Recordatorio borrado.")

    def attempt_login(self):
        user = (self.username_var.get() or "").strip()
        pw = (self.password_var.get() or "").strip()

        # Llamada al login robusto
        success, msg, userrow = secure_login(user, pw, performed_by=user)
        if success:
            # persistir recordatorio si corresponde
            if self.remember_var.get():
                write_remembered_user(user)
            else:
                forget_remembered_user()
            self.set_status("Login correcto.")
            # si es admin, abrir panel, si no, abrir pantalla usuario
            rol = userrow.get("rol") if userrow else None
            if rol == "admin":
                AdminPanel(self.root, current_user=user)
            else:
                UserPanel(self.root, current_user=user, last_login=userrow.get("last_login"))
        else:
            messagebox.showerror("Error", msg)
            self.set_status(msg, True)
        self.refresh_logs_view()

    def open_register_window(self):
        win = tk.Toplevel(self.root)
        win.title("Registro")
        ttk.Label(win, text="Usuario:").grid(row=0, column=0, sticky="w")
        uvar = tk.StringVar()
        ttk.Entry(win, textvariable=uvar).grid(row=0, column=1, pady=(4,8))
        ttk.Label(win, text="Contraseña:").grid(row=1, column=0, sticky="w")
        pvar = tk.StringVar()
        ttk.Entry(win, textvariable=pvar, show="*").grid(row=1, column=1, pady=(4,8))
        def do_register():
            u = (uvar.get() or "").strip()
            p = (pvar.get() or "").strip()
            ok, message = secure_register(u, p)
            if ok:
                messagebox.showinfo("OK", "Usuario creado. Podés iniciar sesión.")
                win.destroy()
            else:
                messagebox.showerror("Error", message)
        ttk.Button(win, text="Crear", command=do_register).grid(row=2, column=0, columnspan=2, pady=(8,8))

# Panel mínimo para usuarios (no admin)
class UserPanel:
    def __init__(self, parent, current_user="user", last_login=None):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Bienvenido — {current_user}")
        ttk.Label(self.win, text=f"Usuario: {current_user}").pack(pady=(8,4))
        ttk.Label(self.win, text=f"Último login (UTC): {last_login or 'Nunca'}").pack(pady=(0,8))
        ttk.Button(self.win, text="Cerrar sesión", command=self.win.destroy).pack(pady=(8,8))

# Panel admin (ya tenías uno; este es minimal para la demo)
class AdminPanel:
    def __init__(self, parent, current_user="admin"):
        self.parent = parent
        self.win = tk.Toplevel(parent)
        self.win.title(f"Panel de Administración — {current_user}")
        self.win.geometry("980x560"); self.win.minsize(900, 520)
        ttk.Label(self.win, text=f"Sesión admin: {current_user}").pack(pady=10)
        ttk.Button(self.win, text="Cerrar", command=self.win.destroy).pack(pady=6)

if __name__ == "__main__":
    # Verificación simple de DB y arranque
    if not DB_PATH.exists():
        messagebox.showerror("Error", f"DB no encontrada. Ejecutá setup_db.py primero. ({DB_PATH})")
        print("DB not found. Run setup_db.py first.")
    else:
        root = tk.Tk()
        SecureLoginUI(root)
        root.mainloop()
