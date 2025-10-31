#!/usr/bin/env python3
# app.py — Grupo 7
# Login para todos + Panel de Administración (solo admins)
# Panel Admin: pestaña Usuarios (tabla + reset de bloqueo + cambiar rol) y pestaña Logs (visor/buscar/exportar)

import os, sqlite3
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

from utils import (
    verify_password, valid_username, valid_password,
    log_event, LOGFILE, hash_password
)

DB_PATH = os.path.join("data", "app.db")
LOCK_THRESHOLD = 5
LOCK_DURATION_SECONDS = 60 * 5
REMEMBER_FILE = "remember.txt"

# --------- helpers ---------
def get_db_conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)

def read_remembered_user():
    try:
        if os.path.exists(REMEMBER_FILE):
            return open(REMEMBER_FILE, "r", encoding="utf-8").read().strip()
    except Exception: pass
    return ""

def write_remembered_user(username):
    try:
        open(REMEMBER_FILE, "w", encoding="utf-8").write(username or "")
    except Exception: pass

def last_log_entries(n=500):
    if not os.path.exists(LOGFILE):
        return []
    with open(LOGFILE, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f]
    return lines[-n:]

# ===================== LOGIN UI =====================
class SecureLoginUI:
    def __init__(self, root):
        self.root = root
        root.title("Grupo 7 — Demo Login Seguro")
        root.geometry("760x460"); root.minsize(720, 440); root.resizable(True, True)

        style = ttk.Style()
        try: style.theme_use("clam")
        except tk.TclError: pass
        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Help.TLabel",  font=("Segoe UI", 9))
        style.configure("Hint.TLabel",  foreground="#1f4b99")
        style.configure("Status.TLabel", anchor="w")

        container = ttk.Frame(root, padding=(14, 12, 14, 10))
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=2)
        container.columnconfigure(1, weight=3)
        container.rowconfigure(1, weight=1)

        ttk.Label(container, text="Demo: Login seguro (Grupo 7)", style="Title.TLabel")\
            .grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        # ---- Izquierda: login ----
        left = ttk.LabelFrame(container, text="Acceso", padding=(12, 10))
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        left.columnconfigure(1, weight=1)

        ttk.Label(left, text="Usuario:").grid(row=0, column=0, sticky="e", pady=6)
        self.username_var = tk.StringVar(value=read_remembered_user())
        self.username_entry = ttk.Entry(left, textvariable=self.username_var, width=28)
        self.username_entry.grid(row=0, column=1, sticky="we", pady=6, padx=(8,0))

        ttk.Label(left, text="Contraseña:").grid(row=1, column=0, sticky="e", pady=6)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(left, textvariable=self.password_var, width=28, show="*")
        self.password_entry.grid(row=1, column=1, sticky="we", pady=6, padx=(8,0))

        self.show_pw_var = tk.BooleanVar(False)
        ttk.Checkbutton(left, text="Mostrar contraseña", variable=self.show_pw_var,
                        command=lambda: self.password_entry.config(show="" if self.show_pw_var.get() else "*"))\
            .grid(row=2, column=1, sticky="w", pady=(0, 4))

        self.remember_var = tk.BooleanVar(value=bool(read_remembered_user()))
        ttk.Checkbutton(left, text="Recordarme", variable=self.remember_var)\
            .grid(row=3, column=1, sticky="w", pady=(0, 8))

        btns = ttk.Frame(left); btns.grid(row=4, column=0, columnspan=2, pady=(2, 0))
        ttk.Button(btns, text="Iniciar sesión", command=self.attempt_login).grid(row=0, column=0, padx=(0,8))
        ttk.Button(btns, text="Registrarse",   command=self.open_register_window).grid(row=0, column=1)

        # ---- Derecha: info ----
        right = ttk.LabelFrame(container, text="Información", padding=(12, 10))
        right.grid(row=1, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)

        self.status_msg = tk.StringVar(value="Listo")
        ttk.Label(right, text="Estado:").grid(row=0, column=0, sticky="w")
        ttk.Label(right, textvariable=self.status_msg, style="Hint.TLabel").grid(row=1, column=0, sticky="w", pady=(0,8))

        help_text = ("Prueba SQLi: intenta `pedro' OR '1'='1` en usuario/contraseña (debe fallar).\n"
                     "Bloqueo: 6 intentos fallidos ⇒ bloqueo temporal.\n"
                     "Panel Admin con logs y usuarios: solo para rol 'admin'.")
        ttk.Label(right, text=help_text, style="Help.TLabel", wraplength=360, justify="left")\
            .grid(row=2, column=0, sticky="we", pady=(10,0))

        # Status bar
        self.statusbar = ttk.Label(root, text=" ", style="Status.TLabel", relief="sunken")
        self.statusbar.pack(side="bottom", fill="x")

        # estado sesión
        self.current_user = None
        self.current_role = None

        root.bind("<Return>", lambda e: self.attempt_login())
        self.username_entry.focus_set()

    def set_status(self, txt, sticky=False):
        self.statusbar.config(text=txt)
        if not sticky:
            self.root.after(5000, lambda: self.statusbar.config(text=" "))

    # -------- login --------
    def attempt_login(self):
        user = (self.username_var.get() or "").strip()
        pw   = (self.password_var.get() or "").strip()

        if not valid_username(user):
            messagebox.showerror("Error", "Usuario inválido (formato).")
            log_event("LOGIN_FAIL", {"user": user, "reason": "validation_username"})
            self.set_status("Formato de usuario inválido."); return
        if not valid_password(pw):
            messagebox.showerror("Error", "Contraseña inválida (mín. 6).")
            log_event("LOGIN_FAIL", {"user": user, "reason": "validation_password"})
            self.set_status("Formato de contraseña inválido."); return

        conn = get_db_conn(); cur = conn.cursor()
        cur.execute("SELECT id, pw_hash, pw_salt, intentos_fallidos, bloqueado_hasta, rol FROM usuarios WHERE nombre = ?", (user,))
        row = cur.fetchone()
        if not row:
            messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
            log_event("LOGIN_FAIL", {"user": user, "reason": "no_user"})
            self.set_status("Login fallido."); conn.close(); return

        uid, pw_hash, pw_salt, intentos, bloqueado_hasta, rol = row

        # bloqueo temporal
        if bloqueado_hasta:
            try: until = datetime.fromisoformat(bloqueado_hasta)
            except Exception: until = None
            if until and until > datetime.utcnow():
                remaining = int((until - datetime.utcnow()).total_seconds())
                messagebox.showwarning("Bloqueado", f"Usuario bloqueado. Intenta en {remaining}s.")
                log_event("LOGIN_BLOCKED", {"user": user, "blocked_until": until.isoformat()})
                self.set_status("Usuario bloqueado temporalmente.", True)
                conn.close(); return
            else:
                cur.execute("UPDATE usuarios SET intentos_fallidos=0, bloqueado_hasta=NULL WHERE id=?", (uid,))
                conn.commit(); intentos = 0

        # verificar password
        if verify_password(pw, pw_hash, pw_salt):
            cur.execute("UPDATE usuarios SET intentos_fallidos=0, bloqueado_hasta=NULL WHERE id=?", (uid,))
            conn.commit()
            log_event("LOGIN_SUCCESS", {"user": user, "role": rol})
            self.current_user, self.current_role = user, rol
            write_remembered_user(user if self.remember_var.get() else "")
            messagebox.showinfo("OK", f"Acceso concedido. Rol: {rol}")
            self.set_status(f"Bienvenido {user} ({rol}).", True)
            conn.close()

            # Si es admin => abrir panel de admins
            if (rol or "").lower() == "admin":
                AdminPanel(self.root, current_user=user)
            return
        else:
            intentos = (intentos or 0) + 1
            if intentos >= LOCK_THRESHOLD:
                until = (datetime.utcnow() + timedelta(seconds=LOCK_DURATION_SECONDS)).isoformat()
                cur.execute("UPDATE usuarios SET intentos_fallidos=?, bloqueado_hasta=? WHERE id=?",
                            (intentos, until, uid))
                conn.commit()
                log_event("LOGIN_FAIL", {"user": user, "reason": "too_many_attempts", "attempts": intentos})
                log_event("LOGIN_BLOCKED", {"user": user, "blocked_until": until})
                messagebox.showwarning("Bloqueado", "Usuario bloqueado por múltiples intentos.")
                self.set_status("Usuario bloqueado por intentos fallidos.", True)
            else:
                cur.execute("UPDATE usuarios SET intentos_fallidos=? WHERE id=?", (intentos, uid))
                conn.commit()
                log_event("LOGIN_FAIL", {"user": user, "reason": "bad_credentials", "attempts": intentos})
                messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
                self.set_status(f"Intentos fallidos: {intentos}")
            conn.close(); return

    # -------- registro --------
    def open_register_window(self):
        win = tk.Toplevel(self.root); win.title("Registrarse - Nuevo usuario"); win.resizable(False, False)
        frm = ttk.Frame(win, padding=(12, 10)); frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Usuario:").grid(row=0, column=0, sticky="e", pady=4)
        uvar = tk.StringVar(); uentry = ttk.Entry(frm, textvariable=uvar, width=28); uentry.grid(row=0, column=1, padx=(8,0), pady=4)

        ttk.Label(frm, text="Contraseña:").grid(row=1, column=0, sticky="e", pady=4)
        pvar = tk.StringVar(); pentry = ttk.Entry(frm, textvariable=pvar, width=28, show="*"); pentry.grid(row=1, column=1, padx=(8,0), pady=4)

        show = tk.BooleanVar(False)
        ttk.Checkbutton(frm, text="Mostrar contraseña", variable=show,
                        command=lambda: pentry.config(show="" if show.get() else "*")).grid(row=2, column=1, sticky="w")

        ttk.Button(frm, text="Crear cuenta", command=lambda: self._do_register(uvar, pvar, win))\
            .grid(row=3, column=0, columnspan=2, pady=(8,0))
        uentry.focus_set()

    def _do_register(self, uvar, pvar, win):
        u = (uvar.get() or "").strip()
        p = (pvar.get() or "").strip()
        if not valid_username(u):
            messagebox.showerror("Error","Usuario inválido (3-32; letras/números/._-)")
            return
        if not valid_password(p):
            messagebox.showerror("Error","Contraseña inválida (mínimo 6)")
            return
        conn=get_db_conn(); cur=conn.cursor()
        cur.execute("SELECT id FROM usuarios WHERE nombre=?", (u,))
        if cur.fetchone():
            messagebox.showerror("Error","Usuario ya existe."); conn.close(); return
        h,s = hash_password(p)
        cur.execute("INSERT INTO usuarios (nombre,pw_hash,pw_salt,rol) VALUES (?,?,?,?)",(u,h,s,"user"))
        conn.commit(); conn.close()
        log_event("DB_ACTION", {"action":"register_user","user":u})
        messagebox.showinfo("OK","Usuario creado. Podés iniciar sesión.")
        win.destroy()

# ===================== ADMIN PANEL =====================
class AdminPanel:
    def __init__(self, parent, current_user="admin"):
        self.parent = parent
        self.win = tk.Toplevel(parent)
        self.win.title(f"Panel de Administración — {current_user}")
        self.win.geometry("900x540"); self.win.minsize(820, 480)
        self.current_user = current_user

        nb = ttk.Notebook(self.win)
        nb.pack(fill="both", expand=True)

        # --- Tab Usuarios ---
        self.tab_users = ttk.Frame(nb, padding=10); nb.add(self.tab_users, text="Usuarios")
        self.build_users_tab()

        # --- Tab Logs ---
        self.tab_logs = ttk.Frame(nb, padding=10); nb.add(self.tab_logs, text="Logs")
        self.build_logs_tab()

    # ---- Usuarios ----
    def build_users_tab(self):
        top = ttk.Frame(self.tab_users); top.pack(fill="x", pady=(0,8))
        ttk.Button(top, text="Refrescar", command=self.load_users).pack(side="left")
        ttk.Button(top, text="Resetear bloqueo", command=self.reset_lock_selected).pack(side="left", padx=6)
        ttk.Button(top, text="Cambiar rol (admin↔user)", command=self.toggle_role_selected).pack(side="left", padx=6)

        cols = ("id","nombre","rol","intentos_fallidos","bloqueado_hasta")
        self.tree = ttk.Treeview(self.tab_users, columns=cols, show="headings", height=16)
        for c, w in zip(cols, (60,180,90,130,260)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.load_users()

    def load_users(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        conn=get_db_conn(); cur=conn.cursor()
        for row in cur.execute("SELECT id,nombre,rol,intentos_fallidos,IFNULL(bloqueado_hasta,'') FROM usuarios ORDER BY nombre"):
            self.tree.insert("", "end", values=row)
        conn.close()

    def _selected_user(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Información","Seleccioná un usuario en la tabla.")
            return None
        vals = self.tree.item(sel[0],"values")
        return {"id": int(vals[0]), "nombre": vals[1], "rol": vals[2]}

    def reset_lock_selected(self):
        u = self._selected_user()
        if not u: return
        conn=get_db_conn(); cur=conn.cursor()
        cur.execute("UPDATE usuarios SET intentos_fallidos=0, bloqueado_hasta=NULL WHERE id=?", (u["id"],))
        conn.commit(); conn.close()
        log_event("DB_ACTION", {"action":"reset_lock","user":u["nombre"]})
        self.load_users()
        messagebox.showinfo("OK", f"Bloqueo reseteado para {u['nombre']}")

    def toggle_role_selected(self):
        u = self._selected_user()
        if not u: return
        new_role = "user" if u["rol"].lower()=="admin" else "admin"
        conn=get_db_conn(); cur=conn.cursor()
        cur.execute("UPDATE usuarios SET rol=? WHERE id=?", (new_role, u["id"]))
        conn.commit(); conn.close()
        log_event("DB_ACTION", {"action":"toggle_role","user":u["nombre"], "new_role":new_role})
        self.load_users()
        messagebox.showinfo("OK", f"Rol de {u['nombre']} cambiado a {new_role}")

    # ---- Logs ----
    def build_logs_tab(self):
        # barra de acciones
        actions = ttk.Frame(self.tab_logs); actions.pack(fill="x", pady=(0,8))
        ttk.Button(actions, text="Refrescar", command=self.populate_logs).pack(side="left")
        ttk.Button(actions, text="Exportar…", command=self.export_logs).pack(side="left", padx=6)

        ttk.Label(actions, text="Buscar:").pack(side="left", padx=(12,4))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(actions, textvariable=self.search_var, width=32)
        search_entry.pack(side="left")
        ttk.Button(actions, text="Ir", command=self.search_in_logs).pack(side="left", padx=4)

        # visor
        self.txt = scrolledtext.ScrolledText(self.tab_logs, wrap="none", font=("Consolas", 10))
        self.txt.pack(fill="both", expand=True)
        self.populate_logs()

    def populate_logs(self):
        lines = last_log_entries(500)
        self.txt.config(state="normal"); self.txt.delete("1.0","end")
        self.txt.insert("end", "\n".join(lines) if lines else "No hay registros aún.\n")
        self.txt.config(state="disabled")

    def search_in_logs(self):
        pat = (self.search_var.get() or "").strip()
        if not pat: return
        self.txt.tag_remove("sel", "1.0", "end")
        self.txt.tag_configure("hit", background="#fff59d")
        self.txt.tag_remove("hit", "1.0", "end")
        start = "1.0"; hits=0
        while True:
            idx = self.txt.search(pat, start, stopindex="end", nocase=True)
            if not idx: break
            last = f"{idx}+{len(pat)}c"
            self.txt.tag_add("hit", idx, last)
            start = last; hits+=1
        if hits==0:
            messagebox.showinfo("Búsqueda", "No hubo coincidencias.")

    def export_logs(self):
        lines = last_log_entries(500)
        if not lines:
            messagebox.showinfo("Exportar", "No hay registros para exportar.")
            return
        path = filedialog.asksaveasfilename(title="Exportar logs",
                                            defaultextension=".txt",
                                            filetypes=[("Texto", "*.txt"), ("Todos", "*.*")],
                                            initialfile="security_export.txt")
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        messagebox.showinfo("Exportar", f"Logs exportados a:\n{path}")

# ------------- main -------------
if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        messagebox.showerror("Error", f"DB no encontrada. Ejecutá setup_db.py primero. ({DB_PATH})")
        print("DB not found. Run setup_db.py first.")
    else:
        root = tk.Tk()
        SecureLoginUI(root)
        root.mainloop()
