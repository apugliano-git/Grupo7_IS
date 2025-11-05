# app.py — TP IS Grupo 9 | Versión final reforzada y refactorizada

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from pathlib import Path
from datetime import datetime, timezone
import json, dateutil.parser, tzlocal

from security_hardening import secure_login, secure_register, rotate_log_if_needed
from utils import (
    read_remembered_user,
    write_remembered_user,
    forget_remembered_user,
    DB_PATH,
)

# ---------------------------------------------------------------------
# Utilidad: convierte una fecha ISO a formato local y calcula tiempo restante
# ---------------------------------------------------------------------
def _pretty_lock_info(iso_str: str):
    try:
        iso_str = iso_str.replace("Z", "+00:00")
        dt_utc = datetime.fromisoformat(iso_str)
        now_local = datetime.now().astimezone()
        dt_local = dt_utc.astimezone(now_local.tzinfo)
        pretty = dt_local.strftime("%H:%M:%S %d/%m/%Y (%Z)")

        if dt_local > now_local:
            delta = dt_local - now_local
            total_mins = int(delta.total_seconds() // 60)
            h, m = divmod(total_mins, 60)
            return pretty, (h, m)
        return pretty, None
    except Exception:
        return iso_str, None


# ---------------------------------------------------------------------
# Interfaz principal de login y registro
# ---------------------------------------------------------------------
class SecureLoginUI:
    def __init__(self, root):
        self.root = root
        root.title("Login — TP IS Grupo 9")
        root.geometry("780x420")

        # Estado de sesión y preferencias
        self.username_var = tk.StringVar(value=read_remembered_user())
        self.password_var = tk.StringVar()
        self.show_pw_var = tk.BooleanVar(value=False)
        self.remember_var = tk.BooleanVar(value=bool(read_remembered_user()))
        self.status = tk.StringVar(value="Listo.")

        # ----- Layout -----
        container = ttk.Frame(root, padding=12)
        container.pack(expand=True, fill="both")

        # --- Panel Izquierdo: Login ---
        left = ttk.Frame(container)
        left.grid(row=0, column=0, sticky="n")

        ttk.Label(left, text="Usuario:").grid(row=0, column=0, sticky="w")
        ttk.Entry(left, textvariable=self.username_var, width=30).grid(row=0, column=1, pady=(0, 8))

        ttk.Label(left, text="Contraseña:").grid(row=1, column=0, sticky="w")
        self.password_entry = ttk.Entry(left, show="*", textvariable=self.password_var, width=30)
        self.password_entry.grid(row=1, column=1, pady=(0, 8))

        ttk.Checkbutton(
            left, text="Mostrar contraseña", variable=self.show_pw_var,
            command=lambda: self.password_entry.config(show="" if self.show_pw_var.get() else "*")
        ).grid(row=2, column=1, sticky="w", pady=(0, 4))

        ttk.Checkbutton(left, text="Recordarme", variable=self.remember_var)\
            .grid(row=3, column=1, sticky="w", pady=(0, 8))
        ttk.Button(left, text="Olvidar recordatorio", command=self.forget_remember)\
            .grid(row=3, column=0, sticky="w", pady=(0, 8))

        btns = ttk.Frame(left); btns.grid(row=4, column=0, columnspan=2, pady=(2, 0))
        ttk.Button(btns, text="Iniciar sesión", command=self.attempt_login).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(btns, text="Registrarse", command=self.open_register_window).grid(row=0, column=1)

        # --- Panel Derecho: Estado y Logs ---
        right = ttk.LabelFrame(container, text="Información", padding=10)
        right.grid(row=0, column=1, padx=(12, 0), sticky="n")

        ttk.Label(right, textvariable=self.status, width=40).pack()
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(right, text="Logs recientes:").pack(anchor="w")

        self.logs_txt = scrolledtext.ScrolledText(right, height=12, width=50, state="disabled")
        self.logs_txt.pack()

        ttk.Button(right, text="Limpiar log mostrado", command=self.clear_log_view).pack(pady=(6, 4))
        ttk.Button(right, text="Vaciar archivo de log", command=self.clear_log_file).pack(pady=(0, 8))

        root.bind("<Return>", lambda e: self.attempt_login())
        self.refresh_logs_view()

    # -----------------------------------------------------------------
    # Logs y estado de interfaz
    # -----------------------------------------------------------------
    def set_status(self, txt: str, error: bool = False):
        self.status.set(txt)

    def refresh_logs_view(self):
        """Muestra las últimas 10 líneas del log de seguridad."""
        rotate_log_if_needed()
        logf = Path("data") / "security.log"
        lines = []
        if logf.exists():
            try:
                lines = logf.read_text(encoding="utf-8").splitlines()[-10:]
            except Exception:
                pass
        self.logs_txt.config(state="normal")
        self.logs_txt.delete("1.0", "end")
        self.logs_txt.insert("end", "\n".join(lines))
        self.logs_txt.config(state="disabled")

    def clear_log_view(self):
        self.logs_txt.config(state="normal")
        self.logs_txt.delete("1.0", "end")
        self.logs_txt.config(state="disabled")
        self.set_status("Log visual limpiado.")

    def clear_log_file(self):
        try:
            (Path("data") / "security.log").write_text("", encoding="utf-8")
            self.clear_log_view()
            self.set_status("Archivo de log vaciado.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo vaciar el log: {e}")

    # -----------------------------------------------------------------
    # Funciones de cuenta
    # -----------------------------------------------------------------
    def forget_remember(self):
        forget_remembered_user()
        self.username_var.set("")
        self.remember_var.set(False)
        messagebox.showinfo("Recordatorio", "Recordatorio eliminado.")
        self.set_status("Recordatorio borrado.")

    # -----------------------------------------------------------------
    # Lógica principal de autenticación
    # -----------------------------------------------------------------
    def attempt_login(self):
        from security_hardening import get_conn
        user, pw = self.username_var.get().strip(), self.password_var.get().strip()
        success, msg, userrow = secure_login(user, pw, performed_by=user)

        if success:
            if self.remember_var.get(): write_remembered_user(user)
            else: forget_remembered_user()

            self.set_status("Login correcto.")
            rol = userrow.get("rol") if userrow else None
            if rol == "admin":
                AdminPanel(self.root, current_user=user)
            else:
                UserPanel(self.root, current_user=user, last_login=userrow.get("last_login"))
            self.refresh_logs_view()
            return

        # Login fallido → mostramos intentos y tiempo restante
        intentos, bloqueado = None, None
        try:
            conn = get_conn(); cur = conn.cursor()
            cur.execute("SELECT intentos_fallidos, bloqueado_hasta FROM usuarios WHERE nombre = ?", (user,))
            if row := cur.fetchone():
                intentos, bloqueado = row["intentos_fallidos"], row["bloqueado_hasta"]
        finally:
            try: conn.close()
            except Exception: pass

        detalles = ""
        if bloqueado:
            pretty_dt, restante = _pretty_lock_info(bloqueado)
            if restante:
                h, m = restante
                detalles = f"\nPodrás volver a intentar a las {pretty_dt} (en {h}h {m}m)."
            else:
                detalles = f"\nPodrás volver a intentar a las {pretty_dt}."

        final_msg = f"{msg}\nIntentos fallidos: {intentos or 0}." + detalles
        messagebox.showerror("Error", final_msg)
        self.set_status(final_msg, True)
        self.refresh_logs_view()

    def open_register_window(self):
        """Subventana para registrar un nuevo usuario."""
        win = tk.Toplevel(self.root)
        win.title("Registro")
        ttk.Label(win, text="Usuario:").grid(row=0, column=0, sticky="w")
        uvar = tk.StringVar(); ttk.Entry(win, textvariable=uvar).grid(row=0, column=1, pady=(4, 8))
        ttk.Label(win, text="Contraseña:").grid(row=1, column=0, sticky="w")
        pvar = tk.StringVar(); ttk.Entry(win, textvariable=pvar, show="*").grid(row=1, column=1, pady=(4, 8))

        def do_register():
            u, p = uvar.get().strip(), pvar.get().strip()
            ok, msg = secure_register(u, p)
            messagebox.showinfo("OK", "Usuario creado.") if ok else messagebox.showerror("Error", msg)
            if ok: win.destroy()

        ttk.Button(win, text="Crear", command=do_register).grid(row=2, column=0, columnspan=2, pady=(8, 8))


# ---------------------------------------------------------------------
# Panel de usuario (vista informativa)
# ---------------------------------------------------------------------
class UserPanel:
    def __init__(self, parent, current_user="user", last_login=None):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Bienvenido — {current_user}")

        # Fecha formateada de último login
        human_last = "Nunca"
        if last_login:
            try:
                dt = dateutil.parser.isoparse(last_login)
                local_tz = tzlocal.get_localzone()
                dt_local = dt.astimezone(local_tz)
                human_last = dt_local.strftime("%d-%m-%Y %H:%M:%S (%Z)")
            except Exception:
                human_last = last_login

        ttk.Label(self.win, text=f"Usuario: {current_user}").pack(pady=(8, 4))
        ttk.Label(self.win, text=f"Último login: {human_last}").pack(pady=(0, 8))
        ttk.Button(self.win, text="Cerrar sesión", command=self.win.destroy).pack(pady=(8, 8))


# ---------------------------------------------------------------------
# Panel de administración: gestión de usuarios y auditoría
# ---------------------------------------------------------------------
class AdminPanel:
    def __init__(self, parent, current_user="admin"):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Panel de Administración — {current_user}")
        self.win.geometry("900x560")

        ttk.Label(self.win, text=f"Sesión admin: {current_user}", font=("Segoe UI", 11, "bold")).pack(pady=6)

        # --- Usuarios ---
        frame_users = ttk.LabelFrame(self.win, text="Gestión de usuarios", padding=8)
        frame_users.pack(fill="x", padx=10, pady=5)

        self.tree = ttk.Treeview(frame_users, columns=("rol", "intentos", "bloqueado"), show="headings", height=6)
        for col, text, w in [("rol", "Rol", 120), ("intentos", "Intentos fallidos", 130), ("bloqueado", "Bloqueado hasta", 240)]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w, anchor="center")
        self.tree.pack(fill="x", padx=5, pady=5)

        btns = ttk.Frame(frame_users); btns.pack(fill="x", pady=(0, 6))
        ttk.Button(btns, text="Actualizar", command=self.load_users).pack(side="left", padx=4)
        ttk.Button(btns, text="Promover a Admin", command=lambda: self._update_role("admin")).pack(side="left", padx=4)
        ttk.Button(btns, text="Revertir a Usuario", command=lambda: self._update_role("user")).pack(side="left", padx=4)
        ttk.Button(btns, text="Resetear intentos", command=self.reset_attempts).pack(side="left", padx=4)
        self.tree.bind("<Double-1>", lambda e: self.filter_events_for_selected_user())

        # --- Logs de eventos ---
        frame_logs = ttk.LabelFrame(self.win, text="Eventos recientes (quién hizo qué)", padding=8)
        frame_logs.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        self.log_table = ttk.Treeview(frame_logs, columns=("ts", "event", "user", "by", "reason"), show="headings", height=12)
        for col, text, w in [("ts", "Fecha", 190), ("event", "Evento", 170),
                             ("user", "Usuario afectado", 180), ("by", "Hecho por", 160),
                             ("reason", "Motivo/Detalle", 180)]:
            self.log_table.heading(col, text=text)
            self.log_table.column(col, width=w, anchor="w")
        self.log_table.pack(fill="both", expand=True)

        ttk.Button(frame_logs, text="Refrescar", command=self.load_logs).pack(side="left", padx=4, pady=6)
        ttk.Button(frame_logs, text="Quitar filtro", command=lambda: self.load_logs()).pack(side="left", padx=4, pady=6)
        ttk.Button(self.win, text="Cerrar", command=self.win.destroy).pack(pady=6)

        self.load_users(); self.load_logs()

    def load_users(self):
        from security_hardening import get_conn
        self.tree.delete(*self.tree.get_children())
        conn = get_conn(); cur = conn.cursor()
        cur.execute("SELECT nombre, rol, intentos_fallidos, bloqueado_hasta FROM usuarios ORDER BY nombre")
        for nombre, rol, intentos, bloqueado in cur.fetchall():
            self.tree.insert("", "end", iid=nombre, values=(rol, intentos or 0, bloqueado or "-"))
        conn.close()

    def _update_role(self, new_role):
        sel = self.tree.selection()
        if not sel: return messagebox.showinfo("Atención", "Seleccioná un usuario.")
        user = sel[0]
        from security_hardening import get_conn, audit_event
        conn = get_conn(); cur = conn.cursor()
        cur.execute("UPDATE usuarios SET rol = ? WHERE nombre = ?", (new_role, user))
        conn.commit(); conn.close()
        audit_event("ROLE_CHANGED", {"user": user, "new_role": new_role, "by": "admin_panel"})
        self.load_users(); self.load_logs()
        messagebox.showinfo("OK", f"Rol de {user} actualizado a {new_role}.")

    def reset_attempts(self):
        sel = self.tree.selection()
        if not sel: return messagebox.showinfo("Atención", "Seleccioná un usuario.")
        user = sel[0]
        from security_hardening import get_conn, audit_event
        conn = get_conn(); cur = conn.cursor()
        cur.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE nombre = ?", (user,))
        conn.commit(); conn.close()
        audit_event("ADMIN_RESET_ATTEMPTS", {"user": user, "by": "admin_panel"})
        self.load_users(); self.load_logs()
        messagebox.showinfo("OK", f"Intentos de {user} reseteados.")

    def _fmt_ts(self, ts_raw):
        try:
            return datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            return ts_raw

    def _push_event_row(self, evt):
        ts = self._fmt_ts(evt.get("ts", ""))
        self.log_table.insert("", "end", values=(
            ts, evt.get("event", ""), evt.get("user", ""),
            evt.get("by", ""), evt.get("reason", "")
        ))

    def load_logs(self, for_user=None):
        self.log_table.delete(*self.log_table.get_children())
        path = Path("data") / "security.log"
        if not path.exists(): return
        try:
            for line in path.read_text(encoding="utf-8").splitlines()[-50:]:
                try: evt = json.loads(line)
                except Exception: continue
                if for_user and evt.get("user") != for_user and evt.get("by") != for_user:
                    continue
                self._push_event_row(evt)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo leer el log: {e}")

    def filter_events_for_selected_user(self):
        sel = self.tree.selection()
        if sel: self.load_logs(for_user=sel[0])


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
if __name__ == "__main__":
    if not DB_PATH.exists():
        messagebox.showerror("Error", f"Base de datos no encontrada. Ejecutá setup_db.py primero. ({DB_PATH})")
        print("DB not found.")
    else:
        root = tk.Tk()
        SecureLoginUI(root)
        root.mainloop()
