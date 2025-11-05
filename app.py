#!/usr/bin/env python3
# app.py — Versión final reforzada (TP IS Grupo 9)
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from pathlib import Path
from security_hardening import secure_login, secure_register, rotate_log_if_needed
from utils import read_remembered_user, write_remembered_user, forget_remembered_user, DB_PATH
from datetime import datetime, timezone
import dateutil.parser
import tzlocal


# -------------------- UI PRINCIPAL --------------------

def _pretty_lock_info(iso_str: str):
    """
    Recibe ISO (ej. '2025-11-05T21:38:55.315604+00:00') y devuelve:
    - texto local 'HH:MM:SS dd/mm/YYYY (TZ)'
    - tupla (horas, minutos) restantes si el bloqueo sigue vigente; si no, None
    """
    try:
        iso_str = iso_str.replace("Z", "+00:00")          # soporta 'Z'
        dt_utc = datetime.fromisoformat(iso_str)          # datetime con tz
        now_local = datetime.now().astimezone()           # ahora en tz local
        dt_local = dt_utc.astimezone(now_local.tzinfo)    # convertimos a local
        pretty = dt_local.strftime("%H:%M:%S %d/%m/%Y (%Z)")

        if dt_local > now_local:
            delta = dt_local - now_local
            total_mins = int(delta.total_seconds() // 60)
            h, m = divmod(total_mins, 60)
            return pretty, (h, m)
        else:
            return pretty, None
    except Exception:
        return iso_str, None

class SecureLoginUI:
    def __init__(self, root):
        self.root = root
        root.title("Login — TP IS Grupo 9")
        root.geometry("780x420")

        # ---- Estado ----
        self.username_var = tk.StringVar(value=read_remembered_user())
        self.password_var = tk.StringVar()
        self.show_pw_var  = tk.BooleanVar(value=False)
        self.remember_var = tk.BooleanVar(value=bool(read_remembered_user()))
        self.status       = tk.StringVar(value="Listo.")

        # ---- Layout base ----
        container = ttk.Frame(root, padding=(12, 12))
        container.pack(expand=True, fill="both")

        # ---- Columna izquierda (form login) ----
        left = ttk.Frame(container)
        left.grid(row=0, column=0, sticky="n")

        ttk.Label(left, text="Usuario:").grid(row=0, column=0, sticky="w")
        ttk.Entry(left, textvariable=self.username_var, width=30)\
            .grid(row=0, column=1, pady=(0, 8))

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

        # Botones de acción
        btns = ttk.Frame(left); btns.grid(row=4, column=0, columnspan=2, pady=(2, 0))
        ttk.Button(btns, text="Iniciar sesión", command=self.attempt_login)\
            .grid(row=0, column=0, padx=(0, 8))
        ttk.Button(btns, text="Registrarse",   command=self.open_register_window)\
            .grid(row=0, column=1)

        # ---- Columna derecha (estado + logs) ----
        right = ttk.LabelFrame(container, text="Información", padding=(12, 10))
        right.grid(row=0, column=1, padx=(12, 0), sticky="n")

        ttk.Label(right, textvariable=self.status, width=40).pack()
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(right, text="Logs recientes:").pack(anchor="w")

        self.logs_txt = scrolledtext.ScrolledText(right, height=12, width=50, state="disabled")
        self.logs_txt.pack()

        ttk.Button(right, text="Limpiar log mostrado", command=self.clear_log_view)\
            .pack(pady=(6, 4))
        ttk.Button(right, text="Vaciar archivo de log", command=self.clear_log_file)\
            .pack(pady=(0, 8))

        root.bind("<Return>", lambda e: self.attempt_login())
        self.refresh_logs_view()

    # ---------------- Helpers UI ----------------
    def set_status(self, txt: str, error: bool = False):
        self.status.set(txt)

    def refresh_logs_view(self):
        """Muestra las últimas 10 líneas del archivo de log."""
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

    # ---------------- Botones de log ----------------
    def clear_log_view(self):
        """Limpia el texto mostrado (solo en pantalla)."""
        self.logs_txt.config(state="normal")
        self.logs_txt.delete("1.0", "end")
        self.logs_txt.config(state="disabled")
        self.set_status("Log visual limpiado.")

    def clear_log_file(self):
        """Vacía el archivo físico de log y limpia la vista."""
        log_path = Path("data") / "security.log"
        try:
            log_path.write_text("", encoding="utf-8")
            self.clear_log_view()
            self.set_status("Archivo de log vaciado.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo vaciar el log: {e}")

    # ---------------- Recordarme ----------------
    def forget_remember(self):
        forget_remembered_user()
        self.username_var.set("")
        self.remember_var.set(False)
        messagebox.showinfo("Recordatorio", "Recordatorio eliminado.")
        self.set_status("Recordatorio borrado.")

    # ---------------- Acciones principales ----------------
    def attempt_login(self):
        from security_hardening import get_conn  # solo para leer intentos/bloqueo

        user = (self.username_var.get() or "").strip()
        pw   = (self.password_var.get() or "").strip()

        success, msg, userrow = secure_login(user, pw, performed_by=user)

        if success:
            if self.remember_var.get():
                write_remembered_user(user)
            else:
                forget_remembered_user()

            self.set_status("Login correcto.")
            rol = userrow.get("rol") if userrow else None
            if rol == "admin":
                AdminPanel(self.root, current_user=user)
            else:
                UserPanel(self.root, current_user=user, last_login=userrow.get("last_login"))
            self.refresh_logs_view()
            return

        # --- fallo de login: mensaje claro con intentos y hora de desbloqueo ---
        intentos = None
        bloqueado_hasta_iso = None
        try:
            conn = get_conn(); cur = conn.cursor()
            cur.execute("SELECT intentos_fallidos, bloqueado_hasta FROM usuarios WHERE nombre = ?", (user,))
            row = cur.fetchone()
            if row:
                intentos = row["intentos_fallidos"]
                bloqueado_hasta_iso = row["bloqueado_hasta"]
        finally:
            try:
                conn.close()
            except Exception:
                pass

        detalles = ""
        if bloqueado_hasta_iso:
            pretty_dt, restante = _pretty_lock_info(bloqueado_hasta_iso)
            if restante:
                h, m = restante
                detalles = f"\nPodrás volver a intentar a las {pretty_dt} (en {h}h {m}m)."
            else:
                detalles = f"\nPodrás volver a intentar a las {pretty_dt}."

        if intentos is not None:
            final_msg = f"{msg}\nIntentos fallidos: {intentos}." + (detalles if detalles else "")
        else:
            final_msg = msg + (detalles if detalles else "")

        messagebox.showerror("Error", final_msg)
        self.set_status(final_msg, True)
        self.refresh_logs_view()

    def open_register_window(self):
        win = tk.Toplevel(self.root)
        win.title("Registro")
        ttk.Label(win, text="Usuario:").grid(row=0, column=0, sticky="w")
        uvar = tk.StringVar(); ttk.Entry(win, textvariable=uvar).grid(row=0, column=1, pady=(4, 8))
        ttk.Label(win, text="Contraseña:").grid(row=1, column=0, sticky="w")
        pvar = tk.StringVar(); ttk.Entry(win, textvariable=pvar, show="*").grid(row=1, column=1, pady=(4, 8))

        def do_register():
            u = (uvar.get() or "").strip()
            p = (pvar.get() or "").strip()
            ok, message = secure_register(u, p)
            if ok:
                messagebox.showinfo("OK", "Usuario creado. Podés iniciar sesión.")
                win.destroy()
            else:
                messagebox.showerror("Error", message)

        ttk.Button(win, text="Crear", command=do_register)\
            .grid(row=2, column=0, columnspan=2, pady=(8, 8))

# -------------------- USER PANEL --------------------
class UserPanel:
    def __init__(self, parent, current_user="user", last_login=None):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Bienvenido — {current_user}")

        # Formatear last_login si viene
        human_last = "Nunca"
        if last_login:
            try:
                # parsear ISO (dateutil es robusto). Si no tenés python-dateutil,
                # usamos datetime.fromisoformat como fallback.
                try:
                    dt = dateutil.parser.isoparse(last_login)
                except Exception:
                    dt = datetime.fromisoformat(last_login)

                # convertir a tz local (si quieres la hora local)
                # tzlocal devuelve la zona local; si no está instalada, mostramos UTC
                try:
                    local_tz = tzlocal.get_localzone()
                    dt_local = dt.astimezone(local_tz)
                    tzname = dt_local.tzname() or ""
                except Exception:
                    dt_local = dt.astimezone(timezone.utc)
                    tzname = "UTC"

                human_last = dt_local.strftime("%d-%m-%Y %H:%M:%S") + f" ({tzname})"
            except Exception:
                human_last = last_login  # fallback: mostrar raw

        ttk.Label(self.win, text=f"Usuario: {current_user}").pack(pady=(8, 4))
        ttk.Label(self.win, text=f"Último login: {human_last}").pack(pady=(0, 8))
        ttk.Button(self.win, text="Cerrar sesión", command=self.win.destroy).pack(pady=(8, 8))

# -------------------- ADMIN PANEL --------------------
import json
from datetime import datetime

class AdminPanel:
    def __init__(self, parent, current_user="admin"):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Panel de Administración — {current_user}")
        self.win.geometry("900x560")

        ttk.Label(self.win, text=f"Sesión admin: {current_user}", font=("Segoe UI", 11, "bold")).pack(pady=6)

        # ===== Usuarios =====
        frame_users = ttk.LabelFrame(self.win, text="Gestión de usuarios", padding=8)
        frame_users.pack(fill="x", expand=False, padx=10, pady=5)

        self.tree = ttk.Treeview(frame_users, columns=("rol","intentos","bloqueado"), show="headings", height=6)
        self.tree.heading("rol", text="Rol");                 self.tree.column("rol", width=120, anchor="center")
        self.tree.heading("intentos", text="Intentos fallidos"); self.tree.column("intentos", width=130, anchor="center")
        self.tree.heading("bloqueado", text="Bloqueado hasta");  self.tree.column("bloqueado", width=240, anchor="center")
        self.tree.pack(fill="x", expand=False, padx=5, pady=5)

        btns = ttk.Frame(frame_users); btns.pack(fill="x", pady=(0,6))
        ttk.Button(btns, text="Actualizar lista",   command=self.load_users).pack(side="left", padx=4)
        ttk.Button(btns, text="Promover a Admin",   command=lambda: self._update_role("admin")).pack(side="left", padx=4)
        ttk.Button(btns, text="Revertir a Usuario", command=lambda: self._update_role("user")).pack(side="left", padx=4)
        ttk.Button(btns, text="Resetear intentos",  command=self.reset_attempts).pack(side="left", padx=4)

        # Doble click en usuario -> filtra eventos de ese usuario
        self.tree.bind("<Double-1>", lambda e: self.filter_events_for_selected_user())

        # ===== Eventos (quién hizo qué) =====
        frame_logs = ttk.LabelFrame(self.win, text="Eventos recientes (quién hizo qué)", padding=8)
        frame_logs.pack(fill="both", expand=True, padx=10, pady=(0,8))

        self.log_table = ttk.Treeview(
            frame_logs,
            columns=("ts","event","user","by","reason"),
            show="headings",
            height=12
        )
        for col, text, w in [
            ("ts","Fecha",190),
            ("event","Evento",170),
            ("user","Usuario afectado",180),
            ("by","Hecho por",160),
            ("reason","Motivo/Detalle",180),
        ]:
            self.log_table.heading(col, text=text)
            self.log_table.column(col, width=w, anchor="w")
        self.log_table.pack(fill="both", expand=True)

        # Botones de eventos
        btns2 = ttk.Frame(frame_logs); btns2.pack(fill="x", pady=6)
        ttk.Button(btns2, text="Refrescar", command=self.load_logs).pack(side="left", padx=4)
        ttk.Button(btns2, text="Quitar filtro", command=lambda: self.load_logs()).pack(side="left", padx=4)

        # Cerrar
        ttk.Button(self.win, text="Cerrar", command=self.win.destroy).pack(pady=6)

        # Carga inicial
        self.load_users()
        self.load_logs()

    # ---------- Usuarios ----------
    def load_users(self):
        from security_hardening import get_conn
        self.tree.delete(*self.tree.get_children())
        conn = get_conn(); cur = conn.cursor()
        try:
            cur.execute("SELECT nombre, rol, intentos_fallidos, bloqueado_hasta FROM usuarios ORDER BY nombre")
            for nombre, rol, intentos, bloqueado in cur.fetchall():
                self.tree.insert("", "end", iid=nombre, values=(rol, intentos or 0, bloqueado or "-"))
        finally:
            conn.close()

    def _update_role(self, new_role: str):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Atención", "Seleccioná un usuario.")
            return
        user = sel[0]
        from security_hardening import get_conn, audit_event
        conn = get_conn(); cur = conn.cursor()
        cur.execute("UPDATE usuarios SET rol = ? WHERE nombre = ?", (new_role, user))
        conn.commit(); conn.close()
        audit_event("ROLE_CHANGED", {"user": user, "new_role": new_role, "by": "admin_panel"})
        self.load_users()
        self.load_logs()
        messagebox.showinfo("OK", f"Rol de {user} actualizado a {new_role}.")

    def reset_attempts(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Atención", "Seleccioná un usuario.")
            return
        user = sel[0]
        from security_hardening import get_conn, audit_event
        conn = get_conn(); cur = conn.cursor()
        cur.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE nombre = ?", (user,))
        conn.commit(); conn.close()
        audit_event("ADMIN_RESET_ATTEMPTS", {"user": user, "by": "admin_panel"})
        self.load_users()
        self.load_logs()
        messagebox.showinfo("OK", f"Intentos de {user} reseteados.")

    # ---------- Eventos (quién hizo qué) ----------
    def _fmt_ts(self, ts_raw: str) -> str:
        # Acepta ISO con o sin zona; muestra dd/mm/yyyy HH:MM:SS
        try:
            dt = datetime.fromisoformat(ts_raw.replace("Z","+00:00"))
            return dt.strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            return ts_raw

    def _push_event_row(self, evt: dict):
        ts   = self._fmt_ts(evt.get("ts",""))
        ev   = evt.get("event","")
        user = evt.get("user","")
        by   = evt.get("by","")
        reason = evt.get("reason","")
        self.log_table.insert("", "end", values=(ts, ev, user, by, reason))

    def load_logs(self, for_user: str | None = None):
        self.log_table.delete(*self.log_table.get_children())
        path = Path("data") / "security.log"
        if not path.exists():
            return
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            # últimas 50
            for line in lines[-50:]:
                try:
                    evt = json.loads(line)
                except Exception:
                    continue
                if for_user and evt.get("user") != for_user and evt.get("by") != for_user:
                    continue
                self._push_event_row(evt)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo leer el log: {e}")

    def filter_events_for_selected_user(self):
        sel = self.tree.selection()
        if not sel:
            return
        user = sel[0]
        self.load_logs(for_user=user)

# -------------------- MAIN --------------------
if __name__ == "__main__":
    if not DB_PATH.exists():
        messagebox.showerror("Error", f"DB no encontrada. Ejecutá setup_db.py primero. ({DB_PATH})")
        print("DB not found. Run setup_db.py first.")
    else:
        root = tk.Tk()
        SecureLoginUI(root)
        root.mainloop()
