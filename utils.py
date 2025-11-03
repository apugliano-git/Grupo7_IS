# utils.py
import os, json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "app.db"
LOGFILE = DATA_DIR / "security.log"
REMEMBER_FILE = BASE_DIR / "remember.txt"

def log_event(e, details=None):
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": e}
    if isinstance(details, dict):
        entry.update(details)
    try:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

def read_remembered_user():
    try:
        if REMEMBER_FILE.exists():
            return REMEMBER_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return ""

def write_remembered_user(username: str):
    try:
        REMEMBER_FILE.write_text(username or "", encoding="utf-8")
    except Exception:
        pass

def forget_remembered_user():
    try:
        if REMEMBER_FILE.exists():
            REMEMBER_FILE.unlink()
    except Exception:
        pass
