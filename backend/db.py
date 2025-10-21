import os
import sqlite3
from pathlib import Path

# Database directory inside the app (can be overridden by env)
DEFAULT_DB_DIR = Path(__file__).resolve().parent / "database"
DB_DIR = Path(os.environ.get("DB_DIR", DEFAULT_DB_DIR))
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("DB_PATH", DB_DIR / "app.db"))


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Ensure FK cascades are enforced in SQLite
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            position INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_todos_user_position ON todos(user_id, position);")
    # App settings key-value table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    # Seed defaults if not present
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('registration_open','1')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('smtp_enabled','0')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('smtp_host','')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('smtp_port','')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('smtp_username','')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('smtp_password','')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('smtp_use_tls','1')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('smtp_sender','')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('smtp_tls_skip_verify','0')")
    # Turnstile (captcha) defaults
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('turnstile_enabled','0')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('turnstile_site_key','')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('turnstile_secret_key','')")
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('turnstile_tls_skip_verify','0')")
    conn.commit()
    conn.close()
