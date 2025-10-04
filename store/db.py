import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "bot.db"

def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _conn() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            telegram_id TEXT PRIMARY KEY,
            google_email TEXT
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS tokens (
            telegram_id TEXT PRIMARY KEY,
            refresh_token TEXT NOT NULL,
            access_token TEXT,
            access_expiry INTEGER,
            FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS states (
            state TEXT PRIMARY KEY,
            telegram_id TEXT NOT NULL
        )""")

def save_state(state: str, telegram_id: str):
    with _conn() as con:
        con.execute("REPLACE INTO states(state, telegram_id) VALUES(?,?)", (state, telegram_id))

def pop_telegram_by_state(state: str) -> str | None:
    with _conn() as con:
        row = con.execute("SELECT telegram_id FROM states WHERE state=?", (state,)).fetchone()
        con.execute("DELETE FROM states WHERE state=?", (state,))
        return row["telegram_id"] if row else None

def save_tokens(telegram_id: str, refresh_token: str, access_token: str | None, access_expiry: int | None):
    with _conn() as con:
        con.execute("""REPLACE INTO tokens(telegram_id, refresh_token, access_token, access_expiry)
                       VALUES(?,?,?,?)""", (telegram_id, refresh_token, access_token, access_expiry))

def get_refresh_token(telegram_id: str) -> str | None:
    with _conn() as con:
        row = con.execute("SELECT refresh_token FROM tokens WHERE telegram_id=?", (telegram_id,)).fetchone()
        return row["refresh_token"] if row else None

def update_access_token(telegram_id: str, access_token: str, access_expiry: int | None):
    with _conn() as con:
        con.execute("UPDATE tokens SET access_token=?, access_expiry=? WHERE telegram_id=?",
                    (access_token, access_expiry, telegram_id))

def unlink(telegram_id: str):
    with _conn() as con:
        con.execute("DELETE FROM tokens WHERE telegram_id=?", (telegram_id,))
        con.execute("DELETE FROM users WHERE telegram_id=?", (telegram_id,))
