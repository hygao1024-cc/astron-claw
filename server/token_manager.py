import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "tokens.db"

# A far-future timestamp (~year 2200) used for "never expires" tokens.
_NEVER_EXPIRES = 9999999999.0


class TokenManager:
    """SQLite-backed token management with sk- prefix and per-token expiry."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self._db_path = db_path
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=DELETE")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens ("
            "  token TEXT PRIMARY KEY,"
            "  created_at REAL NOT NULL"
            ")"
        )
        self._conn.commit()
        self._migrate()

    def _migrate(self):
        """Add name and expires_at columns if missing (backwards-compat)."""
        cols = {
            row[1]
            for row in self._conn.execute("PRAGMA table_info(tokens)").fetchall()
        }
        if "name" not in cols:
            self._conn.execute("ALTER TABLE tokens ADD COLUMN name TEXT DEFAULT ''")
        if "expires_at" not in cols:
            self._conn.execute("ALTER TABLE tokens ADD COLUMN expires_at REAL")
            # Back-fill: old tokens get created_at + 86400
            self._conn.execute(
                "UPDATE tokens SET expires_at = created_at + 86400 WHERE expires_at IS NULL"
            )
        self._conn.commit()

    def generate(self, name: str = "", expires_in: int = 86400) -> str:
        token = "sk-" + secrets.token_hex(24)
        now = time.time()
        expires_at = _NEVER_EXPIRES if expires_in == 0 else now + expires_in
        self._conn.execute(
            "INSERT INTO tokens (token, created_at, name, expires_at) VALUES (?, ?, ?, ?)",
            (token, now, name, expires_at),
        )
        self._conn.commit()
        return token

    def validate(self, token: Optional[str]) -> bool:
        if not token:
            return False
        row = self._conn.execute(
            "SELECT 1 FROM tokens WHERE token = ? AND expires_at >= ?",
            (token, time.time()),
        ).fetchone()
        if row is None:
            return False
        return True

    def update(self, token: str, name: str | None = None, expires_in: int | None = None) -> bool:
        """Update name and/or expiry of an existing token. Returns True if token exists."""
        row = self._conn.execute(
            "SELECT 1 FROM tokens WHERE token = ?", (token,)
        ).fetchone()
        if row is None:
            return False
        if name is not None:
            self._conn.execute("UPDATE tokens SET name = ? WHERE token = ?", (name, token))
        if expires_in is not None:
            expires_at = _NEVER_EXPIRES if expires_in == 0 else time.time() + expires_in
            self._conn.execute("UPDATE tokens SET expires_at = ? WHERE token = ?", (expires_at, token))
        self._conn.commit()
        return True

    def remove(self, token: str) -> None:
        self._conn.execute("DELETE FROM tokens WHERE token = ?", (token,))
        self._conn.commit()

    def list_all(self) -> list[dict]:
        """Return all non-expired tokens."""
        now = time.time()
        rows = self._conn.execute(
            "SELECT token, created_at, name, expires_at FROM tokens WHERE expires_at >= ?",
            (now,),
        ).fetchall()
        return [
            {
                "token": row[0],
                "created_at": row[1],
                "name": row[2] or "",
                "expires_at": row[3],
            }
            for row in rows
        ]

    def cleanup_expired(self) -> int:
        """Remove all expired tokens. Returns count of deleted rows."""
        cur = self._conn.execute(
            "DELETE FROM tokens WHERE expires_at < ?", (time.time(),)
        )
        self._conn.commit()
        return cur.rowcount
