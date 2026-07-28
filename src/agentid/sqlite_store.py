"""SQLite connection defaults shared by all protocol stores."""

from __future__ import annotations

import sqlite3

SQLITE_BUSY_TIMEOUT_MS = 30_000


def connect(database: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
    connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA journal_mode=WAL")
    return connection
