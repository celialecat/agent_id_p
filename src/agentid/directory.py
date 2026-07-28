"""Private protocol namespace for agent contact records."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from .identity import public_key_from_did
from .registry import Registry
from .sqlite_store import connect

Visibility = Literal["public", "bonded_only", "allowlist"]
HANDLE = re.compile(r"^[a-z0-9_-]{3,32}$")


@dataclass(frozen=True)
class ContactRecord:
    handle: str
    did: str
    email: str
    phone: str | None
    webhook: str
    visibility: Visibility
    allowlist: list[str]


class ContactDirectory:
    def __init__(self, database: str = ":memory:") -> None:
        self.connection = connect(database)
        self.connection.execute("""CREATE TABLE IF NOT EXISTS contacts (
            handle TEXT PRIMARY KEY, did TEXT UNIQUE, email TEXT, phone TEXT, webhook TEXT,
            visibility TEXT, allowlist TEXT NOT NULL DEFAULT '[]')""")
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, requester TEXT, handle TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)"""
        )
        self.connection.commit()

    def reserve(self, handle: str, did: str) -> None:
        if not HANDLE.fullmatch(handle):
            raise ValueError("invalid handle")
        if self.connection.execute("SELECT 1 FROM contacts WHERE did=?", (did,)).fetchone():
            raise ValueError("agent already owns a handle")
        try:
            self.connection.execute(
                "INSERT INTO contacts(handle, did, email, phone, webhook, visibility, "
                "allowlist) VALUES (?, ?, '', NULL, '', 'public', '[]')",
                (handle, did),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as error:
            raise ValueError("handle already reserved") from error

    def publish(
        self,
        did: str,
        email: str,
        webhook: str,
        phone: str | None = None,
        visibility: Visibility = "bonded_only",
        allowlist: list[str] | None = None,
    ) -> None:
        email_local, separator, email_domain = email.partition("@")
        if (
            not separator
            or email_domain != "ai_agent"
            or not HANDLE.fullmatch(email_local)
            or urlsplit(webhook).scheme not in {"http", "https"}
            or not urlsplit(webhook).netloc
            or (phone and not re.fullmatch(r"\+[1-9]\d{6,14}", phone))
        ):
            raise ValueError("invalid contact endpoint")
        if visibility not in {"public", "bonded_only", "allowlist"}:
            raise ValueError("invalid contact endpoint")
        normalized_allowlist = _validate_allowlist(allowlist or [])
        reserved = self.connection.execute(
            "SELECT handle FROM contacts WHERE did=?", (did,)
        ).fetchone()
        if reserved is None:
            raise ValueError("handle is not reserved")
        if reserved[0] != email_local:
            raise ValueError("invalid contact endpoint")
        self.connection.execute(
            "UPDATE contacts SET email=?, phone=?, webhook=?, visibility=?, "
            "allowlist=? WHERE did=?",
            (email, phone, webhook, visibility, json.dumps(normalized_allowlist), did),
        )
        self.connection.commit()

    def release(self, did: str) -> None:
        self.connection.execute("DELETE FROM contacts WHERE did=?", (did,))
        self.connection.commit()

    def resolve(
        self, handle: str, requester: str, registry: Registry, bond_balance: int, min_bond: int = 0
    ) -> ContactRecord:
        row = self.connection.execute(
            "SELECT handle,did,email,phone,webhook,visibility,allowlist "
            "FROM contacts WHERE handle=?",
            (handle,),
        ).fetchone()
        if row is None:
            raise KeyError("contact not found")
        requester_record = registry.resolve(requester)
        if requester_record is None or requester_record.status != "active":
            raise PermissionError("requester must be active")
        if row[5] != "public" and bond_balance < min_bond:
            raise PermissionError("requester must be bonded")
        allowlist = _decode_allowlist(row[6])
        if row[5] == "allowlist" and requester not in allowlist:
            raise PermissionError("requester is not allowed")
        self.connection.execute(
            "INSERT INTO audit(requester,handle) VALUES (?,?)", (requester, handle)
        )
        self.connection.commit()
        return ContactRecord(row[0], row[1], row[2], row[3], row[4], row[5], allowlist)

    def audit_entries(self) -> list[tuple[str, str]]:
        return [
            (row[0], row[1])
            for row in self.connection.execute("SELECT requester,handle FROM audit")
        ]


def _validate_allowlist(entries: list[str]) -> list[str]:
    if any(not isinstance(entry, str) for entry in entries):
        raise ValueError("invalid allowlist entry")
    for entry in entries:
        try:
            public_key_from_did(entry)
        except ValueError as error:
            raise ValueError("invalid allowlist entry") from error
    return list(dict.fromkeys(entries))


def _decode_allowlist(value: str) -> list[str]:
    try:
        entries = json.loads(value)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("invalid allowlist entry") from error
    if not isinstance(entries, list):
        raise ValueError("invalid allowlist entry")
    return _validate_allowlist(entries)
