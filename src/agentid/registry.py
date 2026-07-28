"""SQLite-backed agent registry."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .attestation import OperatorAttestation
from .sqlite_store import connect

STATUSES = {"active", "suspended", "revoked"}


@dataclass(frozen=True)
class AgentRecord:
    did: str
    public_key: bytes
    operator_id: str
    scopes: list[str]
    status: str
    contact_endpoint: str
    is_autonomous: bool


class Registry(Protocol):
    def register_agent(self, attestation: OperatorAttestation) -> None: ...
    def resolve(self, did: str) -> AgentRecord | None: ...
    def revoke(self, did: str, reason: str) -> None: ...
    def set_status(self, did: str, status: str) -> None: ...


class SQLiteRegistry:
    def __init__(
        self,
        database: str = ":memory:",
        revoke_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.connection = connect(database)
        self.revoke_hook = revoke_hook
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS agents (
            did TEXT PRIMARY KEY, public_key BLOB NOT NULL, operator_id TEXT NOT NULL,
            scopes TEXT NOT NULL, status TEXT NOT NULL, contact_endpoint TEXT NOT NULL,
            is_autonomous INTEGER NOT NULL, revoke_reason TEXT)"""
        )
        self.connection.commit()

    def register_agent(self, attestation: OperatorAttestation) -> None:
        self.connection.execute(
            """INSERT OR REPLACE INTO agents
            (did, public_key, operator_id, scopes, status, contact_endpoint, is_autonomous)
            VALUES (?, ?, ?, ?, 'active', ?, ?)""",
            (
                attestation.agent_did,
                bytes.fromhex(attestation.agent_public_key),
                attestation.operator_id,
                json.dumps(attestation.scopes),
                attestation.contact_endpoint,
                int(attestation.is_autonomous),
            ),
        )
        self.connection.commit()

    def resolve(self, did: str) -> AgentRecord | None:
        row = self.connection.execute(
            "SELECT did, public_key, operator_id, scopes, status, contact_endpoint, is_autonomous "
            "FROM agents WHERE did = ?",
            (did,),
        ).fetchone()
        if row is None:
            return None
        return AgentRecord(row[0], row[1], row[2], json.loads(row[3]), row[4], row[5], bool(row[6]))

    def revoke(self, did: str, reason: str) -> None:
        self.connection.execute(
            "UPDATE agents SET status = 'revoked', revoke_reason = ? WHERE did = ?", (reason, did)
        )
        self.connection.commit()
        if self.revoke_hook:
            self.revoke_hook(did)

    def set_status(self, did: str, status: str) -> None:
        if status not in STATUSES:
            raise ValueError("invalid status")
        current = self.resolve(did)
        if current and current.status == "revoked" and status != "revoked":
            raise ValueError("revoked agents cannot be reactivated")
        self.connection.execute("UPDATE agents SET status = ? WHERE did = ?", (status, did))
        self.connection.commit()
