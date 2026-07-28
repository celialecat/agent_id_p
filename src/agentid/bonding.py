"""Append-only SQLite bonding ledger."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from .canonical import canonical_json
from .sqlite_store import connect

MAX_AMOUNT = 2**63 - 1


def validate_amount(amount: object, field: str = "amount", allow_zero: bool = False) -> int:
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise ValueError(f"{field} must be a strict integer")
    if (amount < 0 if allow_zero else amount <= 0) or amount > MAX_AMOUNT:
        raise ValueError(f"{field} is outside the permitted range")
    return amount


@dataclass(frozen=True)
class Claim:
    claim_id: str
    claimant: str
    agent_did: str
    amount: int
    evidence_hash: str
    status: str


class BondingPool:
    def __init__(
        self,
        database: str = ":memory:",
        min_bond: int = 100,
        unbonding_delay: timedelta = timedelta(hours=24),
        status_hook: Callable[[str, str], None] | None = None,
    ) -> None:
        self.connection = connect(database)
        self.min_bond = validate_amount(min_bond, "min_bond", allow_zero=True)
        self.unbonding_delay = unbonding_delay
        self.status_hook = status_hook
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, kind TEXT, payload TEXT,
            prev_hash TEXT, hash TEXT, created_at TEXT)"""
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS withdrawals (
            request_id TEXT PRIMARY KEY, agent_did TEXT, amount INTEGER, available_at TEXT,
            completed INTEGER NOT NULL DEFAULT 0)"""
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS claims (
            claim_id TEXT PRIMARY KEY, claimant TEXT, agent_did TEXT, amount INTEGER,
            evidence_hash TEXT, status TEXT NOT NULL)"""
        )
        self.connection.commit()

    def _event(self, kind: str, payload: dict[str, object]) -> None:
        previous = self.connection.execute(
            "SELECT hash FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = previous[0] if previous else ""
        body = {"kind": kind, "payload": payload, "prev_hash": prev_hash}
        digest = hashlib.sha256(canonical_json(body)).hexdigest()
        self.connection.execute(
            "INSERT INTO events VALUES (NULL, ?, ?, ?, ?, ?, ?)",
            (
                uuid4().hex,
                kind,
                json.dumps(payload, sort_keys=True),
                prev_hash,
                digest,
                datetime.now(UTC).isoformat(),
            ),
        )
        self.connection.commit()

    def _change(self, agent_did: str, delta: int) -> None:
        self._event("balance_change", {"agent_did": agent_did, "delta": delta})
        balance = self.balance(agent_did)
        if self.status_hook:
            self.status_hook(agent_did, "active" if balance >= self.min_bond else "suspended")

    def balance(self, agent_did: str) -> int:
        total = 0
        for (payload,) in self.connection.execute("SELECT payload FROM events"):
            item = json.loads(payload)
            if item.get("agent_did") == agent_did:
                total += int(item.get("delta", 0))
            if item.get("recipient") == agent_did:
                total += int(item.get("amount", 0))
        return total

    def deposit(self, operator_id: str, agent_did: str, amount: int) -> None:
        amount = validate_amount(amount)
        if self.balance(agent_did) > MAX_AMOUNT - amount:
            raise ValueError("balance exceeds maximum amount")
        self._event(
            "deposit", {"operator_id": operator_id, "agent_did": agent_did, "delta": amount}
        )
        self._change(agent_did, 0)

    def request_withdraw(self, agent_did: str, amount: int) -> str:
        amount = validate_amount(amount)
        if amount > self.balance(agent_did):
            raise ValueError("invalid withdrawal amount")
        request_id = uuid4().hex
        available = datetime.now(UTC) + self.unbonding_delay
        self.connection.execute(
            "INSERT INTO withdrawals VALUES (?, ?, ?, ?, 0)",
            (request_id, agent_did, amount, available.isoformat()),
        )
        self.connection.commit()
        self._event(
            "withdraw_request", {"request_id": request_id, "agent_did": agent_did, "amount": amount}
        )
        return request_id

    def withdraw(self, request_id: str) -> None:
        row = self.connection.execute(
            "SELECT agent_did, amount, available_at, completed "
            "FROM withdrawals WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None or row[3] or datetime.now(UTC) < datetime.fromisoformat(row[2]):
            raise ValueError("withdrawal unavailable")
        if row[1] > self.balance(row[0]):
            raise ValueError("insufficient balance")
        self.connection.execute(
            "UPDATE withdrawals SET completed = 1 WHERE request_id = ?", (request_id,)
        )
        self.connection.commit()
        self._event("withdraw", {"agent_did": row[0], "delta": -row[1]})
        self._change(row[0], 0)

    def open_claim(self, claimant: str, agent_did: str, amount: int, evidence_hash: str) -> str:
        amount = validate_amount(amount)
        claim_id = uuid4().hex
        self.connection.execute(
            "INSERT INTO claims VALUES (?, ?, ?, ?, ?, 'open')",
            (claim_id, claimant, agent_did, amount, evidence_hash),
        )
        self.connection.commit()
        self._event("claim_open", {"claim_id": claim_id, "agent_did": agent_did, "amount": amount})
        return claim_id

    def resolve_claim(self, claim_id: str, arbiter: str, upheld: bool, slashed_amount: int) -> None:
        slashed_amount = validate_amount(slashed_amount, allow_zero=True)
        row = self.connection.execute(
            "SELECT claimant, agent_did, status FROM claims WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if row is None or row[2] != "open":
            raise ValueError("unknown claim")
        self.connection.execute(
            "UPDATE claims SET status = ? WHERE claim_id = ?",
            ("upheld" if upheld else "rejected", claim_id),
        )
        self.connection.commit()
        self._event("claim_resolve", {"claim_id": claim_id, "arbiter": arbiter, "upheld": upheld})
        if upheld:
            slash = min(max(0, slashed_amount), self.balance(row[1]))
            self._event("slash", {"agent_did": row[1], "delta": -slash})
            self._event("indemnity", {"recipient": row[0], "amount": slash})
            self._change(row[1], 0)
