"""Signed request handshake and replay protection."""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Protocol

from .canonical import canonical_json
from .identity import public_key_from_did, verify_signature
from .registry import AgentRecord, Registry
from .sqlite_store import connect


def signing_string(
    method: str,
    path: str,
    query: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    did: str,
    host: str,
    scope: str | None = None,
) -> bytes:
    return canonical_json(
        {
            "method": method.upper(),
            "path": path,
            "query": query,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": timestamp,
            "nonce": nonce,
            "did": did,
            "host": host,
            "scope": scope,
        }
    )


class AuthError(Exception):
    def __init__(self, code: str, status_code: int = 401) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class NonceCache:
    def __init__(self, ttl: int = 120) -> None:
        self.ttl = ttl
        self._items: dict[tuple[str, str], float] = {}

    def consume(self, did: str, nonce: str) -> bool:
        now = time.time()
        self._items = {key: expiry for key, expiry in self._items.items() if expiry > now}
        key = (did, nonce)
        if key in self._items:
            return False
        self._items[key] = now + self.ttl
        return True


class NonceStore(Protocol):
    def consume(self, did: str, nonce: str) -> bool: ...


class SQLiteNonceStore:
    """Persistent nonce store suitable for multiple service workers."""

    def __init__(self, database: str = ":memory:", ttl: int = 120) -> None:
        self.connection = connect(database)
        self.ttl = ttl
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS nonces "
            "(did TEXT NOT NULL, nonce TEXT NOT NULL, expires_at REAL NOT NULL, "
            "PRIMARY KEY (did, nonce))"
        )
        self.connection.commit()

    def consume(self, did: str, nonce: str) -> bool:
        now = time.time()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
            self.connection.execute(
                "INSERT INTO nonces(did, nonce, expires_at) VALUES (?, ?, ?)",
                (did, nonce, now + self.ttl),
            )
            self.connection.commit()
        except sqlite3.IntegrityError:
            self.connection.rollback()
            return False
        except Exception:
            self.connection.rollback()
            raise
        return True


def verify_request(
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
    method: str,
    path: str,
    query: str,
    body: bytes,
    host: str,
    registry: Registry,
    bond_balance: Callable[[str], int],
    nonces: NonceStore,
    required_scope: str | None = None,
    max_skew: int = 60,
    min_bond: int = 0,
) -> AgentRecord:
    pairs = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
    protocol_headers = {
        "x-agent-did",
        "x-agent-timestamp",
        "x-agent-nonce",
        "x-agent-signature",
        "x-agent-sig-alg",
        "x-agent-scope",
    }
    counts: dict[str, int] = {}
    for key, _ in pairs:
        lowered = key.lower()
        counts[lowered] = counts.get(lowered, 0) + 1
    if any(counts.get(key, 0) > 1 for key in protocol_headers):
        raise AuthError("DUPLICATE_HEADER", 400)
    normalized = {key.lower(): value for key, value in pairs}
    required = [
        "x-agent-did",
        "x-agent-timestamp",
        "x-agent-nonce",
        "x-agent-signature",
        "x-agent-sig-alg",
    ]
    if any(key not in normalized for key in required):
        raise AuthError("HEADERS_MISSING")
    if normalized["x-agent-sig-alg"].lower() != "ed25519":
        raise AuthError("SIG_ALG_UNSUPPORTED", 400)
    did = normalized["x-agent-did"]
    record = registry.resolve(did)
    try:
        public_key = record.public_key if record is not None else public_key_from_did(did)
    except ValueError as error:
        raise AuthError("SIG_INVALID") from error
    try:
        timestamp = datetime.fromisoformat(normalized["x-agent-timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        skew = abs((datetime.now(UTC) - timestamp).total_seconds())
    except (TypeError, ValueError, OverflowError) as error:
        raise AuthError("TIMESTAMP_SKEW") from error
    if skew > max_skew:
        raise AuthError("TIMESTAMP_SKEW")
    try:
        signature = base64.b64decode(normalized["x-agent-signature"], validate=True)
        valid = verify_signature(
            public_key,
            signing_string(
                method,
                path,
                query,
                body,
                normalized["x-agent-timestamp"],
                normalized["x-agent-nonce"],
                did,
                host,
                normalized.get("x-agent-scope"),
            ),
            signature,
        )
    except Exception:
        valid = False
    if not valid:
        raise AuthError("SIG_INVALID")
    if record is None:
        raise AuthError("AGENT_UNKNOWN")
    if record.status == "revoked":
        raise AuthError("REVOKED", 403)
    if bond_balance(did) < min_bond:
        raise AuthError("INSUFFICIENT_BOND", 403)
    if record.status == "suspended":
        raise AuthError("SUSPENDED", 403)
    scope = normalized.get("x-agent-scope")
    if required_scope and scope != required_scope:
        raise AuthError("SCOPE_DENIED", 403)
    if scope and scope not in record.scopes:
        raise AuthError("SCOPE_DENIED", 403)
    if not nonces.consume(did, normalized["x-agent-nonce"]):
        raise AuthError("REPLAY", 409)
    return record
