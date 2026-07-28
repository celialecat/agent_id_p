import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentid.attestation import OperatorAttestation
from agentid.bonding import MAX_AMOUNT, BondingPool
from agentid.canonical import canonical_json
from agentid.directory import ContactDirectory, _decode_allowlist
from agentid.handshake import (
    AuthError,
    NonceCache,
    SQLiteNonceStore,
    signing_string,
    verify_request,
)
from agentid.humanity import create_human_proof, verify_human
from agentid.identity import KeyStore, public_key_from_did
from agentid.registry import SQLiteRegistry


def test_did_round_trip() -> None:
    key = KeyStore.generate()
    assert public_key_from_did(key.did) == key.public_key
    with pytest.raises(ValueError):
        public_key_from_did(key.did.replace("did:agent:", "did:agentx:", 1))
    with pytest.raises(ValueError):
        public_key_from_did("did:agent:not-a-did")


def test_canonicalization_is_stable() -> None:
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_attestation_and_expiry() -> None:
    operator, agent = KeyStore.generate(), KeyStore.generate()
    now = datetime.now(UTC)
    attestation = OperatorAttestation(
        operator_id=operator.did,
        agent_did=agent.did,
        agent_public_key=agent.public_key.hex(),
        contact_endpoint="https://example.test",
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=1),
    ).sign(operator)
    assert attestation.verify(operator.public_key)
    assert not attestation.verify(operator.public_key, now + timedelta(hours=1))
    future = attestation.model_copy(update={"not_before": now + timedelta(hours=1)})
    assert not future.verify(operator.public_key, now)
    altered = attestation.model_copy(update={"scopes": ["altered"]})
    assert not altered.verify(operator.public_key)
    assert not attestation.verify(KeyStore.generate().public_key)


def test_nonce_replay() -> None:
    cache = NonceCache()
    assert cache.consume("did", "nonce")
    assert not cache.consume("did", "nonce")


def test_invalid_signature_does_not_burn_nonce() -> None:
    operator, agent = KeyStore.generate(), KeyStore.generate()
    registry = SQLiteRegistry()
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    attestation = OperatorAttestation(
        operator_id=operator.did,
        agent_did=agent.did,
        agent_public_key=agent.public_key.hex(),
        contact_endpoint="https://example.test",
        not_before=datetime.now(UTC) - timedelta(minutes=1),
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
    ).sign(operator)
    registry.register_agent(attestation)
    pool = BondingPool(min_bond=1)
    pool.deposit(operator.did, agent.did, 1)
    cache = NonceCache()
    body = b'{"b":1,"a":2}'
    payload = signing_string("POST", "/protected", "", body, now, "retry", agent.did, "test")
    headers = {
        "X-Agent-DID": agent.did,
        "X-Agent-Timestamp": now,
        "X-Agent-Nonce": "retry",
        "X-Agent-Signature": base64.b64encode(agent.sign(payload)).decode(),
        "X-Agent-Sig-Alg": "ed25519",
    }
    with pytest.raises(AuthError, match="SIG_INVALID"):
        verify_request(
            {**headers, "X-Agent-Signature": "invalid"},
            "POST",
            "/protected",
            "",
            body,
            "test",
            registry,
            pool.balance,
            cache,
            min_bond=1,
        )
    assert (
        verify_request(
            headers,
            "POST",
            "/protected",
            "",
            body,
            "test",
            registry,
            pool.balance,
            cache,
            min_bond=1,
        ).did
        == agent.did
    )


def test_scope_denial_does_not_burn_nonce() -> None:
    operator, agent = KeyStore.generate(), KeyStore.generate()
    registry = SQLiteRegistry()
    now = datetime.now(UTC)
    registry.register_agent(
        OperatorAttestation(
            operator_id=operator.did,
            agent_did=agent.did,
            agent_public_key=agent.public_key.hex(),
            scopes=["service:write"],
            contact_endpoint="https://example.test",
            not_before=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=1),
        ).sign(operator)
    )
    pool = BondingPool(min_bond=1)
    pool.deposit(operator.did, agent.did, 1)
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    nonce = "scope-retry"
    body = b""
    payload = signing_string(
        "POST", "/protected", "", body, timestamp, nonce, agent.did, "test", "service:write"
    )
    headers = {
        "X-Agent-DID": agent.did,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": base64.b64encode(agent.sign(payload)).decode(),
        "X-Agent-Sig-Alg": "ed25519",
        "X-Agent-Scope": "service:write",
    }
    cache = NonceCache()
    with pytest.raises(AuthError, match="SCOPE_DENIED"):
        verify_request(
            headers,
            "POST",
            "/protected",
            "",
            body,
            "test",
            registry,
            pool.balance,
            cache,
            required_scope="other:write",
            min_bond=1,
        )
    assert (
        verify_request(
            headers,
            "POST",
            "/protected",
            "",
            body,
            "test",
            registry,
            pool.balance,
            cache,
            required_scope="service:write",
            min_bond=1,
        ).did
        == agent.did
    )


def test_amounts_are_strict_and_bounded() -> None:
    pool = BondingPool()
    with pytest.raises(ValueError):
        pool.deposit("operator", "did", True)
    with pytest.raises(ValueError):
        pool.deposit("operator", "did", MAX_AMOUNT + 1)
    with pytest.raises(ValueError):
        pool.open_claim("claimant", "did", MAX_AMOUNT + 1, "evidence")
    pool.deposit("operator", "did", MAX_AMOUNT)
    with pytest.raises(ValueError, match="balance exceeds maximum"):
        pool.deposit("operator", "did", 1)


def test_sqlite_stores_use_wal_and_busy_timeout(tmp_path: Path) -> None:
    registry = SQLiteRegistry(str(tmp_path / "registry.db"))
    pool = BondingPool(str(tmp_path / "bonding.db"))
    directory = ContactDirectory(str(tmp_path / "directory.db"))
    nonce_store = SQLiteNonceStore(str(tmp_path / "nonces.db"))
    for connection in (
        registry.connection,
        pool.connection,
        directory.connection,
        nonce_store.connection,
    ):
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 30_000


def test_naive_timestamp_is_a_protocol_error() -> None:
    operator, agent = KeyStore.generate(), KeyStore.generate()
    registry = SQLiteRegistry()
    now = datetime.now(UTC)
    registry.register_agent(
        OperatorAttestation(
            operator_id=operator.did,
            agent_did=agent.did,
            agent_public_key=agent.public_key.hex(),
            contact_endpoint="https://example.test",
            not_before=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=1),
        ).sign(operator)
    )
    pool = BondingPool(min_bond=1)
    pool.deposit(operator.did, agent.did, 1)
    timestamp = datetime.now().replace(microsecond=0).isoformat()
    payload = signing_string("GET", "/", "", b"", timestamp, "naive", agent.did, "test")
    headers = {
        "X-Agent-DID": agent.did,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": "naive",
        "X-Agent-Signature": base64.b64encode(agent.sign(payload)).decode(),
        "X-Agent-Sig-Alg": "ed25519",
    }
    with pytest.raises(AuthError, match="TIMESTAMP_SKEW"):
        verify_request(
            headers, "GET", "/", "", b"", "test", registry, pool.balance, NonceCache(), min_bond=1
        )


def test_unknown_and_revoked_statuses_follow_signature_verification() -> None:
    operator, agent = KeyStore.generate(), KeyStore.generate()
    registry = SQLiteRegistry()
    pool = BondingPool(min_bond=1)
    pool.deposit(operator.did, agent.did, 1)
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    def headers(key: KeyStore, nonce: str) -> dict[str, str]:
        payload = signing_string("GET", "/", "", b"", timestamp, nonce, key.did, "test")
        return {
            "X-Agent-DID": key.did,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": base64.b64encode(key.sign(payload)).decode(),
            "X-Agent-Sig-Alg": "ed25519",
        }

    with pytest.raises(AuthError, match="AGENT_UNKNOWN"):
        verify_request(
            headers(agent, "unknown"),
            "GET",
            "/",
            "",
            b"",
            "test",
            registry,
            pool.balance,
            NonceCache(),
            min_bond=0,
        )
    now = datetime.now(UTC)
    registry.register_agent(
        OperatorAttestation(
            operator_id=operator.did,
            agent_did=agent.did,
            agent_public_key=agent.public_key.hex(),
            contact_endpoint="https://example.test",
            not_before=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=1),
        ).sign(operator)
    )
    registry.revoke(agent.did, "test")
    with pytest.raises(AuthError, match="REVOKED"):
        verify_request(
            headers(agent, "revoked"),
            "GET",
            "/",
            "",
            b"",
            "test",
            registry,
            pool.balance,
            NonceCache(),
            min_bond=0,
        )


def test_sqlite_nonce_store_persists_between_instances(tmp_path: Path) -> None:
    database = str(tmp_path / "nonces.db")
    assert SQLiteNonceStore(database).consume("did", "nonce")
    assert not SQLiteNonceStore(database).consume("did", "nonce")


def test_duplicate_protocol_headers_are_rejected() -> None:
    with pytest.raises(AuthError, match="DUPLICATE_HEADER"):
        verify_request(
            [
                ("X-Agent-DID", "did:agent:unknown"),
                ("X-Agent-DID", "did:agent:unknown"),
            ],
            "GET",
            "/",
            "",
            b"",
            "test",
            SQLiteRegistry(),
            lambda _did: 0,
            NonceCache(),
        )


def test_missing_headers_and_algorithm_are_explicit() -> None:
    with pytest.raises(AuthError, match="HEADERS_MISSING"):
        verify_request(
            {}, "GET", "/", "", b"", "test", SQLiteRegistry(), lambda _did: 0, NonceCache()
        )
    with pytest.raises(AuthError, match="SIG_ALG_UNSUPPORTED"):
        verify_request(
            {
                "X-Agent-DID": "did:agent:unknown",
                "X-Agent-Timestamp": "2025-01-01T00:00:00Z",
                "X-Agent-Nonce": "nonce",
                "X-Agent-Signature": "signature",
                "X-Agent-Sig-Alg": "rsa",
            },
            "GET",
            "/",
            "",
            b"",
            "test",
            SQLiteRegistry(),
            lambda _did: 0,
            NonceCache(),
        )


def test_bond_slash_and_ledger() -> None:
    pool = BondingPool(min_bond=100)
    pool.deposit("op", "did", 100)
    claim = pool.open_claim("claimant", "did", 50, "evidence")
    pool.resolve_claim(claim, "arbiter", True, 100)
    assert pool.balance("did") == 0


def test_withdrawal_cooldown_and_status_transitions() -> None:
    registry = SQLiteRegistry()
    pool = BondingPool(
        min_bond=100,
        unbonding_delay=timedelta(hours=1),
        status_hook=lambda did, status: registry.set_status(did, status),
    )
    operator, agent = KeyStore.generate(), KeyStore.generate()
    now = datetime.now(UTC)
    registry.register_agent(
        OperatorAttestation(
            operator_id=operator.did,
            agent_did=agent.did,
            agent_public_key=agent.public_key.hex(),
            contact_endpoint="https://example.test",
            not_before=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
        ).sign(operator)
    )
    pool.deposit(operator.did, agent.did, 100)
    request_id = pool.request_withdraw(agent.did, 50)
    with pytest.raises(ValueError, match="withdrawal unavailable"):
        pool.withdraw(request_id)
    pool.connection.execute(
        "UPDATE withdrawals SET available_at=? WHERE request_id=?",
        ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), request_id),
    )
    pool.connection.commit()
    pool.withdraw(request_id)
    assert registry.resolve(agent.did).status == "suspended"
    pool.deposit(operator.did, agent.did, 50)
    assert registry.resolve(agent.did).status == "active"
    registry.revoke(agent.did, "test")
    with pytest.raises(ValueError, match="revoked"):
        pool.deposit(operator.did, agent.did, 100)


def test_handle_uniqueness_and_release_on_revocation() -> None:
    directory = ContactDirectory()
    registry = SQLiteRegistry(revoke_hook=directory.release)
    operator, first, second = KeyStore.generate(), KeyStore.generate(), KeyStore.generate()
    now = datetime.now(UTC)
    registry.register_agent(
        OperatorAttestation(
            operator_id=operator.did,
            agent_did=first.did,
            agent_public_key=first.public_key.hex(),
            contact_endpoint="https://example.test",
            not_before=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
        ).sign(operator)
    )
    directory.reserve("agent_one", first.did)
    with pytest.raises(ValueError, match="already reserved"):
        directory.reserve("agent_one", second.did)
    registry.revoke(first.did, "test")
    directory.reserve("agent_one", second.did)


def test_allowlist_is_validated_and_json_encoded() -> None:
    directory = ContactDirectory()
    owner, allowed = KeyStore.generate(), KeyStore.generate()
    directory.reserve("owner_agent", owner.did)
    directory.publish(
        owner.did,
        "owner_agent@ai_agent",
        "https://example.test/hook",
        visibility="allowlist",
        allowlist=[allowed.did],
    )
    stored = directory.connection.execute(
        "SELECT allowlist FROM contacts WHERE did=?", (owner.did,)
    ).fetchone()[0]
    assert stored == f'["{allowed.did}"]'
    with pytest.raises(ValueError, match="invalid allowlist entry"):
        directory.publish(
            owner.did,
            "owner_agent@ai_agent",
            "https://example.test/hook",
            visibility="allowlist",
            allowlist=[f"{allowed.did},{owner.did}"],
        )
    with pytest.raises(ValueError, match="invalid allowlist entry"):
        _decode_allowlist(f"{allowed.did},{owner.did}")


def test_human_proof_is_publicly_verifiable_and_context_bound() -> None:
    proof = create_human_proof(b"stable secret", "epoch-a")
    assert verify_human(proof, "epoch-a")
    assert not verify_human(proof, "epoch-b")
    altered = proof.__class__(
        proof.nullifier,
        proof.commitment,
        proof.challenge,
        str(int(proof.response) + 1),
        proof.public_key,
    )
    assert not verify_human(altered, "epoch-a")
