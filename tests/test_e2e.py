from datetime import UTC, datetime, timedelta

import httpx
import pytest

from agentid.attestation import OperatorAttestation
from agentid.bonding import BondingPool
from agentid.directory import ContactDirectory
from agentid.identity import KeyStore
from agentid.registry import SQLiteRegistry
from agentid.server import create_app
from agentid_sdk import AgentClient


def _attestation(operator: KeyStore, agent: KeyStore) -> OperatorAttestation:
    now = datetime.now(UTC)
    return OperatorAttestation(
        operator_id=operator.did,
        agent_did=agent.did,
        agent_public_key=agent.public_key.hex(),
        scopes=["service:write", "claims:open", "directory:write", "directory:read"],
        contact_endpoint="https://operator.example/agents",
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
    ).sign(operator)


@pytest.mark.anyio
async def test_complete_http_scenario() -> None:
    operator = KeyStore.generate()
    agent = KeyStore.generate()
    peer = KeyStore.generate()
    reader = KeyStore.generate()
    directory = ContactDirectory()
    registry = SQLiteRegistry(revoke_hook=directory.release)
    pool = BondingPool(
        min_bond=100,
        status_hook=lambda did, status: registry.set_status(did, status),
    )
    registry.register_agent(_attestation(operator, agent))
    registry.register_agent(_attestation(operator, peer))
    registry.register_agent(_attestation(operator, reader))
    pool.deposit(operator.did, agent.did, 100)
    pool.deposit(operator.did, peer.did, 100)
    app = create_app(registry, pool, directory)
    transport = httpx.ASGITransport(app=app)
    client = AgentClient("http://testserver", agent, transport)
    peer_client = AgentClient("http://testserver", peer, transport)
    reader_client = AgentClient("http://testserver", reader, transport)

    accepted = await client.apost("/protected", scope="service:write")
    assert accepted.status_code == 200
    assert accepted.json() == {"status": "accepted"}
    missing_scope = await client.apost("/protected")
    assert missing_scope.status_code == 403
    assert missing_scope.json() == {"code": "SCOPE_DENIED"}
    duplicate_scope_headers = client._headers("POST", "/protected", scope="service:write")
    async with httpx.AsyncClient(base_url="http://testserver", transport=transport) as raw_client:
        duplicate_scope_request = await raw_client.post(
            "/protected",
            headers=[
                *duplicate_scope_headers.items(),
                ("X-Agent-Scope", "service:write"),
            ],
        )
    assert duplicate_scope_request.status_code == 400
    assert duplicate_scope_request.json() == {"code": "DUPLICATE_HEADER"}

    reserve = await client.apost(
        "/directory/reserve", json={"handle": "alpha_agent"}, scope="directory:write"
    )
    assert reserve.status_code == 200
    duplicate = await peer_client.apost(
        "/directory/reserve", json={"handle": "alpha_agent"}, scope="directory:write"
    )
    assert duplicate.status_code == 409
    assert duplicate.json() == {"code": "HANDLE_TAKEN"}
    second_handle = await client.apost(
        "/directory/reserve", json={"handle": "second_agent"}, scope="directory:write"
    )
    assert second_handle.status_code == 409
    assert second_handle.json() == {"code": "HANDLE_ALREADY_RESERVED"}
    invalid_handle = await peer_client.apost(
        "/directory/reserve", json={"handle": "NOPE!"}, scope="directory:write"
    )
    assert invalid_handle.status_code == 422
    assert invalid_handle.json() == {"code": "HANDLE_INVALID"}
    missing_handle = await peer_client.apost("/directory/reserve", json={}, scope="directory:write")
    assert missing_handle.status_code == 422
    assert missing_handle.json() == {"code": "BODY_INVALID"}
    publish = await client.apost(
        "/directory/contact",
        scope="directory:write",
        json={
            "email": "alpha_agent@ai_agent",
            "phone": "+33123456789",
            "webhook": "https://alpha.example/hook",
            "visibility": "bonded_only",
        },
    )
    assert publish.status_code == 200
    invalid_contact = await peer_client.apost(
        "/directory/contact",
        scope="directory:write",
        json={"email": "not-an-agent-email", "webhook": "https://peer.example/hook"},
    )
    assert invalid_contact.status_code == 422
    assert invalid_contact.json() == {"code": "CONTACT_INVALID"}
    unreserved_contact = await peer_client.apost(
        "/directory/contact",
        scope="directory:write",
        json={"email": "peer_agent@ai_agent", "webhook": "https://peer.example/hook"},
    )
    assert unreserved_contact.status_code == 409
    assert unreserved_contact.json() == {"code": "HANDLE_NOT_RESERVED"}
    resolved = await peer_client.aget("/directory/alpha_agent@ai_agent", scope="directory:read")
    assert resolved.status_code == 200
    assert resolved.json()["email"] == "alpha_agent@ai_agent"
    assert directory.audit_entries() == [(peer.did, "alpha_agent")]
    public_update = await client.apost(
        "/directory/contact",
        scope="directory:write",
        json={
            "email": "alpha_agent@ai_agent",
            "webhook": "https://alpha.example/hook",
            "visibility": "public",
        },
    )
    assert public_update.status_code == 200
    public_resolve = await reader_client.aget(
        "/directory/alpha_agent@ai_agent", scope="directory:read"
    )
    assert public_resolve.status_code == 200
    restricted = await client.apost(
        "/directory/contact",
        scope="directory:write",
        json={
            "email": "alpha_agent@ai_agent",
            "webhook": "https://alpha.example/hook",
            "visibility": "allowlist",
            "allowlist": [],
        },
    )
    assert restricted.status_code == 200
    denied = await peer_client.aget("/directory/alpha_agent@ai_agent", scope="directory:read")
    assert denied.status_code == 403
    assert denied.json() == {"code": "CONTACT_DENIED"}

    self_claim = await client.apost(
        "/report-abuse",
        scope="claims:open",
        json={"agent_did": agent.did, "amount": 1, "evidence_hash": "self"},
    )
    assert self_claim.status_code == 403
    assert self_claim.json() == {"code": "CLAIM_SELF_FORBIDDEN"}
    unknown_claim = await peer_client.apost(
        "/report-abuse",
        scope="claims:open",
        json={"agent_did": "did:agent:unknown", "amount": 1, "evidence_hash": "unknown"},
    )
    assert unknown_claim.status_code == 404
    assert unknown_claim.json() == {"code": "CLAIM_TARGET_UNKNOWN"}
    missing_claim_fields = await peer_client.apost("/report-abuse", scope="claims:open", json={})
    assert missing_claim_fields.status_code == 422
    assert missing_claim_fields.json() == {"code": "BODY_INVALID"}
    unknown_claim_field = await peer_client.apost(
        "/report-abuse",
        scope="claims:open",
        json={
            "claimant": peer.did,
            "agent_did": agent.did,
            "amount": 1,
            "evidence_hash": "unknown-field",
        },
    )
    assert unknown_claim_field.status_code == 422
    assert unknown_claim_field.json() == {"code": "BODY_INVALID"}
    huge_claim = await peer_client.apost(
        "/report-abuse",
        scope="claims:open",
        json={"agent_did": agent.did, "amount": int("9" * 400), "evidence_hash": "huge"},
    )
    assert huge_claim.status_code == 422
    assert huge_claim.json() == {"code": "BODY_INVALID"}
    boolean_amount = await peer_client.apost(
        "/report-abuse",
        scope="claims:open",
        json={"agent_did": agent.did, "amount": True, "evidence_hash": "boolean"},
    )
    assert boolean_amount.status_code == 422
    assert boolean_amount.json() == {"code": "BODY_INVALID"}
    invalid_allowlist = await client.apost(
        "/directory/contact",
        scope="directory:write",
        json={
            "email": "alpha_agent@ai_agent",
            "webhook": "https://alpha.example/hook",
            "visibility": "allowlist",
            "allowlist": ["did:agent:not-valid,did:agent:injected"],
        },
    )
    assert invalid_allowlist.status_code == 422
    assert invalid_allowlist.json() == {"code": "ALLOWLIST_INVALID"}

    raw_body = b'{"b": 1, "a":2}'
    raw_headers = client._headers("POST", "/protected", raw_body, scope="service:write")
    raw_response = await client.arequest(
        "POST", "/protected", content=raw_body, headers=raw_headers
    )
    assert raw_response.status_code == 200
    mismatch_headers = client._headers("POST", "/protected", raw_body, scope="service:write")
    tampered = await client.arequest(
        "POST", "/protected", content=b'{"a":2,"b":1}', headers=mismatch_headers
    )
    assert tampered.status_code == 401
    assert tampered.json() == {"code": "SIG_INVALID"}

    claim_response = await peer_client.apost(
        "/report-abuse",
        scope="claims:open",
        json={
            "agent_did": agent.did,
            "amount": 100,
            "evidence_hash": "sha256:evidence",
        },
    )
    assert claim_response.status_code == 200
    claim_id = claim_response.json()["claim_id"]
    pool.resolve_claim(claim_id, "did:arbiter:demo", True, 100)
    rejected_for_bond = await client.apost("/protected", scope="service:write")
    assert rejected_for_bond.status_code == 403
    assert rejected_for_bond.json() == {"code": "INSUFFICIENT_BOND"}

    registry.revoke(agent.did, "upheld abuse claim")
    rejected_for_revocation = await client.apost("/protected", scope="service:write")
    assert rejected_for_revocation.status_code == 403
    assert rejected_for_revocation.json() == {"code": "REVOKED"}
