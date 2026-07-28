"""Readable, entirely in-process AgentID lifecycle demonstration."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx

from agentid.attestation import OperatorAttestation
from agentid.bonding import BondingPool
from agentid.directory import ContactDirectory
from agentid.identity import KeyStore
from agentid.registry import SQLiteRegistry
from agentid.server import create_app
from agentid_sdk import AgentClient


def attestation(operator: KeyStore, agent: KeyStore) -> OperatorAttestation:
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


async def run_demo() -> None:
    print("=== AgentID & Bonding: complete in-process demo ===")
    operator = KeyStore.generate()
    agent = KeyStore.generate()
    peer = KeyStore.generate()
    directory = ContactDirectory()
    registry = SQLiteRegistry(revoke_hook=directory.release)
    pool = BondingPool(
        min_bond=100,
        status_hook=lambda did, status: registry.set_status(did, status),
    )
    app = create_app(registry, pool, directory)
    transport = httpx.ASGITransport(app=app)
    client = AgentClient("http://demo", agent, transport)
    peer_client = AgentClient("http://demo", peer, transport)

    print("\n[1/7] Registering agents and depositing bonds")
    registry.register_agent(attestation(operator, agent))
    registry.register_agent(attestation(operator, peer))
    pool.deposit(operator.did, agent.did, 100)
    pool.deposit(operator.did, peer.did, 100)
    print(f"  agent DID: {agent.did}")
    print(f"  initial bond: {pool.balance(agent.did)} (minimum: {pool.min_bond})")

    print("\n[2/7] Agent sends a signed request to the demo service")
    accepted = await client.apost("/protected", scope="service:write")
    print(f"  POST /protected -> {accepted.status_code} {accepted.json()}")

    print("\n[3/7] Agents exchange a protocol contact via @ai_agent")
    reserved = await client.apost(
        "/directory/reserve", json={"handle": "alpha_agent"}, scope="directory:write"
    )
    await client.apost(
        "/directory/contact",
        scope="directory:write",
        json={
            "email": "alpha_agent@ai_agent",
            "phone": "+33123456789",
            "webhook": "https://alpha.example/hook",
            "visibility": "bonded_only",
        },
    )
    resolved = await peer_client.aget("/directory/alpha_agent@ai_agent", scope="directory:read")
    print(f"  reserve -> {reserved.status_code} {reserved.json()}")
    print(f"  resolve -> {resolved.status_code} {resolved.json()}")
    print(f"  audit log -> {directory.audit_entries()}")

    print("\n[4/7] A peer reports abusive behavior")
    claim_response = await peer_client.apost(
        "/report-abuse",
        scope="claims:open",
        json={
            "agent_did": agent.did,
            "amount": 100,
            "evidence_hash": "sha256:demo-evidence",
        },
    )
    claim_id = claim_response.json()["claim_id"]
    print(f"  POST /report-abuse -> {claim_response.status_code}")
    print(f"  claim id: {claim_id}")

    print("\n[5/7] Arbiter upholds the claim and slashes the bond")
    pool.resolve_claim(claim_id, "did:arbiter:demo", True, 100)
    print(f"  remaining bond: {pool.balance(agent.did)}")
    print(f"  registry status: {registry.resolve(agent.did).status}")

    print("\n[6/7] Suspended agent is refused")
    refused = await client.apost("/protected", scope="service:write")
    print(f"  POST /protected -> {refused.status_code} {refused.json()}")

    print("\n[7/7] Operator revokes the agent permanently")
    registry.revoke(agent.did, "upheld abuse claim")
    revoked = await client.apost("/protected", scope="service:write")
    print(f"  POST /protected -> {revoked.status_code} {revoked.json()}")
    print("\nDemo complete.")


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
