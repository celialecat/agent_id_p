"""Signed synchronous and asynchronous HTTP clients."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from agentid.handshake import signing_string
from agentid.identity import KeyStore


class AgentClient:
    def __init__(
        self, base_url: str, identity: KeyStore, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.base_url, self.identity, self.transport = base_url, identity, transport

    def _headers(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        host: str = "",
        scope: str | None = None,
    ) -> dict[str, str]:
        parsed = urlsplit(path)
        path, query = parsed.path or "/", parsed.query
        if not host:
            host = urlsplit(self.base_url).netloc
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        nonce = uuid4().hex
        signature = self.identity.sign(
            signing_string(
                method, path, query, body, timestamp, nonce, self.identity.did, host, scope
            )
        )
        headers = {
            "X-Agent-DID": self.identity.did,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": base64.b64encode(signature).decode(),
            "X-Agent-Sig-Alg": "ed25519",
        }
        if scope is not None:
            headers["X-Agent-Scope"] = scope
        return headers

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        body = kwargs.get("content", b"")
        if "json" in kwargs:
            body = json.dumps(kwargs["json"], separators=(",", ":")).encode()
            kwargs["content"], _ = body, kwargs.pop("json")
        scope = kwargs.pop("scope", None)
        supplied_headers = kwargs.pop("headers", {})
        supplied_scope = next(
            (value for key, value in supplied_headers.items() if key.lower() == "x-agent-scope"),
            None,
        )
        scope = scope if scope is not None else supplied_scope
        supplied_headers = {
            key: value for key, value in supplied_headers.items() if key.lower() != "x-agent-scope"
        }
        headers = self._headers(method, path, body, scope=scope)
        headers.update(supplied_headers)
        with httpx.Client(base_url=self.base_url) as client:
            return client.request(method, path, headers=headers, **kwargs)

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    async def arequest(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        body = kwargs.get("content", b"")
        if "json" in kwargs:
            body = json.dumps(kwargs["json"], separators=(",", ":")).encode()
            kwargs["content"], _ = body, kwargs.pop("json")
        scope = kwargs.pop("scope", None)
        supplied_headers = kwargs.pop("headers", {})
        supplied_scope = next(
            (value for key, value in supplied_headers.items() if key.lower() == "x-agent-scope"),
            None,
        )
        scope = scope if scope is not None else supplied_scope
        supplied_headers = {
            key: value for key, value in supplied_headers.items() if key.lower() != "x-agent-scope"
        }
        headers = self._headers(method, path, body, scope=scope)
        headers.update(supplied_headers)
        async with httpx.AsyncClient(base_url=self.base_url, transport=self.transport) as client:
            return await client.request(method, path, headers=headers, **kwargs)

    async def aget(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.arequest("GET", path, **kwargs)

    async def apost(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.arequest("POST", path, **kwargs)


class SigningTransport(httpx.AsyncBaseTransport):
    def __init__(
        self, identity: KeyStore, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.identity, self.transport = identity, transport or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = request.content
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        nonce = uuid4().hex
        sig = self.identity.sign(
            signing_string(
                request.method,
                request.url.path,
                request.url.query.decode(),
                body,
                timestamp,
                nonce,
                self.identity.did,
                request.url.host or "",
                request.headers.get("X-Agent-Scope"),
            )
        )
        request.headers.update(
            {
                "X-Agent-DID": self.identity.did,
                "X-Agent-Timestamp": timestamp,
                "X-Agent-Nonce": nonce,
                "X-Agent-Signature": base64.b64encode(sig).decode(),
                "X-Agent-Sig-Alg": "ed25519",
            }
        )
        return await self.transport.handle_async_request(request)


class OperatorClient:
    def __init__(self, registry: Any, pool: Any) -> None:
        self.registry, self.pool = registry, pool

    def register_and_bond(self, attestation: Any, amount: int) -> None:
        self.registry.register_agent(attestation)
        self.pool.deposit(attestation.operator_id, attestation.agent_did, amount)


class AgentIdentity:
    @staticmethod
    def generate() -> KeyStore:
        return KeyStore.generate()

    @staticmethod
    def from_file(path: str) -> KeyStore:
        return KeyStore.from_file(path)

    @staticmethod
    def from_env(name: str = "AGENTID_PRIVATE_KEY") -> KeyStore:
        return KeyStore.from_raw(bytes.fromhex(os.environ[name]))
