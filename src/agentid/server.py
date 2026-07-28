"""FastAPI service and safe component factory."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any, Literal, TypeVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

from .bonding import MAX_AMOUNT, BondingPool
from .directory import ContactDirectory
from .handshake import AuthError, SQLiteNonceStore, verify_request
from .registry import SQLiteRegistry


class AbuseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_did: str
    amount: StrictInt = Field(gt=0, le=MAX_AMOUNT)
    evidence_hash: str = Field(min_length=1)


class ReserveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    handle: str = Field(min_length=1)


class ContactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    webhook: str
    phone: str | None = None
    visibility: Literal["public", "bonded_only", "allowlist"] = "bonded_only"
    allowlist: list[str] = Field(default_factory=list)


def _invalid_body() -> JSONResponse:
    return JSONResponse({"code": "BODY_INVALID"}, status_code=422)


ModelT = TypeVar("ModelT", bound=BaseModel)


async def _model(request: Request, model: type[ModelT]) -> ModelT | JSONResponse:
    try:
        return model.model_validate_json(await request.body())
    except (ValidationError, json.JSONDecodeError):
        return _invalid_body()


def _business_error(error: ValueError) -> JSONResponse:
    message = str(error)
    if message == "invalid handle":
        return JSONResponse({"code": "HANDLE_INVALID"}, status_code=422)
    if message == "handle already reserved":
        return JSONResponse({"code": "HANDLE_TAKEN"}, status_code=409)
    if message == "agent already owns a handle":
        return JSONResponse({"code": "HANDLE_ALREADY_RESERVED"}, status_code=409)
    if message == "handle is not reserved":
        return JSONResponse({"code": "HANDLE_NOT_RESERVED"}, status_code=409)
    if message == "invalid contact endpoint":
        return JSONResponse({"code": "CONTACT_INVALID"}, status_code=422)
    if message == "invalid allowlist entry":
        return JSONResponse({"code": "ALLOWLIST_INVALID"}, status_code=422)
    if message == "balance exceeds maximum amount":
        return JSONResponse({"code": "AMOUNT_LIMIT"}, status_code=422)
    return JSONResponse({"code": "REQUEST_INVALID"}, status_code=422)


def create_app(
    registry: SQLiteRegistry,
    pool: BondingPool,
    directory: ContactDirectory,
    nonce_store: SQLiteNonceStore | None = None,
) -> FastAPI:
    app = FastAPI(title="AgentID demo service")
    nonces = nonce_store or SQLiteNonceStore()
    scopes = {
        "/protected": "service:write",
        "/report-abuse": "claims:open",
        "/directory/reserve": "directory:write",
        "/directory/contact": "directory:write",
    }

    @app.middleware("http")
    async def auth(
        request: Request,
        call_next: Callable[[Request], Awaitable[Any]],
    ) -> Any:
        if request.url.path == "/health":
            return await call_next(request)
        body = await request.body()
        required_scope = scopes.get(request.url.path)
        is_directory_read = request.url.path.startswith("/directory/") and request.method == "GET"
        if is_directory_read:
            required_scope = "directory:read"
        min_bond = 0 if is_directory_read else pool.min_bond
        try:
            record = verify_request(
                [
                    (key.decode("latin-1"), value.decode("latin-1"))
                    for key, value in request.scope.get("headers", [])
                ],
                request.method,
                request.url.path,
                request.url.query,
                body,
                request.headers.get("host", ""),
                registry,
                pool.balance,
                nonces=nonces,
                required_scope=required_scope,
                min_bond=min_bond,
            )
            request.state.agent_did = record.did
        except AuthError as error:
            return JSONResponse({"code": error.code}, status_code=error.status_code)
        return await call_next(request)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/protected")
    async def protected() -> dict[str, str]:
        return {"status": "accepted"}

    @app.post("/report-abuse")
    async def report_abuse(request: Request) -> Any:
        body = await _model(request, AbuseRequest)
        if isinstance(body, JSONResponse):
            return body
        if body.agent_did == request.state.agent_did:
            return JSONResponse({"code": "CLAIM_SELF_FORBIDDEN"}, status_code=403)
        if registry.resolve(body.agent_did) is None:
            return JSONResponse({"code": "CLAIM_TARGET_UNKNOWN"}, status_code=404)
        claim_id = pool.open_claim(
            request.state.agent_did, body.agent_did, body.amount, body.evidence_hash
        )
        return {"claim_id": claim_id}

    @app.post("/directory/reserve")
    async def reserve_handle(request: Request) -> Any:
        body = await _model(request, ReserveRequest)
        if isinstance(body, JSONResponse):
            return body
        try:
            directory.reserve(body.handle, request.state.agent_did)
        except ValueError as error:
            return _business_error(error)
        return {"address": f"{body.handle}@ai_agent"}

    @app.post("/directory/contact")
    async def publish_contact(request: Request) -> Any:
        body = await _model(request, ContactRequest)
        if isinstance(body, JSONResponse):
            return body
        try:
            directory.publish(
                request.state.agent_did,
                body.email,
                body.webhook,
                body.phone,
                body.visibility,
                body.allowlist,
            )
        except ValueError as error:
            return _business_error(error)
        return {"status": "published"}

    @app.get("/directory/{address}")
    async def resolve_contact(address: str, request: Request) -> Any:
        if not address.endswith("@ai_agent"):
            return JSONResponse({"code": "CONTACT_NOT_FOUND"}, status_code=404)
        try:
            contact = directory.resolve(
                address.removesuffix("@ai_agent"),
                request.state.agent_did,
                registry,
                pool.balance(request.state.agent_did),
                pool.min_bond,
            )
        except KeyError:
            return JSONResponse({"code": "CONTACT_NOT_FOUND"}, status_code=404)
        except PermissionError:
            return JSONResponse({"code": "CONTACT_DENIED"}, status_code=403)
        except ValueError:
            return JSONResponse({"code": "CONTACT_DENIED"}, status_code=403)
        return {
            "address": address,
            "did": contact.did,
            "email": contact.email,
            "phone": contact.phone,
            "webhook": contact.webhook,
        }

    return app


def create_demo_app() -> FastAPI:
    """Build a correctly wired file-backed service for Uvicorn."""
    directory = ContactDirectory("agentid-directory.db")
    registry = SQLiteRegistry("agentid-registry.db", revoke_hook=directory.release)
    pool = BondingPool(
        "agentid-bonding.db",
        status_hook=lambda did, status: registry.set_status(did, status),
    )
    return create_app(registry, pool, directory, SQLiteNonceStore("agentid-nonces.db"))
