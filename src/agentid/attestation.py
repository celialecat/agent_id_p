"""Operator attestations."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from .canonical import canonical_json
from .identity import KeyStore, did_from_public_key, verify_signature


class OperatorAttestation(BaseModel):
    model_config = ConfigDict(frozen=True)
    operator_id: str
    agent_did: str
    agent_public_key: str
    scopes: list[str] = Field(default_factory=list)
    is_autonomous: bool = True
    contact_endpoint: str
    not_before: datetime
    expires_at: datetime
    nonce: str = Field(default_factory=lambda: uuid4().hex)
    signature: str | None = None

    def signing_payload(self) -> bytes:
        return canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    def sign(self, operator_key: KeyStore) -> OperatorAttestation:
        return self.model_copy(
            update={"signature": operator_key.sign(self.signing_payload()).hex()}
        )

    def verify(self, operator_public_key: bytes, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        if (
            not self.is_autonomous
            or self.not_before.tzinfo is None
            or self.expires_at.tzinfo is None
        ):
            return False
        if not self.not_before <= now <= self.expires_at or not self.signature:
            return False
        try:
            if did_from_public_key(bytes.fromhex(self.agent_public_key)) != self.agent_did:
                return False
        except ValueError:
            return False
        return verify_signature(
            operator_public_key, self.signing_payload(), bytes.fromhex(self.signature)
        )

    def as_record(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
