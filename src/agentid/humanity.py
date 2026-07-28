"""Issuer credentials and a public-verifiable Ed25519 Schnorr proof."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from .canonical import canonical_json
from .identity import KeyStore, verify_signature

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
Point = tuple[int, int]
_IDENTITY: Point = (0, 1)
_BASE: Point = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def _add(left: Point, right: Point) -> Point:
    x1, y1 = left
    x2, y2 = right
    product = _D * x1 * x2 * y1 * y2
    return (
        ((x1 * y2 + y1 * x2) * pow(1 + product, _P - 2, _P)) % _P,
        ((y1 * y2 + x1 * x2) * pow(1 - product, _P - 2, _P)) % _P,
    )


def _multiply(point: Point, scalar: int) -> Point:
    result = _IDENTITY
    current = point
    while scalar:
        if scalar & 1:
            result = _add(result, current)
        current = _add(current, current)
        scalar >>= 1
    return result


def _encode(point: Point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(encoded: bytes) -> Point:
    if len(encoded) != 32:
        raise ValueError("invalid Ed25519 point length")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("invalid Ed25519 point")
    xx = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P or (x == 0 and sign):
        raise ValueError("invalid Ed25519 point")
    if x & 1 != sign:
        x = _P - x
    return x, y


@dataclass(frozen=True)
class HumanSubject:
    did: str
    is_autonomous: bool = False


@dataclass(frozen=True)
class AgentSubject:
    did: str
    is_autonomous: bool = True


@dataclass(frozen=True)
class VerifiableCredential:
    issuer: str
    subject: str
    humanity_proof: bool
    signature: bytes


@dataclass(frozen=True)
class HumanProof:
    nullifier: str
    commitment: str
    challenge: str
    response: str
    public_key: str


def issue_credential(issuer: KeyStore, subject: str) -> VerifiableCredential:
    payload = canonical_json({"issuer": issuer.did, "subject": subject, "humanityProof": True})
    return VerifiableCredential(issuer.did, subject, True, issuer.sign(payload))


def verify_credential(vc: VerifiableCredential, issuer_public_key: bytes) -> bool:
    return verify_signature(
        issuer_public_key,
        canonical_json(
            {"issuer": vc.issuer, "subject": vc.subject, "humanityProof": vc.humanity_proof}
        ),
        vc.signature,
    )


def _scalar(secret: bytes, context: str) -> int:
    value = (
        int.from_bytes(
            hashlib.sha512(secret + b"\x00key\x00" + context.encode("utf-8")).digest(), "little"
        )
        % _L
    )
    return value or 1


def _nullifier(secret: bytes, context: str) -> bytes:
    return hashlib.sha256(secret + context.encode("utf-8")).digest()


def _challenge(commitment: bytes, public_key: bytes, nullifier: bytes, context: str) -> int:
    transcript = commitment + public_key + nullifier + context.encode("utf-8")
    return int.from_bytes(hashlib.sha256(transcript).digest(), "little") % _L


def create_human_proof(secret: bytes, context: str) -> HumanProof:
    """Create a Fiat-Shamir proof; the verifier only needs the returned object."""
    if not secret:
        raise ValueError("secret must not be empty")
    private_scalar = _scalar(secret, context)
    public_key = _encode(_multiply(_BASE, private_scalar))
    nullifier = _nullifier(secret, context)
    nonce = secrets.randbelow(_L - 1) + 1
    commitment = _encode(_multiply(_BASE, nonce))
    challenge = _challenge(commitment, public_key, nullifier, context)
    response = (nonce + challenge * private_scalar) % _L
    return HumanProof(
        nullifier.hex(), commitment.hex(), str(challenge), str(response), public_key.hex()
    )


def verify_human(proof: HumanProof, context: str) -> bool:
    """Verify a proof without receiving or reconstructing the subject secret."""
    try:
        nullifier = bytes.fromhex(proof.nullifier)
        commitment_bytes = bytes.fromhex(proof.commitment)
        commitment = _decode(commitment_bytes)
        public_key_bytes = bytes.fromhex(proof.public_key)
        public_key = _decode(public_key_bytes)
        challenge = int(proof.challenge)
        response = int(proof.response)
        if len(nullifier) != 32 or len(public_key_bytes) != 32:
            return False
        expected = _challenge(commitment_bytes, public_key_bytes, nullifier, context)
        if challenge != expected or not 0 < response < _L:
            return False
        return _multiply(_BASE, response) == _add(commitment, _multiply(public_key, challenge))
    except (ValueError, OverflowError):
        return False


def classify(did: str) -> HumanSubject | AgentSubject:
    return AgentSubject(did) if did.startswith("did:agent:") else HumanSubject(did)
