"""Ed25519 identities and self-certifying AgentDIDs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PREFIX = bytes.fromhex("ed01")


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    result = ""
    while number:
        number, remainder = divmod(number, 58)
        result = ALPHABET[remainder] + result
    return ALPHABET[0] * (len(data) - len(data.lstrip(b"\0"))) + (result or ALPHABET[0])


def b58decode(value: str) -> bytes:
    if not value or any(char not in ALPHABET for char in value):
        raise ValueError("invalid base58")
    number = 0
    for char in value:
        number = number * 58 + ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + raw


def did_from_public_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("Ed25519 public keys are 32 bytes")
    return f"did:agent:{b58encode(PREFIX + public_key)}"


def public_key_from_did(did: str) -> bytes:
    if not did.startswith("did:agent:") or did.count(":") != 2:
        raise ValueError("invalid AgentDID")
    decoded = b58decode(did.removeprefix("did:agent:"))
    if len(decoded) != 34 or decoded[:2] != PREFIX:
        raise ValueError("invalid AgentDID key material")
    return decoded[2:]


@dataclass(frozen=True)
class KeyStore:
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> KeyStore:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_raw(cls, raw: bytes) -> KeyStore:
        if len(raw) != 32:
            raise ValueError("invalid raw private key")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> KeyStore:
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("PEM does not contain Ed25519 key")
        return cls(key)

    @classmethod
    def from_file(cls, path: str | Path, password: bytes | None = None) -> KeyStore:
        return cls.from_pem(Path(path).read_bytes(), password)

    @property
    def public_key(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def did(self) -> str:
        return did_from_public_key(self.public_key)

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload)

    def raw(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def pem(self, password: bytes | None = None) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )


def verify_signature(public_key: bytes, payload: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except Exception:
        return False
    return True
