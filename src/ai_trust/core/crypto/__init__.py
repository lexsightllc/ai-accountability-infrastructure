# SPDX-License-Identifier: MPL-2.0
"""Cryptographic primitives and helpers for AI Trust.

This module provides a minimal Ed25519 wrapper used throughout the project.
It also exposes a small in-memory :class:`KeyStore` and a helper hashing
function.  The CLI previously imported ``KeyStore`` and ``hash_sha256`` from
this module, but the implementations were missing which caused ``ImportError``
during execution.  The key management features implemented here are intentionally
light-weight but provide the required hooks for validity windows and revocation
support.
"""

from __future__ import annotations

import hashlib
import os
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass
class KeyPair:
    """Represents an Ed25519 public/private key pair.

    The class stores a *key identifier* (``kid``) and optional validity window
    metadata which are used by :class:`KeyStore`.  Existing tests only rely on
    basic signing and verification so default values keep behaviour unchanged.
    """

    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey
    kid: str = field(default_factory=lambda: f"key-{os.urandom(8).hex()}")
    not_before: datetime | None = None
    not_after: datetime | None = None

    DOMAIN: ClassVar[bytes] = b"ai-trust-v1"

    @classmethod
    def generate(cls, kid: str | None = None) -> KeyPair:
        """Generate a new key pair.

        Args:
            kid: Optional key identifier.  If omitted, a random identifier is
                generated.
        """

        private_key = ed25519.Ed25519PrivateKey.generate()
        return cls(
            private_key=private_key,
            public_key=private_key.public_key(),
            kid=kid or f"key-{os.urandom(8).hex()}",
        )

    def sign(self, data: bytes, timestamp: float | None = None) -> bytes:
        """Sign data with the private key."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).timestamp()
        timestamp_int = int(timestamp)
        signed_data = self.DOMAIN + timestamp_int.to_bytes(8, "big") + data
        return cast("bytes", self.private_key.sign(signed_data))

    def verify(
        self,
        data: bytes,
        signature: bytes,
        timestamp: float | None = None,
        max_age_seconds: float = 300,
    ) -> bool:
        """Verify a signature."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).timestamp()
        if abs(datetime.now(timezone.utc).timestamp() - timestamp) > max_age_seconds:
            return False
        try:
            timestamp_int = int(timestamp)
            signed_data = self.DOMAIN + timestamp_int.to_bytes(8, "big") + data
            self.public_key.verify(signature, signed_data)
        except Exception:
            return False
        else:
            return True

    def public_bytes(self) -> bytes:
        """Get the public key as bytes."""
        return cast(
            "bytes",
            self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    @classmethod
    def from_private_bytes(cls, private_bytes: bytes) -> KeyPair:
        """Create a KeyPair from private key bytes."""
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        return cls(private_key=private_key, public_key=private_key.public_key())

    # ------------------------------------------------------------------
    # JWK helpers
    # ------------------------------------------------------------------
    def to_jwk(self, private: bool = False) -> dict:
        """Return the key in JSON Web Key (JWK) format.

        Args:
            private: If ``True`` include the private key material.  The default
                is ``False`` which returns only the public key.
        """

        def _b64u(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.kid,
            "x": _b64u(self.public_bytes()),
        }

        if private:
            private_bytes = cast(
                "bytes",
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            )
            jwk["d"] = _b64u(private_bytes)

        return jwk

    @classmethod
    def from_jwk(cls, jwk: dict) -> KeyPair:
        """Construct a :class:`KeyPair` from JWK data."""

        def _b64u_decode(data: str) -> bytes:
            padding = "=" * (-len(data) % 4)
            return base64.urlsafe_b64decode(data + padding)

        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError("Unsupported JWK parameters")

        public_bytes = _b64u_decode(jwk["x"])
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

        if "d" in jwk:
            private_bytes = _b64u_decode(jwk["d"])
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        else:
            raise ValueError("JWK does not contain private key material")

        return cls(private_key=private_key, public_key=public_key, kid=jwk.get("kid"))


def create_keypair() -> KeyPair:
    """Generate a new key pair."""
    return KeyPair.generate()


def sign(key_pair: KeyPair, data: bytes, timestamp: float | None = None) -> bytes:
    """Sign data with the provided key pair."""
    return key_pair.sign(data, timestamp)


def verify_signature(
    key_pair: KeyPair,
    data: bytes,
    signature: bytes,
    timestamp: float | None = None,
    max_age_seconds: float = 300,
) -> bool:
    """Verify a signature using the provided key pair."""
    return key_pair.verify(data, signature, timestamp, max_age_seconds)


def hash_sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of ``data``.

    The function returns raw bytes instead of a hexadecimal string to make it
    suitable for Merkle tree construction and other binary uses.
    """

    return hashlib.sha256(data).digest()


class KeyStore:
    """A simple in-memory key store.

    The store tracks key pairs by ``kid`` and supports basic revocation and
    validity window enforcement.  It is intentionally minimal but provides the
    API surface expected by the CLI and higher level components.
    """

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}
        self._revoked: set[str] = set()

    def add_key(self, key_pair: KeyPair) -> None:
        """Add ``key_pair`` to the store."""

        self._keys[key_pair.kid] = key_pair

    def get_key(self, kid: str) -> KeyPair:
        """Retrieve ``kid`` ensuring it is valid and not revoked."""

        if kid in self._revoked:
            raise KeyError(kid)

        key = self._keys.get(kid)
        if key is None:
            raise KeyError(kid)

        now = datetime.now(timezone.utc)
        if key.not_before and now < key.not_before:
            raise KeyError(kid)
        if key.not_after and now > key.not_after:
            raise KeyError(kid)

        return key

    def revoke_key(self, kid: str) -> None:
        """Mark ``kid`` as revoked."""

        self._revoked.add(kid)

    def list_keys(self) -> dict[str, KeyPair]:
        """Return a mapping of all stored keys."""

        return dict(self._keys)
