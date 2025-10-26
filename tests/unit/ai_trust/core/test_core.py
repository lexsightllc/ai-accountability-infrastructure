"""Unit tests for core functionality."""

import hashlib

import pytest

from ai_trust.core import KeyPair, canonicalize, create_receipt, verify_receipt
from ai_trust.core.crypto import KeyStore, hash_sha256


def test_canonicalization() -> None:
    """Test that canonicalization produces consistent output."""
    data = {"b": 2, "a": 1, "c": [3, 1, 2]}
    expected = '{"a":1,"b":2,"c":[3,1,2]}'
    assert canonicalize(data) == expected


def test_keypair_generation() -> None:
    """Test key pair generation and signing."""
    key_pair = KeyPair.generate()
    data = b"test data"
    signature = key_pair.sign(data)

    assert key_pair.verify(data, signature)
    assert not key_pair.verify(b"different data", signature)


def test_receipt_creation_and_verification() -> None:
    """Test receipt creation and verification."""
    key_pair = KeyPair.generate()
    data = {"model": "test", "input": "test", "output": "test"}

    receipt = create_receipt(data, key_pair)
    assert receipt.status == "verified"

    assert verify_receipt(receipt, key_pair.public_bytes())


def test_hash_sha256() -> None:
    """hash_sha256 should match hashlib.sha256 output."""
    data = b"abc"
    assert hash_sha256(data) == hashlib.sha256(data).digest()


def test_keystore_add_and_revoke() -> None:
    """The KeyStore should return valid keys and enforce revocation."""
    kp = KeyPair.generate(kid="test")
    store = KeyStore()
    store.add_key(kp)
    assert store.get_key("test") is kp
    store.revoke_key("test")
    with pytest.raises(KeyError):
        store.get_key("test")


def test_keypair_jwk_roundtrip() -> None:
    """KeyPair should round-trip through JWK format."""
    kp = KeyPair.generate(kid="jwk-test")
    jwk = kp.to_jwk(private=True)
    kp2 = KeyPair.from_jwk(jwk)
    data = b"hello"
    sig = kp2.sign(data)
    assert kp2.verify(data, sig)
    assert jwk["kid"] == kp2.kid
