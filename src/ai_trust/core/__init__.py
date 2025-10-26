# SPDX-License-Identifier: MPL-2.0
"""Core functionality for AI Trust."""
from ai_trust.core.canonicalization import canonicalize
from ai_trust.core.crypto import KeyPair, create_keypair, sign, verify_signature
from ai_trust.core.receipt import create_receipt, verify_receipt

__all__ = [
    "canonicalize",
    "KeyPair",
    "create_keypair",
    "sign",
    "verify_signature",
    "create_receipt",
    "verify_receipt",
]
