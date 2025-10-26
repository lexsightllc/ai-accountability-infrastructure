# SPDX-License-Identifier: MPL-2.0
"""
AI Trust - Cryptographic receipts for AI accountability.

This package provides tools for creating, signing, and verifying cryptographic receipts
for AI model outputs, enabling transparency and accountability in AI systems.
"""

import contextlib
from importlib.metadata import version

# Set up version
__version__ = "0.1.0"

with contextlib.suppress(Exception):
    __version__ = version("ai-trust")


# Core components
from ai_trust.core import canonicalize, create_receipt, verify_receipt, verify_signature

# Public API
__all__ = [
    "canonicalize",
    "verify_signature",
    "create_receipt",
    "verify_receipt",
    "__version__",
]
