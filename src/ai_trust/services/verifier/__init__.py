# SPDX-License-Identifier: MPL-2.0
"""
AI Receipt Verifier - Core Package

This package provides functionality for verifying AI accountability receipts,
including signature validation, timestamp verification, and policy compliance.
"""

__version__ = "1.0.0"

from .verify import AIReceiptVerifier, VerificationResult

__all__ = ["AIReceiptVerifier", "VerificationResult"]
