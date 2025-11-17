# SPDX-License-Identifier: MPL-2.0
"""Custom exceptions for AI Trust Infrastructure.

This module defines specific exception types for different error conditions
in the AI Trust system, enabling better error handling and reporting.
"""

from typing import Any, Dict, Optional


class AITrustError(Exception):
    """Base exception for all AI Trust errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the exception.

        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class CryptographicError(AITrustError):
    """Raised when cryptographic operations fail."""

    pass


class SignatureVerificationError(CryptographicError):
    """Raised when signature verification fails."""

    pass


class InvalidKeyError(CryptographicError):
    """Raised when a cryptographic key is invalid or malformed."""

    pass


class ReceiptError(AITrustError):
    """Base exception for receipt-related errors."""

    pass


class InvalidReceiptError(ReceiptError):
    """Raised when a receipt is malformed or invalid."""

    pass


class ReceiptVerificationError(ReceiptError):
    """Raised when receipt verification fails."""

    pass


class MerkleTreeError(AITrustError):
    """Base exception for Merkle tree errors."""

    pass


class InclusionProofError(MerkleTreeError):
    """Raised when inclusion proof verification fails."""

    pass


class ConsistencyProofError(MerkleTreeError):
    """Raised when consistency proof verification fails."""

    pass


class DatabaseError(AITrustError):
    """Base exception for database errors."""

    pass


class EntryNotFoundError(DatabaseError):
    """Raised when a requested entry is not found in the database."""

    pass


class DuplicateEntryError(DatabaseError):
    """Raised when attempting to add a duplicate entry."""

    pass


class ValidationError(AITrustError):
    """Raised when input validation fails."""

    pass


class ConfigurationError(AITrustError):
    """Raised when configuration is invalid or missing."""

    pass


class RateLimitError(AITrustError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the rate limit exception.

        Args:
            message: Error message
            retry_after: Optional number of seconds to wait before retrying
            details: Optional dictionary with additional error details
        """
        super().__init__(message, details)
        self.retry_after = retry_after


class WitnessError(AITrustError):
    """Base exception for witness service errors."""

    pass


class WitnessVerificationError(WitnessError):
    """Raised when witness verification fails."""

    pass


class LogSyncError(WitnessError):
    """Raised when log synchronization fails."""

    pass
