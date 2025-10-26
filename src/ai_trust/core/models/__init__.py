# SPDX-License-Identifier: MPL-2.0
"""Data models for AI Trust."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ReceiptStatus(str, Enum):
    """Status of a receipt."""

    PENDING = "pending"
    VERIFIED = "verified"
    INVALID = "invalid"


@dataclass
class Signature:
    """Represents a cryptographic signature."""

    algorithm: str
    key_id: str
    signature: str
    timestamp: datetime


@dataclass
class Receipt:
    """Represents a verifiable receipt for AI model outputs."""

    id: str  # noqa: A003
    data: dict[str, Any]
    signature: Signature
    status: ReceiptStatus = ReceiptStatus.PENDING
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)
