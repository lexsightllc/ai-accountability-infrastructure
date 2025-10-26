# SPDX-License-Identifier: MPL-2.0
"""Canonicalization utilities following JSON Canonicalization Scheme (RFC 8785)."""

from __future__ import annotations

import json
import math
import unicodedata
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any


class CanonicalizationError(Exception):
    """Raised when data cannot be canonicalized."""


def _normalize(value: Any) -> Any:
    """Recursively normalise a value for canonical JSON serialisation."""

    if isinstance(value, str):
        # Apply NFC normalization for Unicode strings
        return unicodedata.normalize("NFC", value)

    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value

    if isinstance(value, float):
        # RFC 8785: reject NaN/Infinity and emit the most compact form
        if not math.isfinite(value):
            raise CanonicalizationError("Non-finite float values are not allowed")
        if value.is_integer():
            return int(value)
        # Convert through Decimal to avoid scientific notation
        return float(Decimal(str(value)))

    if isinstance(value, datetime):
        # Convert to UTC and RFC3339 format without superfluous zeros
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        value = value.astimezone(timezone.utc)
        iso = value.isoformat(timespec="microseconds").replace("+00:00", "Z")
        if "." in iso:
            main, rest = iso.split(".", 1)
            frac, _ = rest.split("Z")
            frac = frac.rstrip("0")
            iso = main + ("." + frac if frac else "") + "Z"
        return iso

    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]

    if isinstance(value, dict):
        # Ensure all keys are strings
        if any(not isinstance(k, str) for k in value):
            raise CanonicalizationError("Dictionary keys must be strings")
        return {k: _normalize(v) for k, v in value.items()}

    raise CanonicalizationError(f"Type {type(value)!r} is not supported for canonicalization")


def canonicalize(data: Any) -> str:
    """Convert data to a canonical JSON string.

    The implementation performs Unicode NFC normalisation and follows the
    JSON Canonicalization Scheme (RFC 8785) for numbers and datetimes.
    """

    canonical_data = _normalize(data)
    try:
        return json.dumps(
            canonical_data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def canonical_json_dumps(data: Any) -> str:
    """Convenience wrapper for :func:`canonicalize`."""

    return canonicalize(data)


def verify_canonical_equivalence(a: Any, b: Any) -> bool:
    """Return True if two objects canonicalize to the same JSON string."""

    try:
        return canonicalize(a) == canonicalize(b)
    except CanonicalizationError:
        return False
