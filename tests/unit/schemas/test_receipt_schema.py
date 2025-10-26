"""Conformance tests for receipt-v1 JSON schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate

SCHEMA_PATH = Path(__file__).resolve().parents[4] / "schemas" / "receipt-v1.schema.json"
VECTORS_DIR = SCHEMA_PATH.parent / "vectors"

with SCHEMA_PATH.open("r", encoding="utf-8") as f:
    SCHEMA = json.load(f)


def load_vectors(kind: str) -> list[Path]:
    return sorted((VECTORS_DIR / kind).glob("*.json"))


@pytest.mark.parametrize("vector", load_vectors("valid"))
def test_valid_vectors(vector: Path) -> None:
    data = json.loads(vector.read_text())
    validate(instance=data, schema=SCHEMA)


@pytest.mark.parametrize("vector", load_vectors("invalid"))
def test_invalid_vectors(vector: Path) -> None:
    data = json.loads(vector.read_text())
    with pytest.raises(ValidationError):
        validate(instance=data, schema=SCHEMA)
