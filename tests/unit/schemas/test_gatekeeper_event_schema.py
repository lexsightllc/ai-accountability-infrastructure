"""Schema validation tests for gatekeeper events."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA_PATH = Path(__file__).resolve().parents[4] / "schemas" / "gatekeeper.event.v1.json"
FIXTURE_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "raw" / "events"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_valid_event_passes_schema_validation() -> None:
    schema = load_json(SCHEMA_PATH)
    event = load_json(FIXTURE_DIR / "valid_event.json")
    jsonschema.validate(instance=event, schema=schema)


def test_invalid_event_fails_schema_validation() -> None:
    schema = load_json(SCHEMA_PATH)
    bad_event = load_json(FIXTURE_DIR / "invalid_event.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=bad_event, schema=schema)
