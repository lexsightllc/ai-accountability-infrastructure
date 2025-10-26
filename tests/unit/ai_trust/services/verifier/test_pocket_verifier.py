"""Pocket verifier unit tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ai_trust.services.verifier.pocket_verifier import (
    b64url_encode,
    jcs,
    load_jwks,
    verify,
)


FIXTURE_DIR = Path(__file__).resolve().parents[5] / "fixtures" / "raw" / "receipts"


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_valid_receipt() -> None:
    jwks = load_jwks(str(FIXTURE_DIR / "test_jwks.json"))
    receipt = _load_json(FIXTURE_DIR / "valid_receipt.json")
    input_data = _load_json(FIXTURE_DIR / "input_nfd.json")
    output_data = _load_json(FIXTURE_DIR / "output.json")
    ok, reasons = verify(receipt, jwks, input_data, output_data)
    assert ok, reasons


def test_invalid_nonce() -> None:
    jwks = load_jwks(str(FIXTURE_DIR / "test_jwks.json"))
    receipt = _load_json(FIXTURE_DIR / "invalid_nonce.json")
    ok, reasons = verify(receipt, jwks)
    assert not ok


def test_invalid_issued_at() -> None:
    jwks = load_jwks(str(FIXTURE_DIR / "test_jwks.json"))
    receipt = _load_json(FIXTURE_DIR / "invalid_issued_at_offset.json")
    ok, reasons = verify(receipt, jwks)
    assert not ok


def test_unicode_commitment_vector() -> None:
    vector = _load_json(FIXTURE_DIR / "unicode_commitment.json")
    payload = {"prompt": vector["nfd"]}
    digest = hashlib.sha256(jcs(payload).encode()).digest()
    commitment = f"sha256:{b64url_encode(digest)}"
    assert commitment == vector["commitment"]
