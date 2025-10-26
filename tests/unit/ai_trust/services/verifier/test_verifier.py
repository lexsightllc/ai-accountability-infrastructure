# SPDX-License-Identifier: MPL-2.0
"""Tests for the AI Receipt Verifier."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from ai_trust.services.verifier import AIReceiptVerifier, VerificationResult

# Sample valid receipt for testing
SAMPLE_RECEIPT = {
    "receipt_version": "1.0",
    "issued_at": "2025-09-01T19:07:00Z",
    "task_hash": "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    "model_hash": "sha256:4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
    "input_commitment": "sha256:7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3g4h5i6j7k",
    "output_commitment": "sha256:0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3g4h5i6j7k8l9m0n",
    "policies": {
        "satisfied": ["P_SAFE_001", "P_PRIV_007"],
        "relaxed": []
    },
    "costs": {
        "latency_ms": 4210,
        "energy_j": 7.3,
        "tokens": 1284
    },
    "attestation": {
        "signature": "ed25519:VGVzdFNpZ25hdHVyZQ==",
        "pubkey_id": "test_key_2025"
    }
}

class TestAIReceiptVerifier:
    """Test cases for the AIReceiptVerifier class."""
    
    @pytest.fixture
    def verifier(self):
        """Create a verifier instance for testing."""
        return AIReceiptVerifier()

    def test_verify_receipt_valid(self, verifier):
        """Test verification of a valid receipt."""
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        result = verifier.verify_receipt(receipt_json)
        assert result.valid is True
        assert "successfully" in result.reason.lower()

    def test_verify_receipt_invalid_json(self, verifier):
        """Test verification with invalid JSON."""
        result = verifier.verify_receipt("{invalid json")
        assert result.valid is False
        assert "invalid json" in result.reason.lower()

    def test_verify_receipt_missing_field(self, verifier):
        """Test verification with a missing required field."""
        invalid_receipt = SAMPLE_RECEIPT.copy()
        del invalid_receipt["receipt_version"]
        result = verifier.verify_receipt(json.dumps(invalid_receipt))
        assert result.valid is False
        assert "missing required fields" in result.reason.lower()

    def test_verify_receipt_invalid_version(self, verifier):
        """Test verification with an unsupported version."""
        invalid_receipt = SAMPLE_RECEIPT.copy()
        invalid_receipt["receipt_version"] = "0.9"
        result = verifier.verify_receipt(json.dumps(invalid_receipt))
        assert result.valid is False
        assert "unsupported version" in result.reason.lower()

    def test_verify_receipt_future_timestamp(self, verifier):
        """Test verification with a future timestamp."""
        future_time = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        invalid_receipt = SAMPLE_RECEIPT.copy()
        invalid_receipt["issued_at"] = future_time
        result = verifier.verify_receipt(json.dumps(invalid_receipt))
        assert result.valid is False
        assert "future" in result.reason.lower()

    def test_verify_receipt_old_timestamp(self, verifier, monkeypatch):
        """Test verification with a very old timestamp."""
        # Mock datetime to control the current time
        class MockDateTime:
            @classmethod
            def now(cls, tz):
                return datetime(2025, 1, 1, tzinfo=tz)
        
        monkeypatch.setattr("verifier.verify.datetime", MockDateTime)
        
        old_receipt = SAMPLE_RECEIPT.copy()
        old_receipt["issued_at"] = "2020-01-01T00:00:00Z"
        result = verifier.verify_receipt(json.dumps(old_receipt))
        assert result.valid is False
        assert "too old" in result.reason.lower()

    def test_verify_receipt_invalid_hash_format(self, verifier):
        """Test verification with invalid hash format."""
        invalid_receipt = SAMPLE_RECEIPT.copy()
        invalid_receipt["task_hash"] = "invalid_hash"
        result = verifier.verify_receipt(json.dumps(invalid_receipt))
        assert result.valid is False
        assert "hash format" in result.reason.lower()

    def test_verify_receipt_invalid_policy_format(self, verifier):
        """Test verification with invalid policy format."""
        invalid_receipt = SAMPLE_RECEIPT.copy()
        invalid_receipt["policies"]["satisfied"] = ["INVALID_POLICY"]
        result = verifier.verify_receipt(json.dumps(invalid_receipt))
        assert result.valid is False
        assert "policy id format" in result.reason.lower()

    def test_verify_receipt_policy_conflict(self, verifier):
        """Test verification with conflicting policies."""
        invalid_receipt = SAMPLE_RECEIPT.copy()
        invalid_receipt["policies"]["satisfied"] = ["P_TEST_001"]
        invalid_receipt["policies"]["relaxed"] = ["P_TEST_001"]
        result = verifier.verify_receipt(json.dumps(invalid_receipt))
        assert result.valid is False
        assert "conflict" in result.reason.lower()

    def test_verify_receipt_invalid_costs(self, verifier):
        """Test verification with invalid cost values."""
        # Test negative latency
        invalid_receipt = SAMPLE_RECEIPT.copy()
        invalid_receipt["costs"]["latency_ms"] = -100
        result = verifier.verify_receipt(json.dumps(invalid_receipt))
        assert result.valid is False
        assert "latency_ms" in result.reason.lower()
        
        # Test invalid tokens
        invalid_receipt = SAMPLE_RECEIPT.copy()
        invalid_receipt["costs"]["tokens"] = -1
        result = verifier.verify_receipt(json.dumps(invalid_receipt))
        assert result.valid is False
        assert "tokens" in result.reason.lower()

    def test_verify_receipt_signature_skipped(self, verifier):
        """Test that signature verification is skipped when no public key is provided."""
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        result = verifier.verify_receipt(receipt_json)
        assert result.valid is True
        assert "signature_verified" in result.details
        assert result.details["signature_verified"] is False

    # Note: Testing actual signature verification would require generating test keys
    # and is more complex, so it's omitted from these basic tests.

    def test_verification_result_str(self):
        """Test string representation of VerificationResult."""
        result = VerificationResult(True, "Test message")
        assert str(result) == "VALID: Test message"
        
        result = VerificationResult(False, "Test error")
        assert str(result) == "INVALID: Test error"

    def test_verification_result_bool(self):
        """Test boolean evaluation of VerificationResult."""
        result = VerificationResult(True, "Test")
        assert bool(result) is True
        
        result = VerificationResult(False, "Test")
        assert bool(result) is False
