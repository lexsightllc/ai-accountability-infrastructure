"""
Tests for the receipt module.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

import pytest
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

from ai_trust.core.crypto import KeyPair
from ai_trust.core.models import (
    InputCommitment,
    ModelInfo,
    OutputCommitment,
    ReceiptVersion,
)
from ai_trust.core.receipt import Receipt


class TestReceipt:
    """Test cases for the Receipt class."""

    @pytest.fixture
    def sample_receipt_data(self):
        """Create sample receipt data for testing."""
        return {
            "receipt_version": ReceiptVersion.V1,
            "execution_id": "test-execution-123",
            "issued_at": datetime.now(timezone.utc),
            "issuer": "https://example.com",
            "model": ModelInfo(
                name="test-model",
                version="1.0",
                commit_sha256="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",  # 64 chars
            ),
            "output": OutputCommitment(
                body_sha256="d3b07384d113edec49eaa6238ad5ff00" * 2,
                content_type="text/plain",
            ),
        }

    @pytest.fixture
    def sample_keypair(self):
        """Create a sample key pair for testing."""
        return KeyPair.generate("test-key")

    def test_create_receipt(self, sample_receipt_data):
        """Test creating a receipt with valid data."""
        receipt = Receipt(**sample_receipt_data)
        assert receipt.execution_id == sample_receipt_data["execution_id"]
        # Compare string representations to handle AnyHttpUrl type
        assert str(receipt.issuer).rstrip('/') == sample_receipt_data["issuer"].rstrip('/')
        assert receipt.model.name == sample_receipt_data["model"].name

    def test_invalid_execution_id(self, sample_receipt_data):
        """Test that invalid execution IDs are rejected."""
        # Test with empty string
        with pytest.raises(ValueError):
            Receipt(**{**sample_receipt_data, "execution_id": ""})

        # Test with invalid characters
        with pytest.raises(ValueError):
            Receipt(**{**sample_receipt_data, "execution_id": "invalid!id"})

    def test_sign_and_verify(self, sample_receipt_data, sample_keypair):
        """Test signing and verifying a receipt."""
        # Create and sign the receipt
        receipt = Receipt(**sample_receipt_data)
        signed_receipt = receipt.sign(sample_keypair)

        # The receipt should now have a signature
        assert signed_receipt.signature is not None
        assert signed_receipt.signature.kid == sample_keypair.kid
        assert signed_receipt.signature.alg == "EdDSA"

        # Verify the signature using the receipt's verify_signature method
        # This is the recommended way to verify signatures
        assert signed_receipt.verify_signature(sample_keypair.public_key)

    def test_verify_tampered_receipt(self, sample_receipt_data, sample_keypair):
        """Test that tampered receipts fail verification."""
        # Create and sign the receipt
        receipt = Receipt(**sample_receipt_data)
        signed_receipt = receipt.sign(sample_keypair)

        # Tamper with the receipt
        tampered_receipt = signed_receipt.model_copy()
        tampered_receipt.model.name = "tampered-model"

        # Verification should fail
        assert not tampered_receipt.verify_signature(sample_keypair.public_key)

    def test_canonical_representation(self, sample_receipt_data):
        """Test that the canonical representation is deterministic."""
        receipt1 = Receipt(**sample_receipt_data)
        receipt2 = Receipt(**sample_receipt_data)

        # The canonical JSON should be identical
        assert receipt1.to_canonical_json() == receipt2.to_canonical_json()

        # Changing the order of fields should not affect the canonical representation
        receipt2.model.parameters = {"b": 2, "a": 1}
        receipt1.model.parameters = {"a": 1, "b": 2}
        assert receipt1.to_canonical_json() == receipt2.to_canonical_json()

    def test_save_and_load(self, sample_receipt_data, tmp_path):
        """Test saving and loading a receipt to/from a file."""
        receipt = Receipt(**sample_receipt_data)
        file_path = tmp_path / "receipt.json"

        # Save the receipt
        with open(file_path, "w") as f:
            json.dump(receipt.model_dump(), f, default=str)

        # Load the receipt
        with open(file_path, "r") as f:
            loaded_data = json.load(f)
            loaded_receipt = Receipt(**loaded_data)

        # The loaded receipt should be equal to the original
        assert loaded_receipt.model_dump() == receipt.model_dump()

    def test_add_log_entry(self, sample_receipt_data):
        """Test adding a log entry to a receipt."""
        receipt = Receipt(**sample_receipt_data)
        assert receipt.log_entries is None
        
        # Create a valid SHA-256 hash
        root_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        
        # Add a log entry with a valid SHA-256 hash and witness_id
        receipt_with_log = receipt.add_log_entry(
            log_id="test-log",
            leaf_index=123,
            tree_size=1000,
            root_hash=root_hash,
            witness_id="witness-1"
        )

        # The receipt should now have a log entry
        assert receipt_with_log.log_entries is not None
        assert len(receipt_with_log.log_entries) == 1
        log_entry = receipt_with_log.log_entries[0]
        assert log_entry.log_id == "test-log"
        assert log_entry.leaf_index == 123
        assert log_entry.tree_size == 1000
        assert log_entry.root_hash == root_hash
        
        # Add a witness signature
        receipt_with_witness = receipt_with_log.add_witness_signature(
            log_id="test-log",
            witness_id="witness-1",
            signature="test-signature"
        )
        
        # The receipt should now have a witness signature
        assert receipt_with_witness.witness_signatures is not None
        assert len(receipt_with_witness.witness_signatures) == 1
        assert receipt_with_witness.witness_signatures[0].witness_id == "witness-1"

    def test_add_witness_signature(self, sample_receipt_data):
        """Test adding a witness signature to a receipt."""
        receipt = Receipt(**sample_receipt_data)
        assert receipt.witness_signatures is None

        # Add a witness signature
        receipt_with_witness = receipt.add_witness_signature(
            log_id="test-log",
            witness_id="witness-1",
            signature="test-signature",
        )

        # The receipt should now have a witness signature
        assert receipt_with_witness.witness_signatures is not None
        assert len(receipt_with_witness.witness_signatures) == 1
        witness = receipt_with_witness.witness_signatures[0]
        assert witness.log_id == "test-log"
        assert witness.witness_id == "witness-1"
        assert witness.signature == "test-signature"

    def test_receipt_factory_method(self):
        """Test the create factory method."""
        receipt = Receipt.create(
            execution_id="test-execution-123",
            issuer="https://example.com",
            model_name="test-model",
            body_sha256="d3b07384d113edec49eaa6238ad5ff00" * 2,
            content_type="text/plain",
            model_version="1.0",
            model_commit="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            inputs=[
                {"hmac": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "salt_id": "salt1"},
                {"hmac": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1", "salt_id": "salt2"},
            ],
            policy={"key": "value"},
            extensions={"ext": "data"},
        )

        assert receipt.execution_id == "test-execution-123"
        assert str(receipt.issuer).rstrip('/') == "https://example.com"
        assert receipt.model.name == "test-model"
        assert receipt.model.version == "1.0"
        assert receipt.output.body_sha256 == "d3b07384d113edec49eaa6238ad5ff00" * 2
        assert receipt.output.content_type == "text/plain"
        assert receipt.inputs is not None
        assert len(receipt.inputs) == 2
        assert receipt.inputs[0].hmac == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        assert receipt.inputs[0].salt_id == "salt1"
        assert receipt.inputs[1].hmac == "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1"
        assert receipt.inputs[1].salt_id == "salt2"
        assert receipt.policy == {"key": "value"}
        assert receipt.extensions == {"ext": "data"}
