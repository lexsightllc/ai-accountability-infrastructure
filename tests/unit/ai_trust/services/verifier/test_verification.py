"""
Tests for the AI Trust verification system.

This module contains tests for the verification functionality, including:
- Receipt signature verification
- Inclusion proof verification
- Consistency proof verification
- Error handling and edge cases
"""

import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization

from ai_trust.core.verification import (
    ReceiptVerifier,
    verify_receipt_file,
    VerificationResult,
    CRYPTO_AVAILABLE
)
from ai_trust.core.db import LogDB
from ai_trust.core.merkle import MerkleTree

# Skip tests if cryptography is not available
pytestmark = pytest.mark.skipif(
    not CRYPTO_AVAILABLE,
    reason="Cryptography library not available"
)

# Test data
SAMPLE_RECEIPT = {
    "receipt_id": "test-receipt-123",
    "timestamp": "2023-01-01T00:00:00Z",
    "data": {"key": "value"},
    "signature": None  # Will be filled in setup
}

class TestVerificationSystem(unittest.TestCase):
    """Test suite for the verification system."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures before any tests are run."""
        # Generate test keys
        cls.private_key = ed25519.Ed25519PrivateKey.generate()
        cls.public_key = cls.private_key.public_key()
        
        # Serialize public key for testing
        cls.public_key_bytes = cls.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Create a test database
        cls.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        cls.db_path = cls.temp_db.name
        cls.db = LogDB(cls.db_path)
        
        # Initialize verifier
        cls.verifier = ReceiptVerifier(cls.db, cls.public_key)
        
        # Sign the sample receipt
        receipt_copy = SAMPLE_RECEIPT.copy()
        receipt_copy.pop('signature', None)
        message = json.dumps(receipt_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = cls.private_key.sign(message)
        cls.signed_receipt = {**receipt_copy, 'signature': signature.hex()}
        
        # Add a receipt to the database for inclusion tests
        receipt_data = json.dumps(cls.signed_receipt).encode('utf-8')
        cls.db.add_log_entry("test-receipt-123", receipt_data)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test fixtures after all tests are run."""
        cls.temp_db.close()
        os.unlink(cls.db_path)
    
    def test_verify_valid_receipt(self):
        """Test verification of a valid receipt."""
        result = self.verifier.verify_receipt(self.signed_receipt)
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)
    
    def test_verify_tampered_receipt(self):
        """Test verification detects tampered receipt data."""
        tampered = self.signed_receipt.copy()
        tampered['data'] = {"key": "modified"}
        
        result = self.verifier.verify_receipt(tampered, verify_signature=True)
        self.assertFalse(result.is_valid)
        self.assertIn("Invalid signature", str(result.errors))
    
    def test_verify_inclusion_proof(self):
        """Test verification of inclusion proof."""
        # Get inclusion proof
        proof = self.verifier.get_inclusion_proof("test-receipt-123")
        self.assertIsNotNone(proof)
        
        # Verify the proof
        result = self.verifier.verify_receipt(
            self.signed_receipt,
            verify_inclusion=True
        )
        self.assertTrue(result.is_valid)
    
    def test_consistency_proof(self):
        """Test generation and verification of consistency proofs."""
        # Add another receipt to create a consistency proof
        receipt2 = {
            "receipt_id": "test-receipt-456",
            "timestamp": "2023-01-02T00:00:00Z",
            "data": {"key2": "value2"}
        }
        receipt2_data = json.dumps(receipt2).encode('utf-8')
        self.db.add_log_entry("test-receipt-456", receipt2_data)
        
        # Get consistency proof between size 1 and 2
        proof = self.verifier.get_consistency_proof(1, 2)
        self.assertIsNotNone(proof)
        self.assertEqual(proof['first_size'], 1)
        self.assertEqual(proof['second_size'], 2)
        
        # Verify the consistency proof
        is_consistent = self.verifier.verify_consistency_proof(
            first_size=proof['first_size'],
            second_size=proof['second_size'],
            first_root=proof['first_root_hash'],
            second_root=proof['second_root_hash'],
            proof=proof['proof_hashes']
        )
        self.assertTrue(is_consistent)


class TestVerificationEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def test_nonexistent_receipt(self):
        """Test verification of a non-existent receipt."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            db = LogDB(temp_db.name)
            verifier = ReceiptVerifier(db)
            
            result = verifier.verify_receipt({"receipt_id": "nonexistent"})
            self.assertFalse(result.is_valid)
            self.assertIn("not found", str(result.errors).lower())
            
            os.unlink(temp_db.name)
    
    def test_invalid_signature_format(self):
        """Test handling of invalid signature formats."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            db = LogDB(temp_db.name)
            verifier = ReceiptVerifier(db)
            
            # Test with non-base64 signature
            result = verifier.verify_receipt({
                "receipt_id": "test",
                "signature": "not-a-valid-signature"
            })
            self.assertFalse(result.is_valid)
            self.assertIn("invalid signature", str(result.errors).lower())
            
            os.unlink(temp_db.name)


class TestCLICommands(unittest.TestCase):
    """Test the command-line interface for verification."""
    
    def test_cli_verify_receipt(self):
        """Test the receipt verification CLI command."""
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json') as receipt_file, \
             tempfile.NamedTemporaryFile(mode='w+', suffix='.pem') as key_file, \
             tempfile.NamedTemporaryFile(suffix='.db') as db_file:
            
            # Generate a key pair
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            # Save public key to file
            key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
            )
            key_file.flush()
            
            # Create a test receipt
            receipt = {
                "receipt_id": "cli-test-123",
                "timestamp": "2023-01-01T00:00:00Z",
                "data": {"test": "value"}
            }
            
            # Sign the receipt
            message = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode('utf-8')
            signature = private_key.sign(message)
            receipt['signature'] = signature.hex()
            
            # Save receipt to file
            json.dump(receipt, receipt_file)
            receipt_file.flush()
            
            # Initialize database and add receipt
            db = LogDB(db_file.name)
            db.add_log_entry("cli-test-123", json.dumps(receipt).encode('utf-8'))
            
            # Test verification
            result = verify_receipt_file(
                file_path=receipt_file.name,
                db_path=db_file.name,
                public_key_path=key_file.name
            )
            
            self.assertTrue(result.is_valid)


if __name__ == '__main__':
    unittest.main()
