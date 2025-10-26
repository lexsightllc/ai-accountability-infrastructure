# SPDX-License-Identifier: MPL-2.0
"""Tests for the AI Trust Transparency Log."""

import hashlib
import json
import os
import tempfile
import time
from datetime import datetime

import pytest

from log.server import (
    TransparencyLog, 
    MerkleTree, 
    LogEntry, 
    InclusionProof,
    create_app
)

# Sample receipt for testing
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

class TestMerkleTree:
    """Test cases for the MerkleTree class."""
    
    def test_empty_tree(self):
        """Test that an empty tree has the correct root hash."""
        tree = MerkleTree()
        assert tree.root_hash == "0" * 64
        assert tree.size == 0
    
    def test_single_leaf(self):
        """Test a tree with a single leaf."""
        tree = MerkleTree()
        index = tree.add_leaf("a" * 64)
        
        assert index == 0
        assert tree.size == 1
        assert tree.root_hash == "a" * 64
        
        # Verify the inclusion proof
        proof = tree.get_proof(0)
        assert proof is not None
        assert proof.index == 0
        assert proof.tree_size == 1
        assert proof.leaf_hash == "a" * 64
        assert proof.audit_path == []
        assert tree.verify_proof(proof)
    
    def test_two_leaves(self):
        """Test a tree with two leaves."""
        tree = MerkleTree()
        index1 = tree.add_leaf("a" * 64)
        index2 = tree.add_leaf("b" * 64)
        
        assert index1 == 0
        assert index2 == 1
        assert tree.size == 2
        
        # The root should be hash(aaabbb)
        expected_root = hashlib.sha256(f"{'a'*64}:{'b'*64}".encode()).hexdigest()
        assert tree.root_hash == expected_root
        
        # Verify inclusion proofs
        proof1 = tree.get_proof(0)
        assert proof1 is not None
        assert proof1.index == 0
        assert proof1.tree_size == 2
        assert proof1.leaf_hash == "a" * 64
        assert proof1.audit_path == ["b" * 64]
        assert tree.verify_proof(proof1)
        
        proof2 = tree.get_proof(1)
        assert proof2 is not None
        assert proof2.index == 1
        assert proof2.tree_size == 2
        assert proof2.leaf_hash == "b" * 64
        assert proof2.audit_path == ["a" * 64]
        assert tree.verify_proof(proof2)
    
    def test_three_leaves(self):
        """Test a tree with three leaves (unbalanced)."""
        tree = MerkleTree()
        index1 = tree.add_leaf("a" * 64)
        index2 = tree.add_leaf("b" * 64)
        index3 = tree.add_leaf("c" * 64)
        
        assert index1 == 0
        assert index2 == 1
        assert index3 == 2
        assert tree.size == 3
        
        # The root should be hash(hash(aaabbb)ccccc)
        level1_hash1 = hashlib.sha256(f"{'a'*64}:{'b'*64}".encode()).hexdigest()
        level1_hash2 = hashlib.sha256(f"{'c'*64}:{'c'*64}".encode()).hexdigest()  # Duplicate for odd number
        expected_root = hashlib.sha256(f"{level1_hash1}:{level1_hash2}".encode()).hexdigest()
        assert tree.root_hash == expected_root
        
        # Verify inclusion proof for the first leaf
        proof1 = tree.get_proof(0)
        assert proof1 is not None
        assert proof1.index == 0
        assert proof1.tree_size == 3
        assert proof1.leaf_hash == "a" * 64
        assert len(proof1.audit_path) == 2  # Should have two hashes in the audit path
        assert tree.verify_proof(proof1)
    
    def test_invalid_proof(self):
        """Test that invalid proofs are rejected."""
        tree = MerkleTree()
        tree.add_leaf("a" * 64)
        tree.add_leaf("b" * 64)
        
        # Create a valid proof
        valid_proof = tree.get_proof(0)
        
        # Tamper with the proof
        invalid_proof = InclusionProof(
            index=0,
            tree_size=2,
            leaf_hash="x" * 64,  # Invalid leaf hash
            audit_path=valid_proof.audit_path
        )
        assert not tree.verify_proof(invalid_proof)
        
        # Test with invalid index
        invalid_proof = InclusionProof(
            index=2,  # Out of bounds
            tree_size=2,
            leaf_hash="a" * 64,
            audit_path=[]
        )
        assert not tree.verify_proof(invalid_proof)


class TestTransparencyLog:
    """Test cases for the TransparencyLog class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    def test_append_and_retrieve_receipt(self, temp_dir):
        """Test appending and retrieving a receipt from the log."""
        log = TransparencyLog(storage_dir=temp_dir)
        
        # Append a receipt
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        index, receipt_hash = log.append_receipt(receipt_json)
    
        # Verify the receipt was added correctly
        assert index == 0
        assert receipt_hash == hashlib.sha256(receipt_json.encode()).hexdigest()
        
        # Retrieve the receipt
        entry = log.get_receipt(index)
        assert entry is not None
        assert entry.index == 0
        assert entry.receipt_hash == receipt_hash
        assert entry.receipt == receipt_json
    
        # Try retrieving by hash
        entry_by_hash = log.get_receipt(receipt_hash)
        assert entry_by_hash is not None
        assert entry_by_hash.index == index
        assert entry_by_hash.receipt_hash == receipt_hash

    def test_duplicate_receipt(self, temp_dir):
        """Test that duplicate receipts are detected."""
        log = TransparencyLog(storage_dir=temp_dir)
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        
        # First append should succeed
        index1, receipt_hash1 = log.append_receipt(receipt_json)
        
        # Second append with same content should return same index and hash
        index2, receipt_hash2 = log.append_receipt(receipt_json)
        
        assert index1 == index2
        assert receipt_hash1 == receipt_hash2
    
        # Verify only one entry in the log
        assert log.get_tree_size() == 1

    def test_inclusion_proof(self, temp_dir):
        """Test generating and verifying inclusion proofs."""
        log = TransparencyLog(storage_dir=temp_dir)
        
        # Add a receipt
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        index, receipt_hash = log.append_receipt(receipt_json)
        
        # Get inclusion proof
        proof = log.get_inclusion_proof(index)
        assert proof is not None
        assert proof.index == 0
        assert proof.tree_size == 1
        assert proof.leaf_hash == log.get_receipt(index).merkle_leaf_hash
        
        # Verify the proof
        assert log.merkle_tree.verify_proof(proof)

    def test_multiple_receipts(self, temp_dir):
        """Test with multiple receipts in the log."""
        log = TransparencyLog(storage_dir=temp_dir)
        
        # Add multiple receipts
        receipts = []
        for i in range(3):
            receipt = SAMPLE_RECEIPT.copy()
            receipt["task_hash"] = f"sha256:{'a' * 60}{i:02x}"  # Make each receipt unique
            receipt_json = json.dumps(receipt)
            index, receipt_hash = log.append_receipt(receipt_json)
            receipts.append((index, receipt_hash, receipt_json))
        
        # Verify all receipts are stored correctly
        assert log.get_tree_size() == 3
        
        for index, receipt_hash, receipt_json in receipts:
            entry = log.get_receipt(index)
            assert entry is not None
            assert entry.index == index
            assert entry.receipt_hash == receipt_hash
            assert entry.receipt == receipt_json
            
            # Verify inclusion proof
            proof = log.get_inclusion_proof(index)
            assert proof is not None
            assert log.merkle_tree.verify_proof(proof)


class TestFlaskApp:
    """Test cases for the Flask application."""
    
    @pytest.fixture
    def client(self, tmp_path):
        """Create a test client for the Flask app."""
        app = create_app({
            'TESTING': True,
            'STORAGE_DIR': str(tmp_path / 'data')
        })
        
        with app.test_client() as client:
            with app.app_context():
                yield client

    def test_health_check(self, client):
        """Test the health check endpoint."""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert data['tree_size'] == 0
        assert 'merkle_root' in data

    def test_submit_receipt(self, client):
        """Test submitting a receipt to the log."""
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        
        # Submit the receipt
        response = client.post(
            '/receipts',
            data=receipt_json,
            content_type='application/json'
        )
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['index'] == 0
        assert 'receipt_hash' in data
        assert 'merkle_root' in data
        
        # Verify the receipt was stored
        response = client.get(f'/receipts/{data["receipt_hash"]}')
        assert response.status_code == 200
        receipt_data = json.loads(response.data)
        assert receipt_data['receipt_hash'] == data['receipt_hash']

    def test_get_receipt(self, client):
        """Test retrieving a receipt by ID."""
        # First submit a receipt
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        response = client.post(
            '/receipts',
            data=receipt_json,
            content_type='application/json'
        )
        assert response.status_code == 201
        receipt_data = json.loads(response.data)
        
        # Get by index
        response = client.get('/receipts/0')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['index'] == 0
        assert data['receipt_hash'] == receipt_data['receipt_hash']
        
        # Get by hash
        response = client.get(f'/receipts/{receipt_data["receipt_hash"]}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['index'] == 0

    def test_get_inclusion_proof(self, client):
        """Test getting an inclusion proof for a receipt."""
        # Submit a receipt
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        response = client.post(
            '/receipts',
            data=receipt_json,
            content_type='application/json'
        )
        assert response.status_code == 201
        receipt_data = json.loads(response.data)
        
        # Get inclusion proof
        response = client.get(f'/proofs/{receipt_data["receipt_hash"]}')
        assert response.status_code == 200
        proof = json.loads(response.data)
        assert proof['index'] == 0
        assert proof['tree_size'] == 1
        assert 'leaf_hash' in proof
        assert 'audit_path' in proof
        assert 'merkle_root' in proof

    def test_get_merkle_root(self, client):
        """Test getting the current Merkle root."""
        response = client.get('/tree/root')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'tree_size' in data
        assert 'root_hash' in data

    def test_get_tree_size(self, client):
        """Test getting the current tree size."""
        response = client.get('/tree/size')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'tree_size' in data
        assert data['tree_size'] == 0
        
        # Add a receipt and check the size
        receipt_json = json.dumps(SAMPLE_RECEIPT)
        client.post('/receipts', data=receipt_json, content_type='application/json')
        
        response = client.get('/tree/size')
        data = json.loads(response.data)
        assert data['tree_size'] == 1
