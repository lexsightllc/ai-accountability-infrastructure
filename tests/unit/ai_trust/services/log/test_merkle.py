"""
"""Unit tests for the Merkle tree implementation."""

import hashlib

import pytest

from ai_trust.core.merkle import INTERNAL_NODE_PREFIX, LEAF_NODE_PREFIX, MerkleTree


def hash_leaf(data: bytes) -> bytes:
    """Helper function to hash a leaf node."""
    return hashlib.sha256(LEAF_NODE_PREFIX + data).digest()


def hash_internal(left: bytes, right: bytes) -> bytes:
    """Helper function to hash an internal node."""
    return hashlib.sha256(INTERNAL_NODE_PREFIX + left + right).digest()


class TestMerkleTree:
    """Test cases for the MerkleTree class."""

    def test_empty_tree(self):
        """Test that an empty tree has no root."""
        tree = MerkleTree()
        assert tree.get_root_hash() is None
        assert tree.tree_size == 0

    def test_single_leaf(self):
        """Test a tree with a single leaf."""
        data = b"test data"
        tree = MerkleTree([data])
        expected_hash = hash_leaf(data)
        assert tree.get_root_hash() == expected_hash
        assert tree.tree_size == 1

    def test_two_leaves(self):
        """Test a tree with two leaves."""
        data1 = b"test data 1"
        data2 = b"test data 2"
        tree = MerkleTree([data1, data2])
        
        # Calculate expected hash
        hash1 = hash_leaf(data1)
        hash2 = hash_leaf(data2)
        expected_hash = hash_internal(hash1, hash2)
        
        assert tree.get_root_hash() == expected_hash
        assert tree.tree_size == 2

    def test_three_leaves(self):
        """Test a tree with three leaves (odd number)."""
        data1 = b"test data 1"
        data2 = b"test data 2"
        data3 = b"test data 3"
        tree = MerkleTree([data1, data2, data3])
        
        # Calculate expected hash
        hash1 = hash_leaf(data1)
        hash2 = hash_leaf(data2)
        hash3 = hash_leaf(data3)
        hash12 = hash_internal(hash1, hash2)
        hash33 = hash_internal(hash3, hash3)  # Duplicate the last hash for odd number of nodes
        expected_hash = hash_internal(hash12, hash33)
        
        assert tree.get_root_hash() == expected_hash
        assert tree.tree_size == 3

    def test_inclusion_proof_simple(self):
        """Test inclusion proof for a simple tree with 4 leaves."""
        data = [f"data {i}".encode() for i in range(4)]
        tree = MerkleTree(data)
        
        # Get inclusion proof for each leaf
        for i in range(4):
            proof = tree.get_inclusion_proof(i)
            assert proof is not None
            
            # Verify the proof
            leaf_hash = hash_leaf(data[i])
            assert tree.verify_inclusion_proof(
                leaf_hash=leaf_hash,
                proof=proof,
                leaf_index=i,
                tree_size=4,
                root_hash=tree.get_root_hash()
            )

    def test_inclusion_proof_complex(self):
        """Test inclusion proof for a larger tree."""
        data = [f"data {i}".encode() for i in range(10)]
        tree = MerkleTree(data)
        
        # Test inclusion proof for leaf at index 7
        proof = tree.get_inclusion_proof(7)
        assert proof is not None
        
        # Verify the proof
        leaf_hash = hash_leaf(data[7])
        assert tree.verify_inclusion_proof(
            leaf_hash=leaf_hash,
            proof=proof,
            leaf_index=7,
            tree_size=10,
            root_hash=tree.get_root_hash()
        )

    def test_invalid_inclusion_proof(self):
        """Test that invalid inclusion proofs are rejected."""
        data = [f"data {i}".encode() for i in range(4)]
        tree = MerkleTree(data)
        
        # Get a valid proof
        proof = tree.get_inclusion_proof(0)
        assert proof is not None
        
        # Tamper with the proof
        proof[0] = b"\x00" * 32
        
        # Verification should fail
        leaf_hash = hash_leaf(data[0])
        assert not tree.verify_inclusion_proof(
            leaf_hash=leaf_hash,
            proof=proof,
            leaf_index=0,
            tree_size=4,
            root_hash=tree.get_root_hash()
        )

    def test_consistency_proof(self):
        """Test consistency proof between tree states."""
        # Create a tree with 4 leaves
        data1 = [f"data {i}".encode() for i in range(4)]
        tree1 = MerkleTree(data1)
        
        # Add more leaves to create a larger tree
        data2 = data1 + [f"data {i}".encode() for i in range(4, 8)]
        tree2 = MerkleTree(data2)
        
        # Get consistency proof
        proof = tree2.get_consistency_proof(4, 8)
        assert proof is not None
        
        # Verify the consistency proof
        assert MerkleTree.verify_consistency_proof(
            first_root=tree1.get_root_hash(),
            second_root=tree2.get_root_hash(),
            first_size=4,
            second_size=8,
            proof=proof
        )

    def test_invalid_consistency_proof(self):
        """Test that invalid consistency proofs are rejected."""
        # Create two unrelated trees
        data1 = [f"data {i}".encode() for i in range(4)]
        tree1 = MerkleTree(data1)
        
        data2 = [f"different {i}".encode() for i in range(8)]
        tree2 = MerkleTree(data2)
        
        # Get a valid proof from a different tree
        proof = tree2.get_consistency_proof(4, 8)
        
        # Verification should fail because the trees are unrelated
        assert not MerkleTree.verify_consistency_proof(
            first_root=tree1.get_root_hash(),
            second_root=tree2.get_root_hash(),
            first_size=4,
            second_size=8,
            proof=proof or []
        )

    def test_add_leaves(self):
        """Test adding leaves incrementally."""
        tree = MerkleTree()
        data = [f"data {i}".encode() for i in range(5)]
        
        # Add leaves one by one
        for i, d in enumerate(data):
            index = tree.add_leaf(d)
            assert index == i
            assert tree.tree_size == i + 1
        
        # The final tree should be the same as creating it all at once
        expected_tree = MerkleTree(data)
        assert tree.get_root_hash() == expected_tree.get_root_hash()

    def test_get_leaf_hash(self):
        """Test getting the hash of a leaf by index."""
        data = [f"data {i}".encode() for i in range(5)]
        tree = MerkleTree(data)
        
        for i, d in enumerate(data):
            assert tree.get_leaf_hash(i) == hash_leaf(d)
        
        # Test out of bounds
        assert tree.get_leaf_hash(-1) is None
        assert tree.get_leaf_hash(5) is None
