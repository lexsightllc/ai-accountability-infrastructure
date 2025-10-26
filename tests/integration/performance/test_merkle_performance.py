# SPDX-License-Identifier: MPL-2.0
"""
Performance tests for the Merkle tree implementation.

These tests verify that the Merkle tree operations scale efficiently
with increasing numbers of leaves.
"""

import cProfile
import json
import os
import pstats
import tempfile
import time

import pytest

pytest.importorskip("pytest_benchmark")

from ai_trust.core.merkle import MerkleTree
from ai_trust.core.db import LogDB

class TestMerkleTreePerformance:
    """Performance tests for the Merkle tree implementation."""
    
    @pytest.mark.parametrize("num_leaves", [10, 100, 1000, 10000])
    def test_merkle_tree_construction(self, benchmark, num_leaves):
        """Test the performance of Merkle tree construction."""
        # Generate test data
        test_data = [f"leaf-{i}".encode() for i in range(num_leaves)]
        
        # Benchmark tree construction
        def _construct_tree():
            tree = MerkleTree()
            for data in test_data:
                tree.add_leaf(data)
            return tree
            
        tree = benchmark(_construct_tree)
        
        # Verify the tree was constructed correctly
        assert tree.tree_size == num_leaves
        assert tree.root_hash is not None
    
    @pytest.mark.parametrize("num_leaves", [10, 100, 1000])
    def test_merkle_tree_inclusion_proofs(self, benchmark, num_leaves):
        """Test the performance of inclusion proof generation and verification."""
        # Create a tree with test data
        tree = MerkleTree()
        test_data = [f"leaf-{i}".encode() for i in range(num_leaves)]
        
        for data in test_data:
            tree.add_leaf(data)
        
        # Benchmark inclusion proof generation
        def _generate_proofs():
            return [tree.get_inclusion_proof(i, num_leaves) for i in range(num_leaves)]
            
        proofs = benchmark(_generate_proofs)
        
        # Verify all proofs are valid
        for i, proof in enumerate(proofs):
            leaf_hash = tree._hash_leaf(test_data[i])
            assert tree.verify_inclusion_proof(
                leaf_hash=leaf_hash,
                proof=proof,
                leaf_index=i,
                tree_size=num_leaves,
                root_hash=tree.root_hash
            )
    
    @pytest.mark.parametrize("initial_size,delta", [(1000, 100), (5000, 500)])
    def test_merkle_tree_incremental_updates(self, benchmark, initial_size, delta):
        """Test performance of incremental updates to the Merkle tree."""
        # Create initial tree
        tree = MerkleTree()
        initial_data = [f"initial-{i}".encode() for i in range(initial_size)]
        
        for data in initial_data:
            tree.add_leaf(data)
        
        # Benchmark adding more leaves
        def _add_leaves():
            for i in range(delta):
                tree.add_leaf(f"new-leaf-{i}".encode())
        
        benchmark(_add_leaves)
        
        # Verify the final tree state
        assert tree.tree_size == initial_size + delta
        assert tree.root_hash is not None
    
    def test_database_performance(self, benchmark):
        """Test performance of database operations with Merkle tree integration."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            try:
                # Initialize database
                db = LogDB(temp_db.name)
                
                # Benchmark adding entries
                def _add_entries():
                    for i in range(1000):
                        receipt_id = f"perf-test-{i}"
                        data = json.dumps({
                            "receipt_id": receipt_id,
                            "data": {"test": "value" * 10}  # Larger payload
                        }).encode()
                        db.add_log_entry(receipt_id, data)
                
                benchmark(_add_entries)
                
                # Verify the final state
                assert db.get_tree_size() >= 1000
                
            finally:
                temp_db.close()
                os.unlink(temp_db.name)
    
    def test_profile_merkle_tree_operations(self):
        """Profile Merkle tree operations to identify bottlenecks."""
        profiler = cProfile.Profile()
        profiler.enable()
        
        try:
            # Test with a moderate number of leaves
            tree = MerkleTree()
            for i in range(1000):
                tree.add_leaf(f"leaf-{i}".encode())
                
                # Periodically generate proofs
                if i % 100 == 0 and i > 0:
                    for j in range(0, i, 100):
                        proof = tree.get_inclusion_proof(j, i+1)
                        leaf_hash = tree._hash_leaf(f"leaf-{j}".encode())
                        assert tree.verify_inclusion_proof(
                            leaf_hash=leaf_hash,
                            proof=proof,
                            leaf_index=j,
                            tree_size=i+1,
                            root_hash=tree.root_hash
                        )
        finally:
            profiler.disable()
            
            # Save profile results
            stats = pstats.Stats(profiler)
            stats.sort_stats('cumtime')
            
            # Print the 20 most time-consuming functions
            print("\n=== Profiling Results (top 20 by cumulative time) ===")
            stats.print_stats(20)
            
            # Save detailed profile to file
            profile_file = "merkle_performance.prof"
            stats.dump_stats(profile_file)
            print(f"\nDetailed profile saved to: {profile_file}")
            print("Analyze with: snakeviz", profile_file)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
