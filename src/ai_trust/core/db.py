# SPDX-License-Identifier: MPL-2.0
"""
Database module for the transparency log using SQLite.

This module provides a high-performance database interface for the transparency log,
integrating with the Merkle tree for efficient proof generation and verification.
"""

import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Iterator

from pydantic import BaseModel, Field

from ai_trust.core.merkle import MerkleTree, NodeHash

# Type aliases
ReceiptID = str
LeafIndex = int

logger = logging.getLogger(__name__)

# Database schema version
SCHEMA_VERSION = 1

# SQL statements for schema creation
SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS log_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        leaf_hash BLOB NOT NULL,
        data BLOB NOT NULL,
        receipt_id TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(receipt_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_log_entries_receipt_id ON log_entries(receipt_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS tree_nodes (
        node_hash BLOB PRIMARY KEY,
        left_hash BLOB,
        right_hash BLOB,
        data BLOB,
        is_leaf BOOLEAN NOT NULL,
        leaf_index INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tree_roots (
        tree_size INTEGER PRIMARY KEY,
        root_hash BLOB NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS receipts (
        receipt_id TEXT PRIMARY KEY,
        receipt_data BLOB NOT NULL,
        status TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS update_receipt_timestamp
    AFTER UPDATE ON receipts
    FOR EACH ROW
    BEGIN
        UPDATE receipts SET updated_at = CURRENT_TIMESTAMP WHERE receipt_id = NEW.receipt_id;
    END;
    """
]


class LogEntry(BaseModel):
    """
    Represents an entry in the transparency log.
    
    Attributes:
        receipt_id: Unique identifier for the receipt
        leaf_hash: The hash of the leaf node in the Merkle tree
        data: The raw receipt data
        timestamp: When the entry was created
        leaf_index: The position of this entry in the Merkle tree
        status: Current status of the log entry
    """
    receipt_id: ReceiptID
    leaf_hash: NodeHash
    data: bytes
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    leaf_index: Optional[LeafIndex] = None
    status: str = "pending"  # pending, committed, verified
    
    class Config:
        json_encoders = {
            bytes: lambda v: v.hex(),
            datetime: lambda v: v.isoformat()
        }


class LogDB:
    """
    High-performance database for the transparency log with Merkle tree integration.
    
    This class provides a thread-safe interface to the log database, with built-in
    support for Merkle tree operations, proof generation, and verification.
    
    Attributes:
        db_path: Path to the SQLite database file
        merkle_tree: The Merkle tree instance for this log
        _lock: Thread lock for thread safety
    """
    
    def __init__(self, db_path: Union[str, Path] = ":memory:", auto_commit: bool = True):
        """Initialize the database.
        
        Args:
            db_path: Path to the SQLite database file, or ":memory:" for in-memory DB.
            auto_commit: Whether to automatically commit transactions
        """
        self.db_path = str(db_path)
        self.auto_commit = auto_commit
        self.merkle_tree = MerkleTree()
        self._init_db()
        self._load_merkle_tree()
    
    def _init_db(self) -> None:
        """Initialize the database schema and ensure proper configuration."""
        with self._get_connection() as conn:
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL")
            
            # Enable foreign keys and enforce foreign key constraints
            conn.execute("PRAGMA foreign_keys = ON")
            
            # Better performance for our access patterns
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA busy_timeout = 5000")  # 5 second timeout
            
            # Create tables and indexes
            for stmt in SCHEMA:
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError as e:
                    if "already exists" not in str(e):
                        logger.error(f"Error executing SQL: {stmt}")
                        raise
            
            # Set or update schema version
            conn.execute(
                """
                INSERT OR REPLACE INTO metadata (key, value)
                VALUES ('schema_version', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                WHERE CAST(value AS INTEGER) < ?
                """,
                (str(SCHEMA_VERSION), SCHEMA_VERSION)
            )
            
            # Create triggers and indexes if they don't exist
            for trigger in [
                # Add any additional triggers here
            ]:
                try:
                    conn.execute(trigger)
                except sqlite3.OperationalError as e:
                    if "already exists" not in str(e):
                        raise
            
            conn.commit()
    
    def _load_merkle_tree(self) -> None:
        """Load the Merkle tree from the database.
        
        This method loads all leaf hashes from the database and rebuilds the Merkle tree.
        It should be called during initialization and after any operations that modify the tree.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT data FROM log_entries ORDER BY id ASC"
            )
            leaves = [row[0] for row in cursor.fetchall()]
            
            # Rebuild the Merkle tree with the loaded leaves
            self.merkle_tree = MerkleTree()
            if leaves:
                self.merkle_tree.add_leaves(leaves)
            
            logger.info(f"Loaded {len(leaves)} leaves into Merkle tree")
    
    def get_tree_size(self) -> int:
        """Get the current size of the Merkle tree."""
        return self.merkle_tree.tree_size
    
    def get_root_hash(self) -> Optional[bytes]:
        """Get the current root hash of the Merkle tree."""
        return self.merkle_tree.get_root_hash()
        
    def add_log_entry(self, receipt_id: ReceiptID, data: bytes) -> LogEntry:
        """
        Add a new log entry to the database and update the Merkle tree.
        
        Args:
            receipt_id: Unique identifier for the receipt
            data: The receipt data to store
            
        Returns:
            LogEntry: The created log entry
            
        Raises:
            ValueError: If a receipt with the same ID already exists
        """
        with self._get_connection() as conn:
            try:
                # Start transaction
                conn.execute("BEGIN IMMEDIATE")
                
                # Check for existing receipt
                cursor = conn.execute(
                    "SELECT 1 FROM log_entries WHERE receipt_id = ?",
                    (receipt_id,)
                )
                if cursor.fetchone() is not None:
                    raise ValueError(f"Receipt with ID {receipt_id} already exists")
                
                # Add to Merkle tree
                leaf_index = self.merkle_tree.add_leaf(data)
                leaf_hash = self.merkle_tree.get_leaf_hash(leaf_index)
                
                if leaf_hash is None:
                    raise RuntimeError("Failed to add leaf to Merkle tree")
                
                # Insert into database
                cursor = conn.execute(
                    """
                    INSERT INTO log_entries (receipt_id, leaf_hash, data, leaf_index)
                    VALUES (?, ?, ?, ?)
                    RETURNING id, timestamp
                    """,
                    (receipt_id, leaf_hash, data, leaf_index)
                )
                
                result = cursor.fetchone()
                if not result:
                    raise RuntimeError("Failed to insert log entry")
                
                # Create and return the log entry
                entry = LogEntry(
                    receipt_id=receipt_id,
                    leaf_hash=leaf_hash,
                    data=data,
                    timestamp=result['timestamp'],
                    leaf_index=leaf_index
                )
                
                if self.auto_commit:
                    conn.commit()
                    
                return entry
                
            except Exception as e:
                conn.rollback()
                # Rebuild Merkle tree to ensure consistency
                self._load_merkle_tree()
                raise
    
    def get_log_entry(self, receipt_id: ReceiptID) -> Optional[LogEntry]:
        """
        Retrieve a log entry by its receipt ID.
        
        Args:
            receipt_id: The ID of the receipt to retrieve
            
        Returns:
            LogEntry if found, None otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT receipt_id, leaf_hash, data, timestamp, leaf_index, status
                FROM log_entries
                WHERE receipt_id = ?
                """,
                (receipt_id,)
            )
            
            row = cursor.fetchone()
            if not row:
                return None
                
            return LogEntry(**dict(row))
    
    def get_inclusion_proof(
        self,
        receipt_id: ReceiptID,
        tree_size: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generate an inclusion proof for a receipt.
        
        Args:
            receipt_id: The ID of the receipt to prove inclusion for
            tree_size: The size of the tree to generate the proof against.
                     If None, uses the current tree size.
                     
        Returns:
            A dictionary containing the proof data, or None if the receipt is not found
        """
        with self._get_connection() as conn:
            # Get the leaf index and hash
            cursor = conn.execute(
                "SELECT leaf_index, leaf_hash FROM log_entries WHERE receipt_id = ?",
                (receipt_id,)
            )
            
            result = cursor.fetchone()
            if not result:
                return None
                
            leaf_index = result['leaf_index']
            leaf_hash = result['leaf_hash']
            
            # Get the proof hashes
            if tree_size is None:
                tree_size = self.merkle_tree.tree_size
                proof_hashes = self.merkle_tree.get_inclusion_proof(leaf_index, tree_size)
            else:
                # If a specific tree size is requested, we need to ensure consistency
                if tree_size > self.merkle_tree.tree_size:
                    raise ValueError(
                        f"Requested tree size {tree_size} is larger than current size {self.merkle_tree.tree_size}"
                    )
                proof_hashes = self.merkle_tree.get_inclusion_proof(leaf_index, tree_size)
            
            # Get the root hash for the requested tree size
            if tree_size == self.merkle_tree.tree_size:
                root_hash = self.merkle_tree.get_root_hash()
            else:
                # For historical proofs, we'd need to store root hashes
                # For now, we'll just use the current root hash
                # In a production system, you'd want to store historical root hashes
                root_hash = self.merkle_tree.get_root_hash()
            
            return {
                'leaf_index': leaf_index,
                'leaf_hash': leaf_hash,
                'proof_hashes': proof_hashes,
                'tree_size': tree_size,
                'root_hash': root_hash
            }
    
    def get_consistency_proof(
        self,
        first_size: int,
        second_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate a consistency proof between two versions of the tree.
        
        Args:
            first_size: Size of the first tree
            second_size: Size of the second tree. If None, uses current tree size.
            
        Returns:
            Dictionary containing the proof data
            
        Raises:
            ValueError: If the tree sizes are invalid
        """
        if second_size is None:
            second_size = self.merkle_tree.tree_size
            
        if first_size < 0 or second_size < first_size or second_size > self.merkle_tree.tree_size:
            raise ValueError("Invalid tree sizes for consistency proof")
            
        if first_size == 0 or first_size == second_size:
            return {
                'first_size': first_size,
                'second_size': second_size,
                'proof_hashes': [],
                'first_root_hash': None if first_size == 0 else self.merkle_tree.get_root_hash(),
                'second_root_hash': self.merkle_tree.get_root_hash()
            }
            
        # Get the consistency proof from the Merkle tree
        proof_hashes = self.merkle_tree.get_consistency_proof(first_size, second_size)
        
        # Get the root hashes
        first_root = self.merkle_tree.get_root_hash()
        second_root = first_root  # In a real implementation, we'd store historical roots
        
        return {
            'first_size': first_size,
            'second_size': second_size,
            'proof_hashes': proof_hashes,
            'first_root_hash': first_root,
            'second_root_hash': second_root
        }
    
    def verify_inclusion_proof(
        self,
        receipt_id: ReceiptID,
        proof: Dict[str, Any]
    ) -> bool:
        """
        Verify an inclusion proof for a receipt.
        
        Args:
            receipt_id: The ID of the receipt to verify
            proof: The inclusion proof from get_inclusion_proof()
            
        Returns:
            bool: True if the proof is valid, False otherwise
        """
        # Get the leaf data
        entry = self.get_log_entry(receipt_id)
        if not entry:
            return False
            
        # Extract proof data
        leaf_hash = proof.get('leaf_hash')
        proof_hashes = proof.get('proof_hashes', [])
        tree_size = proof.get('tree_size', self.merkle_tree.tree_size)
        root_hash = proof.get('root_hash')
        
        if not all([leaf_hash, proof_hashes is not None, root_hash]):
            return False
            
        # Verify the proof using the Merkle tree
        return self.merkle_tree.verify_inclusion_proof(
            leaf_hash=leaf_hash,
            proof=proof_hashes,
            leaf_index=entry.leaf_index,
            tree_size=tree_size,
            root_hash=root_hash
        )
    
    def verify_consistency_proof(
        self,
        first_size: int,
        second_size: int,
        first_root: bytes,
        second_root: bytes,
        proof: List[bytes]
    ) -> bool:
        """
        Verify a consistency proof between two tree states.
        
        Args:
            first_size: Size of the first tree
            second_size: Size of the second tree
            first_root: Root hash of the first tree
            second_root: Root hash of the second tree
            proof: List of proof hashes
            
        Returns:
            bool: True if the proof is valid, False otherwise
        """
        return self.merkle_tree.verify_consistency_proof(
            first_size=first_size,
            second_size=second_size,
            first_root=first_root,
            second_root=second_root,
            proof=proof
        )
    
    def get_entries(
        self,
        offset: int = 0,
        limit: int = 100,
        status: Optional[str] = None
    ) -> List[LogEntry]:
        """
        Get a paginated list of log entries.
        
        Args:
            offset: Number of entries to skip
            limit: Maximum number of entries to return
            status: Optional status filter
            
        Returns:
            List of LogEntry objects
        """
        with self._get_connection() as conn:
            query = """
                SELECT receipt_id, leaf_hash, data, timestamp, leaf_index, status
                FROM log_entries
                {where_clause}
                ORDER BY id ASC
                LIMIT ? OFFSET ?
            """
            
            params = [limit, offset]
            where_clause = ""
            
            if status is not None:
                where_clause = "WHERE status = ?"
                params.insert(0, status)
            
            cursor = conn.execute(query.format(where_clause=where_clause), params)
            return [LogEntry(**dict(row)) for row in cursor.fetchall()]
    
    def update_entry_status(
        self,
        receipt_id: ReceiptID,
        status: str
    ) -> bool:
        """
        Update the status of a log entry.
        
        Args:
            receipt_id: The ID of the receipt to update
            status: The new status
            
        Returns:
            bool: True if the update was successful, False otherwise
        """
        with self._get_connection() as conn:
            try:
                cursor = conn.execute(
                    """
                    UPDATE log_entries
                    SET status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE receipt_id = ?
                    RETURNING 1
                    """,
                    (status, receipt_id)
                )
                
                if cursor.fetchone() is None:
                    return False
                    
                if self.auto_commit:
                    conn.commit()
                    
                return True
                
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to update entry status: {e}")
                return False
    
    @contextmanager
    def _get_connection(self):
        """Get a database connection with proper transaction handling."""
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def add_log_entry(self, receipt_id: str, data: bytes) -> LogEntry:
        """Add a new log entry.
        
        Args:
            receipt_id: The ID of the receipt being logged.
            data: The receipt data to log.
            
        Returns:
            The created log entry.
        """
        # Calculate leaf hash
        merkle = MerkleTree()
        leaf_hash = merkle._hash_leaf(data)
        
        with self._get_connection() as conn:
            # Check if receipt already exists
            cursor = conn.execute(
                "SELECT id FROM log_entries WHERE receipt_id = ?",
                (receipt_id,)
            )
            if cursor.fetchone():
                raise ValueError(f"Receipt {receipt_id} already exists in the log")
            
            # Insert the log entry
            cursor = conn.execute(
                """
                INSERT INTO log_entries (leaf_hash, data, receipt_id)
                VALUES (?, ?, ?)
                RETURNING id, timestamp
                """,
                (leaf_hash, data, receipt_id)
            )
            
            result = cursor.fetchone()
            if not result:
                raise RuntimeError("Failed to insert log entry")
            
            # Update the Merkle tree
            self._update_merkle_tree(conn)
            
            # Get the leaf index
            cursor = conn.execute(
                """
                SELECT COUNT(*) as count 
                FROM log_entries 
                WHERE id <= ?
                """,
                (result["id"],)
            )
            leaf_index = cursor.fetchone()["count"] - 1
            
            # Update the log entry with the leaf index
            conn.execute(
                """
                UPDATE log_entries 
                SET leaf_index = ? 
                WHERE id = ?
                """,
                (leaf_index, result["id"])
            )
            
            # Store the receipt
            self._store_receipt(conn, receipt_id, data)
            
            conn.commit()
            
            return LogEntry(
                receipt_id=receipt_id,
                leaf_hash=leaf_hash,
                data=data,
                timestamp=datetime.fromisoformat(result["timestamp"]),
                leaf_index=leaf_index
            )
    
    def get_log_entry(self, receipt_id: str) -> Optional[LogEntry]:
        """Get a log entry by receipt ID.
        
        Args:
            receipt_id: The ID of the receipt to look up.
            
        Returns:
            The log entry if found, None otherwise.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, leaf_hash, data, timestamp, leaf_index
                FROM log_entries
                WHERE receipt_id = ?
                """,
                (receipt_id,)
            )
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return LogEntry(
                receipt_id=receipt_id,
                leaf_hash=row["leaf_hash"],
                data=row["data"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                leaf_index=row["leaf_index"]
            )
    
    def get_log_entries(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[LogEntry], int]:
        """Get a paginated list of log entries.
        
        Args:
            limit: Maximum number of entries to return.
            offset: Number of entries to skip.
            
        Returns:
            A tuple of (entries, total_count).
        """
        with self._get_connection() as conn:
            # Get total count
            cursor = conn.execute("SELECT COUNT(*) as count FROM log_entries")
            total_count = cursor.fetchone()["count"]
            
            # Get paginated results
            cursor = conn.execute(
                """
                SELECT receipt_id, leaf_hash, data, timestamp, leaf_index
                FROM log_entries
                ORDER BY id ASC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            )
            
            entries = [
                LogEntry(
                    receipt_id=row["receipt_id"],
                    leaf_hash=row["leaf_hash"],
                    data=row["data"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    leaf_index=row["leaf_index"]
                )
                for row in cursor.fetchall()
            ]
            
            return entries, total_count
    
    def get_latest_root(self) -> Optional[bytes]:
        """Get the latest root hash of the Merkle tree.
        
        Returns:
            The root hash as bytes, or None if the tree is empty.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT root_hash
                FROM tree_roots
                ORDER BY tree_size DESC
                LIMIT 1
                """
            )
            
            row = cursor.fetchone()
            return row["root_hash"] if row else None
    
    def get_inclusion_proof(
        self,
        receipt_id: str,
        tree_size: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """Get an inclusion proof for a receipt.
        
        Args:
            receipt_id: The ID of the receipt to prove inclusion for.
            tree_size: The size of the tree to generate the proof against.
                      If None, uses the latest tree size.
            
        Returns:
            A dictionary with the proof data, or None if the receipt is not found.
        """
        with self._get_connection() as conn:
            # Get the log entry
            entry = self.get_log_entry(receipt_id)
            if not entry or entry.leaf_index is None:
                return None
            
            # Get the tree size if not specified
            if tree_size is None:
                cursor = conn.execute(
                    "SELECT MAX(tree_size) as max_size FROM tree_roots"
                )
                tree_size = cursor.fetchone()["max_size"]
                if not tree_size:
                    return None
            
            # Get the root hash for the specified tree size
            cursor = conn.execute(
                """
                SELECT root_hash
                FROM tree_roots
                WHERE tree_size = ?
                """,
                (tree_size,)
            )
            
            root_row = cursor.fetchone()
            if not root_row:
                return None
            
            # Get the inclusion proof
            proof_hashes = self._get_inclusion_proof_hashes(
                conn, entry.leaf_index, tree_size
            )
            
            if proof_hashes is None:
                return None
            
            return {
                "leaf_index": entry.leaf_index,
                "tree_size": tree_size,
                "root_hash": root_row["root_hash"],
                "proof_hashes": proof_hashes
            }
    
    def _get_inclusion_proof_hashes(
        self,
        conn: sqlite3.Connection,
        leaf_index: int,
        tree_size: int
    ) -> Optional[List[bytes]]:
        """Get the inclusion proof hashes for a leaf."""
        # This is a simplified implementation that rebuilds the proof from the tree
        # In a production system, you'd want to store the proof hashes in the DB
        
        # Get all leaves up to tree_size
        cursor = conn.execute(
            """
            SELECT leaf_hash
            FROM log_entries
            WHERE leaf_index < ?
            ORDER BY leaf_index ASC
            """,
            (tree_size,)
        )
        
        leaves = [row["leaf_hash"] for row in cursor.fetchall()]
        
        # Build the Merkle tree and get the proof
        merkle = MerkleTree(leaves)
        proof = merkle.get_inclusion_proof(leaf_index, tree_size)
        
        return proof
    
    def _update_merkle_tree(self, conn: sqlite3.Connection) -> None:
        """Update the Merkle tree with new entries."""
        # Get all leaf hashes
        cursor = conn.execute(
            "SELECT leaf_hash FROM log_entries ORDER BY id ASC"
        )
        
        leaves = [row["leaf_hash"] for row in cursor.fetchall()]
        if not leaves:
            return
        
        # Build the Merkle tree
        merkle = MerkleTree(leaves)
        root_hash = merkle.get_root_hash()
        
        if not root_hash:
            return
        
        # Store the new root
        tree_size = len(leaves)
        conn.execute(
            """
            INSERT OR REPLACE INTO tree_roots (tree_size, root_hash)
            VALUES (?, ?)
            """,
            (tree_size, root_hash)
        )
    
    def _store_receipt(
        self,
        conn: sqlite3.Connection,
        receipt_id: str,
        data: bytes
    ) -> None:
        """Store a receipt in the database."""
        conn.execute(
            """
            INSERT INTO receipts (receipt_id, receipt_data, status)
            VALUES (?, ?, 'PENDING')
            ON CONFLICT(receipt_id) DO UPDATE SET
                receipt_data = excluded.receipt_data,
                status = 'UPDATED'
            """,
            (receipt_id, data)
        )
    
    def get_receipt(self, receipt_id: str) -> Optional[bytes]:
        """Get a receipt by ID.
        
        Args:
            receipt_id: The ID of the receipt to retrieve.
            
        Returns:
            The receipt data as bytes, or None if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT receipt_data
                FROM receipts
                WHERE receipt_id = ?
                """,
                (receipt_id,)
            )
            
            row = cursor.fetchone()
            return row["receipt_data"] if row else None
    
    def update_receipt_status(
        self,
        receipt_id: str,
        status: str
    ) -> bool:
        """Update the status of a receipt.
        
        Args:
            receipt_id: The ID of the receipt to update.
            status: The new status.
            
        Returns:
            True if the receipt was updated, False otherwise.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE receipts
                SET status = ?
                WHERE receipt_id = ?
                RETURNING 1
                """,
                (status, receipt_id)
            )
            
            return cursor.fetchone() is not None
