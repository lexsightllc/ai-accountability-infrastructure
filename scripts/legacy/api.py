"""
Transparency Log API

A FastAPI-based service for submitting and verifying AI Trust receipts.
This implements a basic transparency log with Merkle tree verification.
"""

import os
import json
import base64
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Generator, Tuple

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

from ai_trust.services.verifier import ReceiptVerifier, VerificationResult

# Constants
DEFAULT_DB_PATH = "data/transparency_log.db"
DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_data TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    merkle_proof TEXT
);

CREATE TABLE IF NOT EXISTS tree_nodes (
    level INTEGER NOT NULL,
    node_index INTEGER NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY (level, node_index)
);

CREATE TABLE IF NOT EXISTS tree_state (
    id INTEGER PRIMARY KEY,
    root_hash TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO tree_state (id, root_hash, size) VALUES (1, '', 0);
"""

# Pydantic models
class ReceiptSubmission(BaseModel):
    """Model for receipt submission."""
    receipt: Dict[str, Any]
    verify_signature: bool = True

class ReceiptResponse(BaseModel):
    """Response model for receipt submission."""
    receipt_id: int
    receipt_hash: str
    timestamp: str
    merkle_root: str
    tree_size: int

class ReceiptVerificationResponse(BaseModel):
    """Response model for receipt verification."""
    is_valid: bool
    receipt_id: Optional[int] = None
    receipt_hash: Optional[str] = None
    merkle_proof: Optional[List[str]] = None
    merkle_root: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class TreeStateResponse(BaseModel):
    """Response model for tree state."""
    root_hash: str
    size: int
    last_updated: str

# Initialize FastAPI app
app = FastAPI(
    title="AI Trust Transparency Log",
    description="API for submitting and verifying AI trust receipts",
    version="1.0.0"
)

def get_db():
    """Get a database connection."""
    db_path = os.getenv("DB_PATH", DEFAULT_DB_PATH)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # Initialize database schema if needed
    conn.executescript(DB_SCHEMA)
    conn.commit()
    
    try:
        yield conn
    finally:
        conn.close()

def calculate_hash(data: str) -> str:
    """Calculate SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

class MerkleTree:
    """A simple Merkle tree implementation for the transparency log."""
    
    def __init__(self, db_conn):
        self.db = db_conn
        self._ensure_tree_state()
    
    def _ensure_tree_state(self):
        """Ensure the tree state is initialized."""
        cursor = self.db.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM tree_state")
        if cursor.fetchone()['count'] == 0:
            cursor.execute(
                "INSERT INTO tree_state (id, root_hash, size) VALUES (1, '', 0)"
            )
            self.db.commit()
    
    def get_state(self) -> Dict[str, Any]:
        """Get the current state of the Merkle tree."""
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM tree_state WHERE id = 1")
        return dict(cursor.fetchone())
    
    def add_receipt(self, receipt_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a receipt to the Merkle tree and update the tree."""
        # Serialize receipt data
        receipt_json = json.dumps(receipt_data, sort_keys=True)
        receipt_hash = calculate_hash(receipt_json)
        
        # Check for duplicates
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM receipts WHERE receipt_hash = ?", (receipt_hash,))
        if cursor.fetchone() is not None:
            raise ValueError("Receipt already exists in the log")
        
        # Insert receipt
        cursor.execute(
            """
            INSERT INTO receipts (receipt_data, receipt_hash, timestamp)
            VALUES (?, ?, ?)
            """,
            (receipt_json, receipt_hash, datetime.now(timezone.utc).isoformat())
        )
        receipt_id = cursor.lastrowid
        
        # Update Merkle tree
        self._update_merkle_tree()
        
        # Get updated state
        state = self.get_state()
        
        return {
            "receipt_id": receipt_id,
            "receipt_hash": receipt_hash,
            "merkle_root": state["root_hash"],
            "tree_size": state["size"]
        }
    
    def _update_merkle_tree(self):
        """Update the Merkle tree with the latest receipts."""
        cursor = self.db.cursor()
        
        # Get current state
        state = self.get_state()
        current_size = state["size"]
        
        # Get all receipts not yet in the tree
        cursor.execute(
            "SELECT id, receipt_hash FROM receipts ORDER BY id LIMIT ? OFFSET ?",
            (1000, current_size)  # Process in batches of 1000
        )
        new_receipts = cursor.fetchall()
        
        if not new_receipts:
            return  # No new receipts to add
        
        # Initialize leaves
        leaves = [row["receipt_hash"] for row in new_receipts]
        
        # Build the Merkle tree
        level = 0
        nodes = {level: leaves}
        
        while len(nodes[level]) > 1:
            next_level = []
            for i in range(0, len(nodes[level]), 2):
                left = nodes[level][i]
                right = nodes[level][i + 1] if i + 1 < len(nodes[level]) else left
                combined = left + right
                next_level.append(calculate_hash(combined))
            
            level += 1
            nodes[level] = next_level
        
        # Update the database with the new nodes
        with self.db:  # Use a transaction
            # Save all nodes
            for lvl, node_hashes in nodes.items():
                for idx, node_hash in enumerate(node_hashes):
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO tree_nodes (level, node_index, hash)
                        VALUES (?, ?, ?)
                        """,
                        (lvl, idx, node_hash)
                    )
            
            # Update receipts with their Merkle proofs
            for i, receipt in enumerate(new_receipts):
                proof = self._generate_proof(receipt["receipt_hash"])
                cursor.execute(
                    "UPDATE receipts SET merkle_proof = ? WHERE id = ?",
                    (json.dumps(proof), receipt["id"])
                )
            
            # Update tree state
            new_size = current_size + len(new_receipts)
            new_root = nodes[level][0] if nodes[level] else ""
            
            cursor.execute(
                """
                UPDATE tree_state 
                SET root_hash = ?, size = ?, last_updated = ?
                WHERE id = 1
                """,
                (new_root, new_size, datetime.now(timezone.utc).isoformat())
            )
    
    def _generate_proof(self, leaf_hash: str) -> List[str]:
        """Generate a Merkle proof for a leaf node."""
        cursor = self.db.cursor()
        proof = []
        
        # Start with the leaf node
        cursor.execute(
            "SELECT level, node_index FROM tree_nodes WHERE hash = ? AND level = 0",
            (leaf_hash,)
        )
        node = cursor.fetchone()
        
        if not node:
            return []
        
        level, idx = node["level"], node["node_index"]
        
        # Traverse up the tree
        while level > 0:
            # Get the sibling node
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            
            cursor.execute(
                "SELECT hash FROM tree_nodes WHERE level = ? AND node_index = ?",
                (level, sibling_idx)
            )
            sibling = cursor.fetchone()
            
            if sibling:
                proof.append(sibling["hash"])
            
            # Move up to the parent level
            level -= 1
            idx = idx // 2
        
        return proof
    
    def verify_receipt(self, receipt_hash: str) -> Dict[str, Any]:
        """Verify that a receipt is included in the Merkle tree."""
        cursor = self.db.cursor()
        
        # Get the receipt
        cursor.execute(
            """
            SELECT id, receipt_hash, merkle_proof, timestamp 
            FROM receipts 
            WHERE receipt_hash = ?
            """,
            (receipt_hash,)
        )
        receipt = cursor.fetchone()
        
        if not receipt:
            return {
                "is_valid": False,
                "error": "Receipt not found"
            }
        
        # Get the Merkle proof
        proof = json.loads(receipt["merkle_pro0f"]) if receipt["merkle_proof"] else []
        
        # Get the current root hash
        state = self.get_state()
        
        # Reconstruct the Merkle root
        current_hash = receipt["receipt_hash"]
        
        for sibling_hash in proof:
            # Determine the order of concatenation based on the hash comparison
            if current_hash < sibling_hash:
                current_hash = calculate_hash(current_hash + sibling_hash)
            else:
                current_hash = calculate_hash(sibling_hash + current_hash)
        
        is_valid = current_hash == state["root_hash"]
        
        return {
            "is_valid": is_valid,
            "receipt_id": receipt["id"],
            "receipt_hash": receipt["receipt_hash"],
            "merkle_proof": proof,
            "merkle_root": state["root_hash"],
            "timestamp": receipt["timestamp"]
        }

# API endpoints
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "AI Trust Transparency Log",
        "version": "1.0.0",
        "documentation": "/docs"
    }

@app.post("/receipts", response_model=ReceiptResponse)
async def submit_receipt(
    submission: ReceiptSubmission,
    db: sqlite3.Connection = Depends(get_db)
):
    """Submit a new receipt to the transparency log."""
    # Verify the receipt if requested
    if submission.verify_signature:
        verifier = ReceiptVerifier()
        result = verifier.verify_receipt(submission.receipt)
        
        if not result.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Receipt verification failed",
                    "errors": result.errors,
                    "warnings": result.warnings
                }
            )
    
    # Add to Merkle tree
    try:
        merkle = MerkleTree(db)
        result = merkle.add_receipt(submission.receipt)
        db.commit()
        
        return {
            "receipt_id": result["receipt_id"],
            "receipt_hash": result["receipt_hash"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "merkle_root": result["merkle_root"],
            "tree_size": result["tree_size"]
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": str(e)}
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": f"Failed to process receipt: {str(e)}"}
        )

@app.get("/receipts/{receipt_hash}", response_model=ReceiptVerificationResponse)
async def verify_receipt(
    receipt_hash: str,
    db: sqlite3.Connection = Depends(get_db)
):
    """Verify that a receipt is included in the transparency log."""
    merkle = MerkleTree(db)
    result = merkle.verify_receipt(receipt_hash)
    
    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": result["error"]}
        )
    
    return {
        "is_valid": result["is_valid"],
        "receipt_id": result.get("receipt_id"),
        "receipt_hash": result.get("receipt_hash"),
        "merkle_proof": result.get("merkle_proof"),
        "merkle_root": result.get("merkle_root")
    }

@app.get("/tree/state", response_model=TreeStateResponse)
async def get_tree_state(db: sqlite3.Connection = Depends(get_db)):
    """Get the current state of the Merkle tree."""
    merkle = MerkleTree(db)
    state = merkle.get_state()
    
    return {
        "root_hash": state["root_hash"],
        "size": state["size"],
        "last_updated": state["last_updated"]
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": f"Internal server error: {str(exc)}"}
    )

if __name__ == "__main__":
    import uvicorn
    
    # Create data directory if it doesn't exist
    os.makedirs("data", exist_ok=True)
    
    # Run the API server
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
