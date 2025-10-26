# SPDX-License-Identifier: MPL-2.0
"""Transparency Log Service

Implements an append-only Merkle tree for storing and verifying log entries.
"""

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import aiosqlite
from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, HttpUrl

from ai_trust.core.canonicalization import canonicalize
from ai_trust.core.crypto import KeyPair, sign_receipt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
LOG_DATABASE = os.getenv("LOG_DATABASE", "transparency-log.db")
LOG_ID = os.getenv("LOG_ID", "default-log")
LOG_PUBLIC_URL = os.getenv("LOG_PUBLIC_URL", "http://localhost:8000")

# Initialize FastAPI app
app = FastAPI(
    title="AI Trust Transparency Log",
    description="Append-only Merkle tree for cryptographic transparency",
    version="0.1.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection pool
db_pool = None

# In-memory cache for the Merkle tree
class MerkleTree:
    def __init__(self):
        self.leaves = []  # List of leaf hashes
        self.tree = []  # List of lists representing each level of the tree
        self.size = 0

    def add_leaf(self, data: bytes) -> int:
        """Add a leaf to the Merkle tree and return its index."""
        # Hash the data with a prefix to prevent second preimage attacks
        leaf_hash = hashlib.sha256(b"\x00" + data).digest()
        self.leaves.append(leaf_hash)
        self.size += 1
        
        # Rebuild the tree
        self._build_tree()
        return self.size - 1
    
    def get_leaf(self, index: int) -> bytes:
        """Get a leaf hash by index."""
        if index < 0 or index >= self.size:
            raise IndexError("Leaf index out of bounds")
        return self.leaves[index]
    
    def get_root(self) -> bytes:
        """Get the current Merkle root."""
        if not self.tree:
            return b''
        return self.tree[-1][0] if self.tree[-1] else b''
    
    def get_proof(self, index: int) -> List[bytes]:
        """Get the Merkle proof for a leaf."""
        if index < 0 or index >= self.size:
            raise IndexError("Leaf index out of bounds")
        
        if not self.tree:
            return []
        
        proof = []
        for level in self.tree[:-1]:  # Exclude the root level
            # For each level, add the sibling hash to the proof
            if index % 2 == 1:  # Right child
                proof.append(level[index - 1])
            else:  # Left child or no sibling
                if index + 1 < len(level):
                    proof.append(level[index + 1])
                else:
                    proof.append(None)
            index = index // 2
        
        return proof
    
    def _build_tree(self):
        """Build or update the Merkle tree."""
        if not self.leaves:
            self.tree = []
            return
        
        # Reset the tree
        self.tree = [self.leaves.copy()]
        
        # Build each level of the tree
        current_level = self.leaves
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs of nodes
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                
                # Hash the concatenation of the two child hashes with a prefix
                parent = hashlib.sha256(b"\x01" + left + right).digest()
                next_level.append(parent)
            
            self.tree.append(next_level)
            current_level = next_level


# Global Merkle tree instance
merkle_tree = MerkleTree()

# Key pair for signing tree heads
signing_key: Optional[KeyPair] = None

# Models
class LogEntryRequest(BaseModel):
    """Request model for adding a new log entry."""
    data: str  # Base64-encoded data
    

class LogEntryResponse(BaseModel):
    """Response model for log entry operations."""
    leaf_index: int
    tree_size: int
    root_hash: str
    inclusion_proof: List[str]
    timestamp: datetime


class SignedTreeHead(BaseModel):
    """Signed tree head structure."""
    tree_size: int
    root_hash: str
    timestamp: datetime
    log_id: str
    signature: Optional[str] = None


class ConsistencyProof(BaseModel):
    """Consistency proof between two tree states."""
    first: int
    second: int
    proof: List[str]


# Database initialization
async def init_db():
    """Initialize the database."""
    global db_pool
    
    db_pool = await aiosqlite.connect(LOG_DATABASE)
    
    # Enable foreign keys
    await db_pool.execute("PRAGMA foreign_keys = ON")
    
    # Create tables if they don't exist
    await db_pool.executescript("""
    CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data BLOB NOT NULL,
        leaf_hash BLOB NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(leaf_hash)
    );
    
    CREATE TABLE IF NOT EXISTS tree_heads (
        tree_size INTEGER PRIMARY KEY,
        root_hash BLOB NOT NULL,
        signature BLOB,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # Load existing entries into the Merkle tree
    async with db_pool.execute("SELECT leaf_hash FROM entries ORDER BY id") as cursor:
        async for row in cursor:
            merkle_tree.leaves.append(row[0])
            merkle_tree.size += 1
    
    if merkle_tree.leaves:
        merkle_tree._build_tree()
        logger.info(f"Loaded {merkle_tree.size} existing entries into Merkle tree")
    
    # Initialize signing key
    global signing_key
    if os.path.exists("log-key.json"):
        with open("log-key.json", "r") as f:
            key_data = json.load(f)
            signing_key = KeyPair.from_jwk(key_data)
    else:
        signing_key = KeyPair.generate("log-key-1")
        with open("log-key.json", "w") as f:
            json.dump(signing_key.to_jwk(private=True), f, indent=2)
    
    logger.info(f"Initialized log with ID: {LOG_ID}")


# Event handlers
@app.on_event("startup")
async def startup_event():
    """Initialize the application."""
    await init_db()


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources on shutdown."""
    if db_pool:
        await db_pool.close()


# Helper functions
async def add_entry(data: bytes) -> Tuple[int, bytes]:
    """Add an entry to the log and return its index and leaf hash."""
    # Calculate leaf hash (with prefix to prevent second preimage attacks)
    leaf_hash = hashlib.sha256(b"\x00" + data).digest()
    
    # Add to database
    try:
        await db_pool.execute(
            "INSERT INTO entries (data, leaf_hash) VALUES (?, ?)",
            (data, leaf_hash)
        )
        await db_pool.commit()
    except sqlite3.IntegrityError:
        # Entry already exists, find its index
        cursor = await db_pool.execute(
            "SELECT id FROM entries WHERE leaf_hash = ?",
            (leaf_hash,)
        )
        row = await cursor.fetchone()
        return row[0] - 1, leaf_hash
    
    # Add to in-memory tree
    index = merkle_tree.add_leaf(data)
    
    # Sign the new tree head
    await sign_tree_head()
    
    return index, leaf_hash


async def sign_tree_head() -> str:
    """Sign the current tree head and return the signature."""
    if not signing_key:
        raise ValueError("No signing key configured")
    
    tree_head = {
        "tree_size": merkle_tree.size,
        "root_hash": merkle_tree.get_root().hex(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "log_id": LOG_ID,
    }
    
    # Canonicalize the tree head
    canonical_data = canonicalize(tree_head)
    
    # Sign the canonical data
    signature = signing_key.sign(canonical_data)
    
    # Store the signed tree head
    await db_pool.execute(
        """
        INSERT OR REPLACE INTO tree_heads (tree_size, root_hash, signature, timestamp)
        VALUES (?, ?, ?, ?)
        """,
        (
            merkle_tree.size,
            merkle_tree.get_root(),
            signature,
            datetime.now(timezone.utc)
        )
    )
    await db_pool.commit()
    
    return base64.b64encode(signature).decode('ascii')


# API Endpoints
@app.get("/", include_in_schema=False)
async def root():
    """Redirect to the API documentation."""
    return RedirectResponse(url="/docs")


@app.get("/.well-known/ai-trust/keys.json")
async def get_public_keys():
    """Get the log's public keys."""
    if not signing_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No signing key configured"
        )
    
    return {
        "keys": [signing_key.to_jwk()]
    }


@app.post("/v0/entries", response_model=LogEntryResponse)
async def add_log_entry(entry: LogEntryRequest):
    """Add a new entry to the log."""
    try:
        # Decode the base64 data
        data = base64.b64decode(entry.data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid base64 data: {str(e)}"
        )
    
    # Add the entry to the log
    try:
        index, leaf_hash = await add_entry(data)
    except Exception as e:
        logger.exception("Failed to add log entry")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add log entry: {str(e)}"
        )
    
    # Get the inclusion proof
    proof = merkle_tree.get_proof(index)
    
    return {
        "leaf_index": index,
        "tree_size": merkle_tree.size,
        "root_hash": merkle_tree.get_root().hex(),
        "inclusion_proof": [h.hex() for h in proof if h is not None],
        "timestamp": datetime.now(timezone.utc)
    }


@app.get("/v0/entries/{index}", response_model=Dict)
async def get_log_entry(index: int):
    """Get a log entry by index."""
    if index < 0 or index >= merkle_tree.size:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entry with index {index} not found"
        )
    
    # Get the entry from the database
    cursor = await db_pool.execute(
        "SELECT data FROM entries WHERE id = ?",
        (index + 1,)  # SQLite uses 1-based indexing
    )
    row = await cursor.fetchone()
    
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entry with index {index} not found in database"
        )
    
    return {
        "leaf_index": index,
        "data": base64.b64encode(row[0]).decode('ascii'),
        "leaf_hash": merkle_tree.get_leaf(index).hex()
    }


@app.get("/v0/roots/latest", response_model=SignedTreeHead)
async def get_latest_signed_tree_head():
    """Get the latest signed tree head."""
    if not signing_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No signing key configured"
        )
    
    if merkle_tree.size == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No entries in the log"
        )
    
    # Get the latest signature from the database
    cursor = await db_pool.execute(
        "SELECT signature FROM tree_heads ORDER BY tree_size DESC LIMIT 1"
    )
    row = await cursor.fetchone()
    
    return {
        "tree_size": merkle_tree.size,
        "root_hash": merkle_tree.get_root().hex(),
        "timestamp": datetime.now(timezone.utc),
        "log_id": LOG_ID,
        "signature": base64.b64encode(row[0]).decode('ascii') if row else None
    }


@app.get("/v0/proofs/inclusion", response_model=Dict)
async def get_inclusion_proof(
    leaf_hash: str = Query(..., description="The leaf hash to prove inclusion for"),
    tree_size: int = Query(..., description="The tree size to prove inclusion at")
):
    """Get an inclusion proof for a leaf in the Merkle tree."""
    try:
        # Find the leaf index
        cursor = await db_pool.execute(
            "SELECT id FROM entries WHERE hex(leaf_hash) = ?",
            (leaf_hash,)
        )
        row = await cursor.fetchone()
        
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Leaf hash {leaf_hash} not found in the log"
            )
        
        leaf_index = row[0] - 1  # Convert to 0-based index
        
        # Get the inclusion proof
        proof = merkle_tree.get_proof(leaf_index)
        
        return {
            "leaf_index": leaf_index,
            "tree_size": merkle_tree.size,
            "leaf_hash": leaf_hash,
            "inclusion_path": [h.hex() for h in proof if h is not None]
        }
    except Exception as e:
        logger.exception("Failed to generate inclusion proof")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate inclusion proof: {str(e)}"
        )


@app.get("/v0/proofs/consistency", response_model=ConsistencyProof)
async def get_consistency_proof(
    first: int = Query(..., ge=1, description="First tree size"),
    second: int = Query(..., ge=1, description="Second tree size")
):
    """Get a consistency proof between two tree states."""
    if first >= second:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="First tree size must be less than second tree size"
        )
    
    # For now, we'll return a simple proof since we're rebuilding the tree on startup
    # In a production system, you'd want to store and retrieve consistency proofs
    return {
        "first": first,
        "second": second,
        "proof": []  # This would contain the actual consistency proof
    }


# Error handlers
@app.exception_handler(Exception)
async def handle_exception(request: Request, exc: Exception):
    """Handle uncaught exceptions."""
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "ai_trust.services.log.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
