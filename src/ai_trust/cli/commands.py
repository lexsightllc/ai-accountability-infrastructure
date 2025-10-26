# SPDX-License-Identifier: MPL-2.0
"""
CLI command implementations for AI Trust.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click
from pydantic import AnyHttpUrl, HttpUrl, ValidationError

from ai_trust.core.canonicalization import canonicalize
from ai_trust.core.crypto import KeyPair, KeyStore, hash_sha256
from ai_trust.core.db import LogDB
from ai_trust.core.merkle import MerkleTree
from ai_trust.core.models import (
    ExecutionID,
    InputCommitment,
    LogEntry as LogEntryModel,
    ModelInfo,
    OutputCommitment,
    Receipt,
    ReceiptVersion,
    Signature,
    WitnessSignature,
)
from ai_trust.core.receipt import Receipt as EnhancedReceipt

# Global key store
key_store = KeyStore()

# Helper functions
def load_receipt(file_path: str) -> Receipt:
    """Load a receipt from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return Receipt(**data)
    except (json.JSONDecodeError, ValidationError) as e:
        click.echo(f"Error loading receipt: {e}", err=True)
        sys.exit(1)

def save_receipt(receipt: Receipt, file_path: str) -> None:
    """Save a receipt to a JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(receipt.model_dump(), f, indent=2, default=str)
        click.echo(f"Receipt saved to {file_path}")
    except (IOError, TypeError) as e:
        click.echo(f"Error saving receipt: {e}", err=True)
        sys.exit(1)

def load_keypair(key_file: str) -> KeyPair:
    """Load a key pair from a JSON file."""
    try:
        with open(key_file, 'r') as f:
            key_data = json.load(f)
        return KeyPair.model_validate(key_data)
    except (json.JSONDecodeError, ValidationError) as e:
        click.echo(f"Error loading key pair: {e}", err=True)
        sys.exit(1)

def save_keypair(key_pair: KeyPair, key_file: str) -> None:
    """Save a key pair to a JSON file."""
    try:
        with open(key_file, 'w') as f:
            json.dump(key_pair.model_dump(), f, indent=2)
        click.echo(f"Key pair saved to {key_file}")
    except (IOError, TypeError) as e:
        click.echo(f"Error saving key pair: {e}", err=True)
        sys.exit(1)

def init_log_db(db_path: str = "trust_log.db") -> LogDB:
    """Initialize the log database."""
    try:
        return LogDB(db_path)
    except Exception as e:
        click.echo(f"Error initializing log database: {e}", err=True)
        sys.exit(1)

# Key management commands
def generate_keypair(output: str, kid: Optional[str] = None) -> None:
    """Generate a new Ed25519 key pair.
    
    Args:
        output: Path to save the key pair.
        kid: Optional key ID. If not provided, a UUID will be generated.
    """
    try:
        key_pair = KeyPair.generate(kid or f"key-{os.urandom(8).hex()}")
        save_keypair(key_pair, output)
    except Exception as e:
        click.echo(f"Error generating key pair: {e}", err=True)
        sys.exit(1)

def show_key(key_file: str) -> None:
    """Show information about a key pair.
    
    Args:
        key_file: Path to the key file.
    """
    try:
        key_pair = load_keypair(key_file)
        click.echo(f"Key ID: {key_pair.kid}")
        click.echo(f"Algorithm: {key_pair.algorithm}")
        click.echo(f"Public Key: {key_pair.public_key.hex()}")
        click.echo(f"Created At: {key_pair.created_at}")
        
        if key_pair.not_before:
            click.echo(f"Valid From: {key_pair.not_before}")
        if key_pair.not_after:
            click.echo(f"Valid Until: {key_pair.not_after}")
            
        if key_pair.private_key:
            click.echo("Private Key: [PRESENT]")
        else:
            click.echo("Private Key: [NOT PRESENT]")
            
        if key_pair.metadata:
            click.echo("\nMetadata:")
            for k, v in key_pair.metadata.items():
                click.echo(f"  {k}: {v}")
    except Exception as e:
        click.echo(f"Error showing key: {e}", err=True)
        sys.exit(1)

# Receipt commands
def create_receipt(
    key_file: str,
    output: str,
    issuer: str,
    model_name: str,
    body_sha256: str,
    content_type: Optional[str] = None,
    model_version: Optional[str] = None,
    model_commit: Optional[str] = None,
    inputs: Optional[List[Dict[str, str]]] = None,
    policy: Optional[Dict[str, Any]] = None,
    extensions: Optional[Dict[str, Any]] = None,
) -> None:
    """Create and sign a new receipt.
    
    Args:
        key_file: Path to the key file for signing.
        output: Path to save the signed receipt.
        issuer: Issuer URL (must be HTTPS).
        model_name: Name of the AI model.
        body_sha256: SHA-256 hash of the response body.
        content_type: Optional content type of the response.
        model_version: Optional model version.
        model_commit: Optional model commit hash.
        inputs: Optional list of input commitments.
        policy: Optional policy information.
        extensions: Optional extension fields.
    """
    try:
        # Load the key pair
        key_pair = load_keypair(key_file)
        
        # Create a new receipt
        receipt = EnhancedReceipt.create(
            execution_id=f"exec-{os.urandom(8).hex()}",
            issuer=issuer,
            model_name=model_name,
            body_sha256=body_sha256,
            content_type=content_type,
            model_version=model_version,
            model_commit=model_commit,
            inputs=inputs,
            policy=policy,
            extensions=extensions
        )
        
        # Sign the receipt
        signed_receipt = receipt.sign(key_pair)
        
        # Save the signed receipt
        save_receipt(signed_receipt, output)
        
    except Exception as e:
        click.echo(f"Error creating receipt: {e}", err=True)
        sys.exit(1)

def verify_receipt(
    receipt_file: str,
    key_file: Optional[str] = None,
    public_key: Optional[str] = None,
) -> bool:
    """Verify a receipt's signature and contents.
    
    Args:
        receipt_file: Path to the receipt file.
        key_file: Path to the key file containing the public key.
        public_key: Public key as a hex string.
        
    Returns:
        True if the receipt is valid, False otherwise.
    """
    try:
        # Load the receipt
        receipt_data = load_receipt(receipt_file)
        receipt = EnhancedReceipt.model_validate(receipt_data.model_dump())
        
        # Get the public key
        pub_key_bytes = None
        if key_file:
            key_pair = load_keypair(key_file)
            pub_key_bytes = key_pair.public_key
        elif public_key:
            pub_key_bytes = bytes.fromhex(public_key)
        else:
            click.echo("Error: Either key_file or public_key must be provided", err=True)
            return False
        
        # Verify the signature
        if not receipt.verify_signature(pub_key_bytes):
            click.echo("Error: Invalid signature", err=True)
            return False
        
        # Verify the receipt contents
        try:
            receipt.model_validate(receipt.model_dump())
        except ValidationError as e:
            click.echo(f"Error: Invalid receipt: {e}", err=True)
            return False
        
        click.echo("Receipt is valid")
        return True
        
    except Exception as e:
        click.echo(f"Error verifying receipt: {e}", err=True)
        return False

# Log commands
def submit_to_log(
    db_path: str,
    receipt_file: str,
    output: Optional[str] = None
) -> None:
    """Submit a receipt to the transparency log.
    
    Args:
        db_path: Path to the log database.
        receipt_file: Path to the receipt file.
        output: Optional path to save the updated receipt.
    """
    try:
        # Load the receipt
        receipt_data = load_receipt(receipt_file)
        receipt = EnhancedReceipt.model_validate(receipt_data.model_dump())
        
        # Initialize the log database
        db = init_log_db(db_path)
        
        # Add the receipt to the log
        entry = db.add_log_entry(
            receipt_id=receipt.execution_id,
            data=receipt.model_dump_json().encode('utf-8')
        )
        
        if not entry:
            click.echo("Error: Failed to add receipt to log", err=True)
            sys.exit(1)
        
        # Update the receipt with the log entry
        receipt.add_log_entry(
            log_id=db_path,
            leaf_index=entry.leaf_index or 0,
            tree_size=db.tree_size or 1,
            root_hash=db.get_latest_root() or b''
        )
        
        # Save the updated receipt
        if output:
            save_receipt(receipt, output)
        else:
            click.echo(json.dumps(receipt.model_dump(), indent=2, default=str))
            
    except Exception as e:
        click.echo(f"Error submitting to log: {e}", err=True)
        sys.exit(1)

def verify_inclusion(
    db_path: str,
    receipt_file: str
) -> bool:
    """Verify that a receipt is included in the log.
    
    Args:
        db_path: Path to the log database.
        receipt_file: Path to the receipt file.
        
    Returns:
        True if the receipt is included in the log, False otherwise.
    """
    try:
        # Load the receipt
        receipt_data = load_receipt(receipt_file)
        receipt = EnhancedReceipt.model_validate(receipt_data.model_dump())
        
        # Initialize the log database
        db = init_log_db(db_path)
        
        # Get the log entry
        entry = db.get_log_entry(receipt.execution_id)
        if not entry:
            click.echo("Error: Receipt not found in log", err=True)
            return False
        
        # Get the inclusion proof
        proof = db.get_inclusion_proof(receipt.execution_id)
        if not proof:
            click.echo("Error: Could not generate inclusion proof", err=True)
            return False
        
        # Verify the proof
        merkle = MerkleTree()
        leaf_hash = merkle._hash_leaf(receipt.model_dump_json().encode('utf-8'))
        
        is_valid = merkle.verify_inclusion_proof(
            leaf_hash=leaf_hash,
            proof=[bytes.fromhex(h.hex()) for h in proof['proof_hashes']],
            leaf_index=proof['leaf_index'],
            tree_size=proof['tree_size'],
            root_hash=proof['root_hash']
        )
        
        if is_valid:
            click.echo(f"Receipt is included in log at index {proof['leaf_index']}")
            click.echo(f"Root hash: {proof['root_hash'].hex()}")
            click.echo(f"Tree size: {proof['tree_size']}")
        else:
            click.echo("Error: Invalid inclusion proof", err=True)
            
        return is_valid
        
    except Exception as e:
        click.echo(f"Error verifying inclusion: {e}", err=True)
        return False
