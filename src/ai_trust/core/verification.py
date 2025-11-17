# SPDX-License-Identifier: MPL-2.0
"""
Verification Module for AI Trust Infrastructure

This module provides functionality to verify receipts and their inclusion in the
Merkle tree, ensuring data integrity and trust.
"""

import base64
import json
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Union
from pathlib import Path

# Import cryptography libraries
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from .db import LogDB, LogEntry
from .merkle import MerkleTree

# Type aliases
ReceiptID = str
PublicKey = Union[ed25519.Ed25519PublicKey, rsa.RSAPublicKey]
Signature = bytes

@dataclass
class VerificationResult:
    """Result of a receipt verification operation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    receipt: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        return {
            'is_valid': self.is_valid,
            'errors': self.errors,
            'warnings': self.warnings,
            'receipt': self.receipt
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert the result to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


class ReceiptVerifier:
    """
    Verifies AI accountability receipts and their inclusion in the Merkle tree.
    
    This class provides methods to verify receipt signatures, validate receipt
    structure, and verify inclusion proofs in the Merkle tree.
    """
    
    def __init__(self, db: LogDB, public_key: Optional[PublicKey] = None):
        """Initialize the verifier with a database and optional public key.
        
        Args:
            db: An instance of LogDB for database operations
            public_key: Optional public key for signature verification
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError(
                "Cryptography library not available. "
                "Install with: pip install cryptography"
            )
            
        self.db = db
        self.public_key = public_key
    
    @classmethod
    def from_public_key_file(
        cls, 
        db: LogDB, 
        public_key_path: Union[str, Path]
    ) -> 'ReceiptVerifier':
        """Create a verifier from a public key file.
        
        Args:
            db: An instance of LogDB for database operations
            public_key_path: Path to a PEM-encoded public key file
            
        Returns:
            A new ReceiptVerifier instance
        """
        with open(public_key_path, 'rb') as f:
            public_key_data = f.read()
            
        try:
            public_key = load_pem_public_key(public_key_data)
            if not isinstance(public_key, (ed25519.Ed25519PublicKey, rsa.RSAPublicKey)):
                raise ValueError("Unsupported public key type. Must be Ed25519 or RSA.")
                
            return cls(db, public_key)
            
        except Exception as e:
            raise ValueError(f"Failed to load public key: {e}")
    
    def verify_receipt(
        self, 
        receipt_data: Union[Dict[str, Any], str, bytes],
        verify_signature: bool = True,
        verify_inclusion: bool = True
    ) -> VerificationResult:
        """Verify a receipt's signature and inclusion in the Merkle tree.
        
        Args:
            receipt_data: The receipt data as a dict, JSON string, or bytes
            verify_signature: Whether to verify the receipt's signature
            verify_inclusion: Whether to verify the receipt's inclusion in the Merkle tree
            
        Returns:
            A VerificationResult object with the verification outcome
        """
        # Parse receipt data if needed
        if isinstance(receipt_data, (str, bytes)):
            try:
                if isinstance(receipt_data, bytes):
                    receipt_data = receipt_data.decode('utf-8')
                receipt = json.loads(receipt_data)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return VerificationResult(
                    is_valid=False,
                    errors=[f"Invalid receipt format: {e}"],
                    warnings=[],
                    receipt={}
                )
        else:
            receipt = receipt_data
        
        errors = []
        warnings = []
        
        # Validate receipt structure
        if not isinstance(receipt, dict):
            return VerificationResult(
                is_valid=False,
                errors=["Receipt must be a JSON object"],
                warnings=[],
                receipt=receipt
            )
        
        # Check for required fields
        required_fields = ['receipt_id', 'timestamp', 'data', 'signature']
        for field in required_fields:
            if field not in receipt:
                errors.append(f"Missing required field: {field}")
        
        if errors:
            return VerificationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                receipt=receipt
            )
        
        # Verify signature if requested and public key is available
        if verify_signature and self.public_key:
            try:
                signature = base64.b64decode(receipt['signature'])
                receipt_copy = receipt.copy()
                receipt_copy.pop('signature', None)
                
                # Create a canonical JSON representation
                message = json.dumps(
                    receipt_copy, 
                    sort_keys=True, 
                    separators=(',', ':')
                ).encode('utf-8')
                
                # Verify the signature
                if isinstance(self.public_key, ed25519.Ed25519PublicKey):
                    self.public_key.verify(signature, message)
                elif isinstance(self.public_key, rsa.RSAPublicKey):
                    self.public_key.verify(
                        signature,
                        message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                
            except (ValueError, KeyError, InvalidSignature) as e:
                errors.append(f"Invalid signature: {e}")
        
        # Verify inclusion in Merkle tree if requested
        if verify_inclusion and 'receipt_id' in receipt:
            try:
                entry = self.db.get_log_entry(receipt['receipt_id'])
                if not entry:
                    errors.append("Receipt not found in the transparency log")
                else:
                    # Verify the data matches
                    if entry.data != json.dumps(receipt.get('data', {})):
                        errors.append("Receipt data does not match logged data")
                    
                    # Verify inclusion proof if available
                    if 'inclusion_proof' in receipt:
                        proof = receipt['inclusion_proof']
                        if not self.db.verify_inclusion_proof(receipt['receipt_id'], proof):
                            errors.append("Invalid inclusion proof")
                    
            except Exception as e:
                errors.append(f"Error verifying inclusion: {e}")
        
        # Check for expired receipts
        if 'timestamp' in receipt:
            try:
                timestamp = datetime.fromisoformat(receipt['timestamp'])
                if timestamp > datetime.now(timezone.utc):
                    warnings.append("Receipt timestamp is in the future")
            except (ValueError, TypeError):
                errors.append("Invalid timestamp format")
        
        return VerificationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            receipt=receipt
        )
    
    def verify_receipt_file(
        self,
        file_path: Union[str, Path],
        verify_signature: bool = True,
        verify_inclusion: bool = True
    ) -> VerificationResult:
        """Verify a receipt from a file.
        
        Args:
            file_path: Path to the receipt file
            verify_signature: Whether to verify the receipt's signature
            verify_inclusion: Whether to verify the receipt's inclusion in the Merkle tree
            
        Returns:
            A VerificationResult object with the verification outcome
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                receipt_data = f.read()
                
            return self.verify_receipt(
                receipt_data,
                verify_signature=verify_signature,
                verify_inclusion=verify_inclusion
            )
            
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                errors=[f"Error reading receipt file: {e}"],
                warnings=[],
                receipt={"file_path": str(file_path)}
            )
    
    def get_inclusion_proof(
        self,
        receipt_id: ReceiptID,
        tree_size: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """Get an inclusion proof for a receipt.
        
        Args:
            receipt_id: The ID of the receipt
            tree_size: Optional tree size for historical proofs
            
        Returns:
            A dictionary with the inclusion proof, or None if not found
        """
        return self.db.get_inclusion_proof(receipt_id, tree_size)
    
    def get_consistency_proof(
        self,
        first_size: int,
        second_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get a consistency proof between two tree sizes.
        
        Args:
            first_size: The first tree size
            second_size: The second tree size (defaults to current size)
            
        Returns:
            A dictionary with the consistency proof
        """
        return self.db.get_consistency_proof(first_size, second_size)


def verify_receipt_file(
    file_path: Union[str, Path],
    db_path: Optional[Union[str, Path]] = None,
    public_key_path: Optional[Union[str, Path]] = None,
    verify_signature: bool = True,
    verify_inclusion: bool = True
) -> VerificationResult:
    """Convenience function to verify a receipt file.
    
    Args:
        file_path: Path to the receipt file
        db_path: Optional path to the database file
        public_key_path: Optional path to the public key file
        verify_signature: Whether to verify the receipt's signature
        verify_inclusion: Whether to verify the receipt's inclusion in the Merkle tree
        
    Returns:
        A VerificationResult object with the verification outcome
    """
    if not CRYPTO_AVAILABLE:
        return VerificationResult(
            is_valid=False,
            errors=["Cryptography library not available. Install with: pip install cryptography"],
            warnings=[],
            receipt={"file_path": str(file_path)}
        )
    
    try:
        # Initialize database if path is provided
        db = None
        if db_path:
            db = LogDB(db_path)
        
        # Initialize verifier
        if public_key_path and db:
            verifier = ReceiptVerifier.from_public_key_file(db, public_key_path)
        elif db:
            verifier = ReceiptVerifier(db)
        else:
            return VerificationResult(
                is_valid=False,
                errors=["Database path is required for inclusion verification"],
                warnings=[],
                receipt={"file_path": str(file_path)}
            )
        
        # Verify the receipt
        return verifier.verify_receipt_file(
            file_path=file_path,
            verify_signature=verify_signature,
            verify_inclusion=verify_inclusion
        )
        
    except Exception as e:
        return VerificationResult(
            is_valid=False,
            errors=[f"Verification error: {e}"],
            warnings=[],
            receipt={"file_path": str(file_path)}
        )
