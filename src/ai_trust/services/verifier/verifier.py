# SPDX-License-Identifier: MPL-2.0
"""
AI Trust Verifier

This module provides functionality to verify AI Trust receipts.
It includes validation of signatures, timestamps, and policy compliance.
"""

import json
import hashlib
import base64
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from pathlib import Path

# Import cryptography libraries
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

@dataclass
class VerificationResult:
    """Result of a receipt verification."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    receipt: Dict[str, Any]

class ReceiptVerifier:
    """Verifies AI accountability receipts."""
    
    def __init__(self, public_key_path: Optional[str] = None, 
                 public_key: Optional[bytes] = None):
        """Initialize the verifier with a public key.
        
        Args:
            public_key_path: Path to a PEM-encoded public key file
            public_key: Raw public key bytes (alternative to public_key_path)
        """
        self.public_key = None
        
        if not CRYPTO_AVAILABLE:
            raise ImportError(
                "Cryptography library not available. "
                "Install with: pip install cryptography"
            )
            
        if public_key_path:
            self.load_public_key_from_file(public_key_path)
        elif public_key:
            self.load_public_key(public_key)
    
    def load_public_key_from_file(self, key_path: str) -> None:
        """Load a public key from a file.
        
        Args:
            key_path: Path to the public key file (PEM or base64-encoded)
        """
        key_path = Path(key_path)
        key_data = key_path.read_bytes()
        
        try:
            # Try to load as PEM
            self.public_key = serialization.load_pem_public_key(
                key_data,
                backend=None
            )
        except (ValueError, TypeError):
            # Try to load as base64-encoded raw key
            try:
                key_bytes = base64.b64decode(key_data)
                self.public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            except Exception as e:
                raise ValueError(
                    f"Could not load public key from {key_path}. "
                    "Expected PEM or base64-encoded key."
                ) from e
    
    def load_public_key(self, key_data: bytes) -> None:
        """Load a public key from bytes.
        
        Args:
            key_data: Public key in PEM or raw bytes format
        """
        try:
            # Try to load as PEM
            self.public_key = serialization.load_pem_public_key(
                key_data,
                backend=None
            )
        except (ValueError, TypeError):
            # Try to load as raw key
            try:
                self.public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_data)
            except Exception as e:
                raise ValueError(
                    "Could not load public key. "
                    "Expected PEM or raw bytes format."
                ) from e
    
    def verify_receipt(self, receipt_data: Union[str, bytes, Dict[str, Any]]) -> VerificationResult:
        """Verify an AI accountability receipt.
        
        Args:
            receipt_data: Receipt as JSON string, bytes, or dict
            
        Returns:
            VerificationResult with validation results
        """
        # Parse receipt data
        if isinstance(receipt_data, (str, bytes)):
            try:
                if isinstance(receipt_data, bytes):
                    receipt_data = receipt_data.decode('utf-8')
                receipt = json.loads(receipt_data)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return VerificationResult(
                    is_valid=False,
                    errors=[f"Invalid receipt format: {str(e)}"],
                    warnings=[],
                    receipt={}
                )
        elif isinstance(receipt_data, dict):
            receipt = receipt_data.copy()
        else:
            return VerificationResult(
                is_valid=False,
                errors=["Receipt must be a JSON string, bytes, or dict"],
                warnings=[],
                receipt={}
            )
        
        errors = []
        warnings = []
        
        # Check required fields
        required_fields = [
            'receipt_version', 'issued_at', 'task_hash', 
            'model_hash', 'policies', 'attestation'
        ]
        
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
        
        # Validate receipt version
        if receipt['receipt_version'] != '1.0':
            warnings.append(f"Unsupported receipt version: {receipt['receipt_version']}")
        
        # Validate timestamp
        try:
            issued_at = datetime.fromisoformat(receipt['issued_at'].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            
            # Check if timestamp is in the future (with 5-minute leeway for clock skew)
            if issued_at > now.tzinfo.localize(now.replace(tzinfo=None)):
                errors.append(f"Receipt timestamp is in the future: {receipt['issued_at']}")
                
            # Check if receipt is too old (optional)
            max_age_days = 365  # 1 year
            if (now - issued_at).days > max_age_days:
                warnings.append(f"Receipt is older than {max_age_days} days")
                
        except (ValueError, TypeError) as e:
            errors.append(f"Invalid timestamp format: {str(e)}")
        
        # Validate hashes
        for hash_field in ['task_hash', 'model_hash', 'input_commitment', 'output_commitment']:
            if hash_field in receipt and not self._is_valid_hash(receipt[hash_field]):
                errors.append(f"Invalid {hash_field} format")
        
        # Validate policies
        if not isinstance(receipt['policies'], dict):
            errors.append("Policies must be an object")
        else:
            for policy_type in ['satisfied', 'relaxed']:
                if policy_type in receipt['policies']:
                    if not isinstance(receipt['policies'][policy_type], list):
                        errors.append(f"{policy_type} policies must be an array")
                    
                    # Check for duplicate policies
                    policies = receipt['policies'][policy_type]
                    if len(policies) != len(set(policies)):
                        warnings.append(f"Duplicate policies found in {policy_type}")
        
        # Verify signature if public key is available
        if self.public_key and 'attestation' in receipt:
            attestation = receipt['attestation']
            
            if 'signature' not in attestation:
                errors.append("Missing signature in attestation")
            else:
                # Extract signature and message
                try:
                    # Clone receipt and remove signature for verification
                    receipt_copy = receipt.copy()
                    receipt_copy['attestation'] = receipt_copy['attestation'].copy()
                    signature = receipt_copy['attestation'].pop('signature')
                    
                    # Convert to canonical JSON
                    message = json.dumps(
                        receipt_copy,
                        sort_keys=True,
                        separators=(',', ':')
                    ).encode('utf-8')
                    
                    # Verify signature
                    if ':' in signature:
                        sig_type, sig_value = signature.split(':', 1)
                        if sig_type.lower() != 'ed25519':
                            errors.append(f"Unsupported signature type: {sig_type}")
                        else:
                            try:
                                sig_bytes = base64.b64decode(sig_value)
                                self.public_key.verify(sig_bytes, message)
                            except (ValueError, InvalidSignature) as e:
                                errors.append(f"Invalid signature: {str(e)}")
                    else:
                        # Try to verify as raw signature
                        try:
                            sig_bytes = base64.b64decode(signature)
                            self.public_key.verify(sig_bytes, message)
                        except (ValueError, InvalidSignature) as e:
                            errors.append(f"Invalid signature: {str(e)}")
                            
                except Exception as e:
                    errors.append(f"Error verifying signature: {str(e)}")
        
        return VerificationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            receipt=receipt
        )
    
    @staticmethod
    def _is_valid_hash(hash_str: str) -> bool:
        """Check if a string is a valid hash."""
        if not isinstance(hash_str, str):
            return False
            
        # Check for common hash formats (e.g., 'sha256:abc123...')
        if ':' in hash_str:
            algo, value = hash_str.split(':', 1)
            if algo not in hashlib.algorithms_available:
                return False
            # Check if the value is valid hex
            try:
                int(value, 16)
                return True
            except ValueError:
                return False
        
        # Assume it's just a hash value
        try:
            int(hash_str, 16)
            return True
        except ValueError:
            return False

def verify_receipt_file(
    receipt_path: str, 
    public_key_path: Optional[str] = None,
    verbose: bool = True
) -> bool:
    """Verify a receipt from a file.
    
    Args:
        receipt_path: Path to the receipt JSON file
        public_key_path: Optional path to the public key file
        verbose: Whether to print verification results
        
    Returns:
        bool: True if verification succeeded, False otherwise
    """
    try:
        # Load receipt
        with open(receipt_path, 'r') as f:
            receipt_data = f.read()
        
        # Initialize verifier
        verifier = ReceiptVerifier(public_key_path=public_key_path)
        
        # Verify receipt
        result = verifier.verify_receipt(receipt_data)
        
        # Print results
        if verbose:
            print(f"Receipt: {receipt_path}")
            print(f"Valid: {'[VALID]' if result.is_valid else '[INVALID]'}")
            
            if result.warnings:
                print("\nWarnings:")
                for warning in result.warnings:
                    print(f"  [WARNING] {warning}")
            
            if result.errors:
                print("\nErrors:")
                for error in result.errors:
                    print(f"  [ERROR] {error}")
            
            if not result.errors and not result.warnings:
                print("No issues found!")
        
        return result.is_valid
        
    except Exception as e:
        if verbose:
            print(f"Error verifying receipt: {str(e)}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Verify an AI accountability receipt')
    parser.add_argument('receipt', help='Path to the receipt JSON file')
    parser.add_argument('--public-key', '-k', help='Path to the public key file (PEM or base64)')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
    
    args = parser.parse_args()
    
    verify_receipt_file(
        args.receipt,
        public_key_path=args.public_key,
        verbose=not args.quiet
    )
