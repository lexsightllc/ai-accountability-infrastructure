# SPDX-License-Identifier: MPL-2.0
"""
AI Receipt Verifier - The Pocket Verifier
==========================================

A minimal, standalone verifier for AI accountability receipts.
Verifies Ed25519 signatures, timestamps, hashes, and policy compliance.
"""

import json
import hashlib
import base64
import argparse
import sys
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

# Optional cryptography import for Ed25519
CRYPTO_AVAILABLE = True
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
except ImportError:
    CRYPTO_AVAILABLE = False


class VerificationResult:
    """Represents the result of a verification operation."""

    def __init__(self, valid: bool, reason: str, details: Dict[str, Any] = None):
        self.valid = valid
        self.reason = reason
        self.details = details or {}

    def __bool__(self):
        return self.valid

    def __str__(self):
        status = "VALID" if self.valid else "INVALID"
        return f"{status}: {self.reason}"


class AIReceiptVerifier:
    """Verifies AI accountability receipts according to the v1.0 standard."""

    REQUIRED_FIELDS = [
        'receipt_version',
        'issued_at',
        'task_hash',
        'model_hash',
        'input_commitment',
        'output_commitment',
        'policies',
        'costs',
        'attestation'
    ]
    
    SUPPORTED_VERSIONS = ['1.0']
    MAX_RECEIPT_AGE_HOURS = 24 * 30  # 30 days
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
    def verify_receipt(self, receipt_json: str, public_key: Optional[ed25519.Ed25519PublicKey] = None) -> VerificationResult:
        """Main verification method. Returns VerificationResult."""
        try:
            receipt = json.loads(receipt_json)
        except json.JSONDecodeError as e:
            return VerificationResult(False, f"Invalid JSON: {e}")
            
        # Step 1: Structure validation
        result = self._verify_structure(receipt)
        if not result.valid:
            return result
            
        # Step 2: Timestamp validation  
        result = self._verify_timestamp(receipt)
        if not result.valid:
            return result
            
        # Step 3: Hash format validation
        result = self._verify_hashes(receipt)
        if not result.valid:
            return result
            
        # Step 4: Policy validation
        result = self._verify_policies(receipt)
        if not result.valid:
            return result
            
        # Step 5: Cost validation
        result = self._verify_costs(receipt)
        if not result.valid:
            return result
            
        # Step 6: Signature verification (if public key provided)
        if public_key:
            result = self._verify_signature(receipt, public_key)
            if not result.valid:
                return result
        elif self.verbose:
            print("[WARNING] No public key provided, skipping signature verification")
        
        return VerificationResult(True, "Receipt verified successfully", {
            'version': receipt['receipt_version'],
            'issued_at': receipt['issued_at'],
            'policies_satisfied': len(receipt['policies'].get('satisfied', [])),
            'policies_relaxed': len(receipt['policies'].get('relaxed', [])),
            'latency_ms': receipt['costs'].get('latency_ms'),
            'energy_j': receipt['costs'].get('energy_j'),
            'signature_verified': public_key is not None
        })
    
    def _verify_structure(self, receipt: Dict[str, Any]) -> VerificationResult:
        """Verify receipt has all required fields and correct structure."""
        # Check required top-level fields
        missing_fields = [f for f in self.REQUIRED_FIELDS if f not in receipt]
        if missing_fields:
            return VerificationResult(False, f"Missing required fields: {', '.join(missing_fields)}")
        
        # Check version support
        version = receipt.get('receipt_version')
        if version not in self.SUPPORTED_VERSIONS:
            return VerificationResult(False, f"Unsupported version: {version}")
            
        # Check nested structures
        for field in ['policies', 'costs', 'attestation']:
            if not isinstance(receipt.get(field), dict):
                return VerificationResult(False, f"Invalid {field} structure")
            
        # Check attestation has required fields
        attestation = receipt['attestation']
        if 'signature' not in attestation or 'pubkey_id' not in attestation:
            return VerificationResult(False, "Attestation missing signature or pubkey_id")
            
        return VerificationResult(True, "Structure valid")
    
    def _verify_timestamp(self, receipt: Dict[str, Any]) -> VerificationResult:
        """Verify timestamp is valid RFC 3339 format and not too old."""
        issued_at_str = receipt['issued_at']
        
        try:
            # Parse RFC 3339 timestamp
            issued_at = datetime.fromisoformat(issued_at_str.replace('Z', '+00:00'))
        except ValueError:
            return VerificationResult(False, f"Invalid timestamp format: {issued_at_str}")
            
        # Check if timestamp is in the future (with 5 minute grace period)
        now = datetime.now(timezone.utc)
        if issued_at > now.replace(microsecond=0).replace(second=0) + timedelta(minutes=5):
            return VerificationResult(False, f"Timestamp is in the future: {issued_at_str}")
            
        # Check if timestamp is too old
        hours_old = (now - issued_at).total_seconds() / 3600
        if hours_old > self.MAX_RECEIPT_AGE_HOURS:
            return VerificationResult(False, f"Receipt is too old: {hours_old:.1f} hours")
            
        return VerificationResult(True, "Timestamp valid")
    
    def _verify_hashes(self, receipt: Dict[str, Any]) -> VerificationResult:
        """Verify all hash fields have correct format."""
        hash_fields = ['task_hash', 'model_hash', 'input_commitment', 'output_commitment']
        
        for field in hash_fields:
            hash_value = receipt.get(field, '')
            if not hash_value.startswith('sha256:'):
                return VerificationResult(False, f"Invalid hash format for {field}: must start with 'sha256:'")
                
            hash_hex = hash_value[7:]  # Remove 'sha256:' prefix
            if len(hash_hex) != 64:  # SHA-256 is 32 bytes = 64 hex chars
                return VerificationResult(False, f"Invalid hash length for {field}: expected 64 hex chars")
                
            try:
                int(hash_hex, 16)  # Verify it's valid hex
            except ValueError:
                return VerificationResult(False, f"Invalid hash format for {field}: not valid hex")
                
        return VerificationResult(True, "Hash formats valid")
    
    def _verify_policies(self, receipt: Dict[str, Any]) -> VerificationResult:
        """Verify policy structure and format."""
        policies = receipt['policies']
        
        # Check policies structure
        if 'satisfied' not in policies or 'relaxed' not in policies:
            return VerificationResult(False, "Policies must contain 'satisfied' and 'relaxed' arrays")
            
        if not isinstance(policies['satisfied'], list) or not isinstance(policies['relaxed'], list):
            return VerificationResult(False, "Policy satisfied and relaxed must be arrays")
            
        # Validate policy IDs format (should start with P_)
        all_policies = policies['satisfied'] + policies['relaxed']
        for policy_id in all_policies:
            if not isinstance(policy_id, str) or not policy_id.startswith('P_'):
                return VerificationResult(False, f"Invalid policy ID format: {policy_id}")
                
        # Check for policy conflicts (same policy in both satisfied and relaxed)
        satisfied_set = set(policies['satisfied'])
        relaxed_set = set(policies['relaxed'])
        conflicts = satisfied_set.intersection(relaxed_set)
        if conflicts:
            return VerificationResult(False, f"Policy conflicts: {list(conflicts)}")
            
        return VerificationResult(True, "Policies valid")
    
    def _verify_costs(self, receipt: Dict[str, Any]) -> VerificationResult:
        """Verify cost metrics are reasonable."""
        costs = receipt['costs']
        
        # Check required cost fields
        if 'latency_ms' not in costs:
            return VerificationResult(False, "Missing latency_ms in costs")
            
        # Validate numeric fields
        latency_ms = costs.get('latency_ms')
        if not isinstance(latency_ms, (int, float)) or latency_ms < 0:
            return VerificationResult(False, "Invalid latency_ms: must be non-negative number")
            
        # Energy is optional but should be valid if present
        if 'energy_j' in costs:
            energy_j = costs['energy_j']
            if not isinstance(energy_j, (int, float)) or energy_j < 0:
                return VerificationResult(False, "Invalid energy_j: must be non-negative number")
                
        # Tokens is optional but should be valid if present  
        if 'tokens' in costs:
            tokens = costs['tokens']
            if not isinstance(tokens, int) or tokens < 0:
                return VerificationResult(False, "Invalid tokens: must be non-negative integer")
                
        # Sanity checks
        if latency_ms > 300000:  # > 5 minutes seems suspicious
            return VerificationResult(False, f"Suspicious latency_ms: {latency_ms} (> 5 minutes)")
            
        return VerificationResult(True, "Costs valid")
    
    def _verify_signature(self, receipt: Dict[str, Any], public_key: ed25519.Ed25519PublicKey) -> VerificationResult:
        """Verify Ed25519 signature."""
        if not CRYPTO_AVAILABLE:
            return VerificationResult(False, "Cryptography library not available for signature verification")
            
        attestation = receipt['attestation']
        signature_str = attestation['signature']
        
        # Parse signature
        if not signature_str.startswith('ed25519:'):
            return VerificationResult(False, "Invalid signature format: must start with 'ed25519:'")
            
        try:
            signature_b64 = signature_str[8:]  # Remove 'ed25519:' prefix
            signature_bytes = base64.b64decode(signature_b64)
        except Exception as e:
            return VerificationResult(False, f"Invalid signature encoding: {e}")
            
        # Create canonical JSON for signing (sorted keys, no spaces)
        try:
            # Remove signature for canonical form
            receipt_for_signing = receipt.copy()
            receipt_for_signing['attestation'] = {
                'pubkey_id': attestation['pubkey_id']
            }
            canonical_json = json.dumps(receipt_for_signing, separators=(',', ':'), sort_keys=True)
            canonical_bytes = canonical_json.encode('utf-8')
        except Exception as e:
            return VerificationResult(False, f"Failed to create canonical JSON: {e}")
            
        # Verify signature
        try:
            public_key.verify(signature_bytes, canonical_bytes)
            return VerificationResult(True, "Signature valid")
        except InvalidSignature:
            return VerificationResult(False, "Invalid signature")
        except Exception as e:
            return VerificationResult(False, f"Signature verification error: {e}")


def load_public_key(key_path: str) -> ed25519.Ed25519PublicKey:
    """Load Ed25519 public key from PEM file."""
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library is required for key loading")
        
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
            
        # Try to parse as PEM
        try:
            return serialization.load_pem_public_key(key_data)
        except ValueError:
            # Try to parse as base64
            key_b64 = key_data.decode('utf-8').strip()
            key_bytes = base64.b64decode(key_b64)
            return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            
    except Exception as e:
        raise ValueError(f"Error loading public key: {e}")


def main():
    """Command-line interface for the verifier."""
    if not CRYPTO_AVAILABLE:
        print("Error: cryptography library required. Install with: pip install cryptography")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Verify AI accountability receipts')
    parser.add_argument('receipt', help='Path to receipt JSON file')
    parser.add_argument('--pubkey', help='Path to Ed25519 public key file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Load receipt
    try:
        with open(args.receipt, 'r') as f:
            receipt_json = f.read()
    except Exception as e:
        print(f"[ERROR] Error reading receipt file: {e}")
        sys.exit(1)
    
    # Load public key if provided
    public_key = None
    if args.pubkey:
        try:
            public_key = load_public_key(args.pubkey)
            if args.verbose:
                print(f"[OK] Loaded public key from {args.pubkey}")
        except Exception as e:
            print(f"[ERROR] Error loading public key: {e}")
            sys.exit(1)
    
    # Verify receipt
    verifier = AIReceiptVerifier(verbose=args.verbose)
    result = verifier.verify_receipt(receipt_json, public_key)
    
    # Output result
    if result.valid:
        print(f"[VALID] {result.reason}")
        if args.verbose and result.details:
            print("\n[INFO] Receipt Details:")
            for key, value in result.details.items():
                print(f"   {key}: {value}")
    else:
        print(f"[INVALID] {result.reason}")
        sys.exit(1)


if __name__ == '__main__':
    main()
