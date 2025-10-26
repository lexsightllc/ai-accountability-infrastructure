#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""
Sign an AI accountability receipt with an Ed25519 private key.

This script loads a receipt from a JSON file, signs it with the provided private key,
and saves the signed receipt to a new file.
"""

import json
import os
import sys
import argparse
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def load_private_key(key_path: str) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    with open(key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("The provided key is not an Ed25519 private key")
    
    return private_key

def sign_receipt(receipt: dict, private_key: ed25519.Ed25519PrivateKey) -> dict:
    """Sign an AI accountability receipt.
    
    Args:
        receipt: The receipt to sign (as a dictionary)
        private_key: The private key to sign with
        
    Returns:
        A new receipt dictionary with the signature added to the attestation
    """
    # Make a copy of the receipt to avoid modifying the original
    signed_receipt = receipt.copy()
    
    # Ensure the receipt has an attestation section
    if 'attestation' not in signed_receipt:
        signed_receipt['attestation'] = {}
    
    # Create a copy of the receipt without the signature for signing
    receipt_for_signing = signed_receipt.copy()
    if 'signature' in receipt_for_signing['attestation']:
        del receipt_for_signing['attestation']['signature']
    
    # Convert to canonical JSON (sorted keys, no whitespace)
    canonical_json = json.dumps(
        receipt_for_signing,
        sort_keys=True,
        separators=(',', ':')
    )
    
    # Sign the canonical JSON
    signature = private_key.sign(canonical_json.encode('utf-8'))
    
    # Add the base64-encoded signature to the receipt
    signed_receipt['attestation']['signature'] = f"ed25519:{base64.b64encode(signature).decode('ascii')}"
    
    return signed_receipt

def main():
    parser = argparse.ArgumentParser(description='Sign an AI accountability receipt with an Ed25519 private key')
    parser.add_argument('receipt_file', help='Path to the receipt JSON file')
    parser.add_argument('--key', '-k', required=True, help='Path to the private key file (PEM format)')
    parser.add_argument('--output', '-o', help='Output file path (default: <input_file>.signed.json)')
    
    args = parser.parse_args()
    
    # Set default output filename if not provided
    if not args.output:
        base, ext = os.path.splitext(args.receipt_file)
        args.output = f"{base}.signed{ext}"
    
    try:
        # Load the private key
        private_key = load_private_key(args.key)
        
        # Load the receipt
        with open(args.receipt_file, 'r') as f:
            receipt = json.load(f)
        
        # Sign the receipt
        signed_receipt = sign_receipt(receipt, private_key)
        
        # Save the signed receipt
        with open(args.output, 'w') as f:
            json.dump(signed_receipt, f, indent=2)
        
        print(f"Successfully signed receipt saved to: {args.output}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
