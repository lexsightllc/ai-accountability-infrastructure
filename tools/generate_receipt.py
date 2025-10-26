#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""
Generate a sample AI accountability receipt.

This script creates a sample receipt that can be used for testing the
verifier and transparency log.
"""

import json
import uuid
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Sample policies that might be included in a receipt
SAMPLE_POLICIES = {
    "satisfied": [
        "P_SAFE_001",  # No harmful content
        "P_SAFE_002",  # No biased content
        "P_PRIV_001",  # No PII in output
        "P_PRIV_007",  # Data minimization
        "P_COMP_001",  # Compliance with terms of service
    ],
    "relaxed": [
        "P_SAFE_003",  # Potentially sensitive topic
        "P_PRIV_005",  # Data retention
    ]
}

def generate_sample_receipt(
    task_description: str = "A sample task description",
    model_name: str = "gpt-4",
    model_version: str = "2023-06-01",
    policies: dict = None,
    costs: dict = None,
    sign: bool = False,
    key_path: str = None
) -> dict:
    """Generate a sample AI accountability receipt.
    
    Args:
        task_description: Description of the task
        model_name: Name of the model
        model_version: Version of the model
        policies: Dictionary of satisfied and relaxed policies
        costs: Dictionary of cost metrics
        sign: Whether to sign the receipt (requires key_path)
        key_path: Path to the private key for signing
        
    Returns:
        A dictionary containing the receipt
    """
    if policies is None:
        policies = SAMPLE_POLICIES
    
    if costs is None:
        costs = {
            "latency_ms": 1450,
            "energy_j": 3.2,
            "tokens": 342,
            "api_cost_usd": 0.0042
        }
    
    # Generate a unique task ID
    task_id = str(uuid.uuid4())
    
    # Current timestamp in ISO 8601 format with timezone
    issued_at = datetime.now(timezone.utc).isoformat()
    
    # Create the receipt
    receipt = {
        "receipt_version": "1.0",
        "issued_at": issued_at,
        "task_id": task_id,
        "task_description": task_description,
        "model_name": model_name,
        "model_version": model_version,
        "task_hash": f"sha256:{task_id.replace('-', '')[:64]}",
        "model_hash": f"sha256:{model_name}_{model_version}".encode('utf-8').hex()[:64],
        "input_commitment": f"sha256:input_commitment_{task_id[:8]}",
        "output_commitment": f"sha256:output_commitment_{task_id[:8]}",
        "policies": policies,
        "costs": costs,
        "attestation": {
            "signature": "",  # Will be filled if signed
            "pubkey_id": "sample_key_2023"
        },
        "metadata": {
            "environment": "production",
            "region": "us-west-2",
            "service_version": "1.0.0"
        }
    }
    
    # Sign the receipt if requested
    if sign and key_path:
        try:
            # Import here to avoid requiring cryptography unless needed
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            
            # Load the private key
            with open(key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("The provided key is not an Ed25519 private key")
            
            # Create a copy of the receipt without the signature
            receipt_for_signing = receipt.copy()
            receipt_for_signing['attestation'] = receipt['attestation'].copy()
            receipt_for_signing['attestation']['signature'] = ""
            
            # Convert to canonical JSON
            canonical_json = json.dumps(
                receipt_for_signing,
                sort_keys=True,
                separators=(',', ':')
            )
            
            # Sign the canonical JSON
            signature = private_key.sign(canonical_json.encode('utf-8'))
            
            # Add the base64-encoded signature to the receipt
            receipt['attestation']['signature'] = f"ed25519:{signature.hex()}"
            
        except Exception as e:
            print(f"Warning: Could not sign receipt: {e}", file=sys.stderr)
    
    return receipt

def main():
    parser = argparse.ArgumentParser(description='Generate a sample AI accountability receipt')
    parser.add_argument('--output', '-o', default='sample_receipt.json',
                      help='Output file path (default: sample_receipt.json)')
    parser.add_argument('--task', '-t', default='A sample task description',
                      help='Task description')
    parser.add_argument('--model', '-m', default='gpt-4',
                      help='Model name')
    parser.add_argument('--version', '-v', default='2023-06-01',
                      help='Model version')
    parser.add_argument('--sign', '-s', action='store_true',
                      help='Sign the receipt (requires --key)')
    parser.add_argument('--key', '-k',
                      help='Path to the private key file for signing (PEM format)')
    
    args = parser.parse_args()
    
    # Generate the receipt
    receipt = generate_sample_receipt(
        task_description=args.task,
        model_name=args.model,
        model_version=args.version,
        sign=args.sign,
        key_path=args.key
    )
    
    # Save to file
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(receipt, f, indent=2)
    
    print(f"Sample receipt saved to: {output_path.absolute()}")
    
    if args.sign and args.key:
        print("Receipt has been signed with the provided private key.")
    elif args.sign:
        print("Warning: --sign was specified but no key was provided. Receipt was not signed.")
    else:
        print("Note: Receipt is not signed. Use --sign and --key to sign it.")

if __name__ == "__main__":
    import sys
    main()
