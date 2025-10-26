#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""
Verify an AI Trust receipt.

This script verifies the signature and structure of an AI Trust receipt
using the verifier module. It provides detailed validation results including
signature verification, timestamp validation, and policy compliance checks.
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, Optional

from ai_trust.services.verifier import ReceiptVerifier, VerificationResult

def load_receipt(receipt_path: str) -> Dict[str, Any]:
    """Load a receipt from a JSON file."""
    try:
        with open(receipt_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in receipt file: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"❌ Error: Receipt file not found: {receipt_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error loading receipt file: {e}", file=sys.stderr)
        sys.exit(1)

def load_public_key(key_path: str) -> Optional[bytes]:
    """Load a public key from a file."""
    try:
        with open(key_path, 'r', encoding='utf-8') as f:
            return f.read().strip().encode('utf-8')
    except FileNotFoundError:
        print(f"⚠️  Warning: Public key file not found: {key_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"⚠️  Warning: Error loading public key: {e}", file=sys.stderr)
        return None

def print_verification_result(result: VerificationResult, verbose: bool = False) -> None:
    """Print the verification result in a human-readable format."""
    print("\n" + "=" * 50)
    print("🔍 Receipt Verification Results")
    print("=" * 50)
    
    # Print basic validation status
    status_emoji = "✅" if result.is_valid else "❌"
    print(f"\nStatus: {status_emoji} {'Valid' if result.is_valid else 'Invalid'}")
    
    # Print receipt metadata if available
    receipt = result.receipt
    if receipt:
        print("\n📋 Receipt Details:")
        print(f"  • Version: {receipt.get('receipt_version', 'N/A')}")
        print(f"  • Issued At: {receipt.get('issued_at', 'N/A')}")
        print(f"  • Task Hash: {receipt.get('task_hash', 'N/A')}")
        print(f"  • Model Hash: {receipt.get('model_hash', 'N/A')}")
    
    # Print errors if any
    if result.errors:
        print("\n❌ Errors:")
        for error in result.errors:
            print(f"  • {error}")
    
    # Print warnings if any
    if result.warnings:
        print("\n⚠️  Warnings:")
        for warning in result.warnings:
            print(f"  • {warning}")
    
    # Print verification summary
    print("\n" + "=" * 50)
    if result.is_valid and not result.warnings:
        print("✅ Verification successful! The receipt is valid and all checks passed.")
    elif result.is_valid and result.warnings:
        print("⚠️  Verification completed with warnings. The receipt is valid but has some issues to review.")
    else:
        print("❌ Verification failed. The receipt is not valid.")
    
    print("=" * 50 + "\n")

def main() -> None:
    """Main function for the receipt verification script."""
    parser = argparse.ArgumentParser(
        description='Verify an AI accountability receipt',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        'receipt_file',
        help='Path to the receipt JSON file',
        type=str
    )
    parser.add_argument(
        '--public-key', '-k',
        help='Path to the public key file (PEM or base64)',
        type=str,
        default=None
    )
    parser.add_argument(
        '--check-log',
        help='Verify receipt inclusion in the transparency log',
        action='store_true'
    )
    parser.add_argument(
        '--log-server',
        help='URL of the transparency log server',
        type=str,
        default='http://localhost:8000'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Load the receipt
    receipt = load_receipt(args.receipt_file)
    
    # Load the public key if provided
    public_key = None
    if args.public_key:
        public_key = load_public_key(args.public_key)
    
    # Initialize the verifier
    try:
        if public_key:
            verifier = ReceiptVerifier(public_key=public_key)
        else:
            verifier = ReceiptVerifier()
            if args.verbose:
                print("⚠️  No public key provided. Signature verification will be skipped.")
    except Exception as e:
        print(f"❌ Error initializing verifier: {e}", file=sys.stderr)
        sys.exit(1)
            
    if args.verbose:
        print(f"🔍 Verifying receipt: {args.receipt_file}")
        if public_key:
            print(f"🔑 Using public key: {args.public_key}")
    
    try:
        # Verify the receipt
        result = verifier.verify_receipt(receipt)
        
        # Print the verification results
        print_verification_result(result, args.verbose)
        
        # If requested, verify against the transparency log
        if args.check_log:
            if args.verbose:
                print("\n🔗 Checking transparency log...")
            
            try:
                import requests
                from urllib.parse import urljoin
                
                # Get the receipt hash
                receipt_hash = receipt.get('receipt_hash')
                if not receipt_hash and 'attestation' in receipt and 'signature' in receipt['attestation']:
                    # If no explicit hash, use the signature as the unique identifier
                    receipt_hash = receipt['attestation']['signature'].split(':')[-1][:32]
                
                if not receipt_hash:
                    print("⚠️  Could not determine receipt hash for log verification")
                else:
                    # Query the transparency log
                    log_url = urljoin(args.log_server, f"/receipts/{receipt_hash}")
                    if args.verbose:
                        print(f"  • Querying log server: {log_url}")
                    
                    response = requests.get(log_url, timeout=10)
                    if response.status_code == 200:
                        log_data = response.json()
                        if log_data.get('is_valid', False):
                            print(f"✅ Receipt found in transparency log (ID: {log_data.get('receipt_id')})")
                            if args.verbose:
                                print(f"   • Merkle Root: {log_data.get('merkle_root')}")
                                print(f"   • Proof Length: {len(log_data.get('merkle_proof', []))} hashes")
                        else:
                            print("⚠️  Receipt not found in transparency log")
                    else:
                        print(f"⚠️  Error querying transparency log: {response.status_code} - {response.text}")
            except ImportError:
                print("⚠️  'requests' package not found. Install with: pip install requests")
            except Exception as e:
                print(f"⚠️  Error checking transparency log: {e}")
        
        # Exit with appropriate status code
        sys.exit(0 if result.is_valid else 1)
        
    except Exception as e:
        print(f"\n❌ Error verifying receipt: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    sys.exit(0 if result.is_valid else 1)

if __name__ == "__main__":
    main()
