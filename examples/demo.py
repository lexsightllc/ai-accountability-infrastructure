#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""
AI Trust Demo
=============

This script demonstrates how to use the AI Trust tools:
1. Verify a receipt
2. Start a transparency log server
3. Submit a receipt to the log
4. Verify the receipt's inclusion in the log
"""

import json
import os
import time
import threading
import requests

from ai_trust.services.verifier import AIReceiptVerifier
from ai_trust.services.log.server import run_server, TransparencyLog

# Configuration
SAMPLE_RECEIPT_PATH = "examples/sample_receipt.json"
LOG_DIR = "./data"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"

def print_header(title: str) -> None:
    """Print a formatted header."""
    print(f"\n{'=' * 80}")
    print(f" {title.upper()} ".center(80, '='))
    print(f"{'=' * 80}\n")

def verify_receipt_demo() -> None:
    """Demo of the receipt verification process."""
    print_header("1. Verifying a Receipt")
    
    # Load the sample receipt
    with open(SAMPLE_RECEIPT_PATH, 'r') as f:
        receipt_json = f.read()
    
    print("Verifying receipt:")
    print(json.dumps(json.loads(receipt_json), indent=2))
    
    # Verify the receipt
    verifier = AIReceiptVerifier(verbose=True)
    result = verifier.verify_receipt(receipt_json)
    
    print("\nVerification result:")
    print(f"- Valid: {result.valid}")
    print(f"- Reason: {result.reason}")
    
    if result.details:
        print("\nDetails:")
        for key, value in result.details.items():
            print(f"- {key}: {value}")
    
    return result.valid

def start_transparency_log() -> threading.Thread:
    """Start the transparency log server in a background thread."""
    print_header("2. Starting Transparency Log Server")
    
    # Create the log directory if it doesn't exist
    os.makedirs(LOG_DIR, exist_ok=True)
    
    # Start the server in a background thread
    def run():
        run_server(host=SERVER_HOST, port=SERVER_PORT, debug=False)
    
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    
    # Wait for the server to start
    max_retries = 10
    for _ in range(max_retries):
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=1)
            if response.status_code == 200:
                print(f"Server is running at {BASE_URL}")
                print(f"Merkle root: {response.json()['merkle_root']}")
                return thread
        except (requests.RequestException, ConnectionError):
            time.sleep(0.5)
    
    raise RuntimeError("Failed to start transparency log server")

def submit_receipt_demo() -> str:
    """Submit a receipt to the transparency log."""
    print_header("3. Submitting Receipt to Transparency Log")
    
    # Load the sample receipt
    with open(SAMPLE_RECEIPT_PATH, 'r') as f:
        receipt_json = f.read()
    
    # Submit the receipt
    response = requests.post(
        f"{BASE_URL}/receipts",
        data=receipt_json,
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code != 201:
        print(f"Error submitting receipt: {response.status_code} - {response.text}")
        return None
    
    result = response.json()
    print("Receipt submitted successfully!")
    print(f"- Index: {result['index']}")
    print(f"- Receipt Hash: {result['receipt_hash']}")
    print(f"- Merkle Root: {result['merkle_root']}")
    
    return result['receipt_hash']

def verify_inclusion_proof(receipt_hash: str) -> None:
    """Verify the inclusion proof for a receipt."""
    print_header("4. Verifying Inclusion Proof")
    
    # Get the inclusion proof
    response = requests.get(f"{BASE_URL}/proofs/{receipt_hash}")
    
    if response.status_code != 200:
        print(f"Error getting inclusion proof: {response.status_code} - {response.text}")
        return
    
    proof = response.json()
    print("Inclusion proof:")
    print(f"- Index: {proof['index']}")
    print(f"- Tree Size: {proof['tree_size']}")
    print(f"- Leaf Hash: {proof['leaf_hash']}")
    print(f"- Merkle Root: {proof['merkle_root']}")
    print(f"- Audit Path: {proof['audit_path']}")
    
    # Verify the proof using the transparency log
    log = TransparencyLog(storage_dir=LOG_DIR)
    is_valid = log.merkle_tree.verify_proof(
        type('InclusionProof', (), {
            'index': proof['index'],
            'tree_size': proof['tree_size'],
            'leaf_hash': proof['leaf_hash'],
            'audit_path': proof['audit_path']
        })
    )
    
    print(f"\nInclusion proof is {'VALID' if is_valid else 'INVALID'}")

def main():
    """Run the demo."""
    try:
        # Verify the receipt
        if not verify_receipt_demo():
            print("Receipt verification failed, exiting...")
            return
        
        # Start the transparency log server
        server_thread = start_transparency_log()
        
        try:
            # Submit a receipt to the log
            receipt_hash = submit_receipt_demo()
            
            if receipt_hash:
                # Verify the inclusion proof
                verify_inclusion_proof(receipt_hash)
                
                # Print the final status
                print_header("Demo Complete!")
                print("Successfully demonstrated the AI Trust tools:")
                print("1. Verified a receipt")
                print("2. Started a transparency log server")
                print("3. Submitted a receipt to the log")
                print("4. Verified the receipt's inclusion in the log")
                
                print("\nYou can explore the API further using these endpoints:")
                print(f"- {BASE_URL}/health - Server health check")
                print(f"- {BASE_URL}/receipts - Submit a receipt (POST) or get a receipt (GET /receipts/<id>)")
                print(f"- {BASE_URL}/proofs/<id> - Get inclusion proof for a receipt")
                print(f"- {BASE_URL}/tree/root - Get the current Merkle root")
                print(f"- {BASE_URL}/tree/size - Get the current tree size")
                
                print("\nPress Ctrl+C to stop the server.")
                
                # Keep the server running
                server_thread.join()
                
        except KeyboardInterrupt:
            print("\nShutting down...")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
