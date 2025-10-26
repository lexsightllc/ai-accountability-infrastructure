#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""
AI Trust Client Example

This script demonstrates how to use the AI Trust system to:
1. Generate a receipt for an AI operation
2. Sign the receipt with a private key
3. Submit the receipt to a transparency log
4. Verify the receipt and its inclusion in the log
"""

import json
import os
import time
from pathlib import Path
from urllib.parse import urljoin

import requests

from ai_trust.services.verifier import AIReceiptVerifier

class AITrustClient:
    """Client for interacting with the AI Trust system."""
    
    def __init__(self, server_url='http://localhost:5000', verify_ssl=True):
        """Initialize the client with the server URL."""
        self.server_url = server_url
        self.verify_ssl = verify_ssl
        self.verifier = AIReceiptVerifier()
    
    def generate_receipt(self, task_description, model_name, model_version, policies=None, costs=None):
        """Generate a receipt for an AI operation."""
        if policies is None:
            policies = {
                "satisfied": ["P_SAFE_001", "P_PRIV_007"],
                "relaxed": []
            }
            
        if costs is None:
            costs = {
                "latency_ms": 1500,
                "energy_j": 2.8,
                "tokens": 256
            }
        
        # In a real application, you would generate these hashes based on the actual inputs/outputs
        task_id = f"task_{int(time.time())}"
        
        receipt = {
            "receipt_version": "1.0",
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "task_id": task_id,
            "task_description": task_description,
            "model_name": model_name,
            "model_version": model_version,
            "task_hash": f"sha256:{task_id}",
            "model_hash": f"sha256:{model_name}_{model_version}",
            "input_commitment": f"sha256:input_{task_id}",
            "output_commitment": f"sha256:output_{task_id}",
            "policies": policies,
            "costs": costs,
            "attestation": {
                "signature": "",  # Will be filled when signed
                "pubkey_id": "example_key_2023"
            },
            "metadata": {
                "environment": "production",
                "service_version": "1.0.0"
            }
        }
        
        return receipt
    
    def sign_receipt(self, receipt, private_key_path):
        """Sign a receipt with a private key."""
        try:
            # Load the private key
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
                
            # Determine if it's PEM or raw key
            if b'-----BEGIN PRIVATE KEY-----' in private_key_data:
                self.verifier.load_public_key(private_key_data, format='pem')
                private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None
                )
            else:
                # Assume it's a raw key
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                    base64.b64decode(private_key_data)
                )
            
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
            
            # Add the signature to the receipt
            receipt['attestation']['signature'] = f"ed25519:{base64.b64encode(signature).decode('ascii')}"
            
            return True, ""
            
        except Exception as e:
            return False, str(e)
    
    def submit_receipt(self, receipt):
        """Submit a receipt to the transparency log."""
        url = urljoin(self.server_url, '/receipts')
        
        try:
            response = requests.post(
                url,
                json=receipt,
                headers={'Content-Type': 'application/json'},
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return True, response.json()
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_details = e.response.json()
                    error_msg = f"{error_msg}: {json.dumps(error_details, indent=2)}"
                except:
                    error_msg = f"{error_msg}: {e.response.text}"
            return False, error_msg
    
    def verify_receipt(self, receipt, public_key_path=None):
        """Verify a receipt's signature and structure."""
        # Load the public key if provided
        if public_key_path:
            try:
                with open(public_key_path, 'r') as f:
                    public_key_data = f.read().strip()
                
                # Determine the key format
                if '-----BEGIN PUBLIC KEY-----' in public_key_data:
                    self.verifier.load_public_key(public_key_data, format='pem')
                else:
                    self.verifier.load_public_key(public_key_data, format='base64')
            except Exception as e:
                return False, f"Failed to load public key: {e}"
        
        # Verify the receipt
        result = self.verifier.verify(receipt, verbose=True)
        
        if result.is_valid:
            return True, "Receipt is valid and verified!"
        else:
            return False, f"Receipt verification failed: {', '.join(result.errors)}"
    
    def check_inclusion(self, receipt_id_or_hash):
        """Check if a receipt is included in the log and get its inclusion proof."""
        # Get the receipt
        receipt_url = urljoin(self.server_url, f'/receipts/{receipt_id_or_hash}')
        proof_url = urljoin(self.server_url, f'/proofs/{receipt_id_or_hash}')
        
        try:
            # Get the receipt
            receipt_response = requests.get(receipt_url, verify=self.verify_ssl)
            receipt_response.raise_for_status()
            receipt_data = receipt_response.json()
            
            # Get the inclusion proof
            proof_response = requests.get(proof_url, verify=self.verify_ssl)
            
            if proof_response.status_code == 200:
                proof_data = proof_response.json()
                return True, {"receipt": receipt_data, "proof": proof_data}
            else:
                return False, f"Failed to get inclusion proof: {proof_response.text}"
                
        except requests.exceptions.RequestException as e:
            return False, f"Error checking inclusion: {e}"

def main():
    # Initialize the client
    client = AIAccountabilityClient(server_url='http://localhost:5000')
    
    print("=" * 60)
    print("AI Trust Client Example")
    print("=" * 60)
    
    # Generate a sample receipt
    print("\n1. Generating a sample receipt...")
    receipt = client.generate_receipt(
        task_description="Generate a summary of the meeting notes",
        model_name="gpt-4",
        model_version="2023-06-01"
    )
    print("   [OK] Receipt generated")
    
    # Sign the receipt (in a real app, you'd have a private key)
    print("\n2. Signing the receipt...")
    private_key_path = "keys/private_key.pem"
    
    if os.path.exists(private_key_path):
        success, message = client.sign_receipt(receipt, private_key_path)
        if success:
            print("   [OK] Receipt signed")
        else:
            print(f"   ! Could not sign receipt: {message}")
    else:
        print(f"   ! Private key not found at {private_key_path}, skipping signature")
    
    # Verify the receipt
    print("\n3. Verifying the receipt...")
    public_key_path = "keys/public_key.pem"
    
    if os.path.exists(public_key_path):
        success, message = client.verify_receipt(receipt, public_key_path)
        print(f"   {'[OK]' if success else '[ERROR]'} {message}")
    else:
        print(f"   ! Public key not found at {public_key_path}, skipping verification")
    
    # Submit to the transparency log
    print("\n4. Submitting to the transparency log...")
    success, result = client.submit_receipt(receipt)
    
    if success:
        print(f"   [OK] Receipt submitted successfully!")
        print(f"   Receipt ID: {result.get('index')}")
        print(f"   Receipt Hash: {result.get('receipt_hash')}")
        
        # Check inclusion in the log
        print("\n5. Verifying inclusion in the log...")
        success, inclusion = client.check_inclusion(result.get('receipt_hash'))
        
        if success:
            print("   [OK] Receipt is included in the log")
            print(f"   Merkle Root: {inclusion['proof'].get('merkle_root')}")
            print(f"   Tree Size: {inclusion['proof'].get('tree_size')}")
        else:
            print(f"   ! Could not verify inclusion: {inclusion}")
    else:
        print(f"   ! Failed to submit receipt: {result}")
    
    print("\n" + "=" * 60)
    print("Example complete!")
    print("To explore further:")
    print(f"- Check the log status: python check_log_status.py")
    print(f"- Start the log server: python start_log_server.py")
    print("=" * 60)

if __name__ == "__main__":
    # Add the cryptography imports here to avoid requiring them for the whole module
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    main()
