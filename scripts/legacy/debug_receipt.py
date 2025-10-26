import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from pydantic import AnyHttpUrl
from ai_trust.core.models import Receipt, ReceiptVersion, ModelInfo, OutputCommitment, Signature
from ai_trust.core.crypto import KeyPair, sign_receipt, verify_receipt
from ai_trust.core.canonicalization import canonicalize
import hashlib
import base64

def main():
    # Create a test receipt with all required fields
    test_commit_sha = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    test_body_hash = hashlib.sha256(b"test").hexdigest()
    
    print("Creating test receipt with:")
    print(f"- Execution ID: test-execution-123")
    print(f"- Issuer: https://example.com")
    print(f"- Model: gpt-4 v1.0 (commit: {test_commit_sha[:8]}...{test_commit_sha[-8:]})")
    print(f"- Body hash: {test_body_hash}")
    
    receipt = Receipt(
        receipt_version=ReceiptVersion.V1,
        execution_id="test-execution-123",
        issued_at=datetime.utcnow(),
        issuer=AnyHttpUrl("https://example.com"),
        model=ModelInfo(
            name="gpt-4",
            version="1.0",
            commit_sha256=test_commit_sha
        ),
        output=OutputCommitment(
            body_sha256=test_body_hash,
            content_type="text/plain"
        ),
        signature=None
    )
    
    # Generate a new key pair
    key_pair = KeyPair.generate("test-key")
    
    # Print the data that will be signed
    def serialize_for_json(obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        elif hasattr(obj, '__str__'):
            return str(obj)
        elif isinstance(obj, dict):
            return {k: serialize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [serialize_for_json(v) for v in obj]
        return obj
    
    receipt_dict = receipt.model_dump(exclude={"signature"}, exclude_unset=True, exclude_none=True)
    serialized_dict = serialize_for_json(receipt_dict)
    
    print("\nData to be signed:")
    print(json.dumps(serialized_dict, indent=2))
    
    canonical_data = canonicalize(receipt_dict)
    print("\nCanonical data to be signed:")
    print(canonical_data.decode('utf-8'))
    
    # Sign the receipt
    print("\nSigning the receipt...")
    try:
        # Get the data that will be signed
        receipt_dict = receipt.model_dump(exclude={"signature"}, exclude_unset=True, exclude_none=True)
        print("\nReceipt data being signed:")
        print(json.dumps(receipt_dict, indent=2, default=str))
        
        # Sign the receipt
        signature = sign_receipt(receipt, key_pair)
        print(f"\nGenerated signature (base64): {signature}")
    except Exception as e:
        print(f"Error during signing: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Add the signature to the receipt
    receipt.signature = Signature(
        alg="EdDSA",
        kid=key_pair.kid,
        sig=signature,
        issued_at=datetime.utcnow()
    )
    
    # Save the receipt and keys for inspection
    with open('debug_receipt.json', 'w') as f:
        json.dump(receipt.model_dump(), f, indent=2, default=str)
    
    with open('debug_keys.json', 'w') as f:
        json.dump({
            'kid': key_pair.kid,
            'public_key': key_pair.public_key.hex(),
            'private_key': key_pair.private_key.hex() if key_pair.private_key else None,
            'algorithm': key_pair.algorithm
        }, f, indent=2)
    
    # Verify the receipt with debug output
    is_valid = verify_receipt(receipt, key_pair.public_key, debug=True)
    print(f"\nReceipt is valid (via verify_receipt): {is_valid}")
    
    # Try verifying the signature directly with the key pair
    try:
        # Get the canonical data that was signed
        receipt_dict = receipt.model_dump(exclude={"signature"}, exclude_unset=True, exclude_none=True)
        for key, value in receipt_dict.items():
            if hasattr(value, 'isoformat'):
                receipt_dict[key] = value.isoformat()
            elif isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(v, 'isoformat'):
                        value[k] = v.isoformat()
        
        canonical_data = canonicalize(receipt_dict)
        
        # Decode the signature
        signature = base64.urlsafe_b64decode(receipt.signature.sig + '==='[:len(receipt.signature.sig) % 4])
        
        # Verify using the key pair directly
        key_pair.public_key_obj.verify(signature, canonical_data)
        print("Direct verification with key_pair.public_key_obj.verify() succeeded!")
        direct_verify = True
    except Exception as e:
        print(f"Direct verification failed: {e}")
        direct_verify = False
    
    print(f"\nReceipt is valid (direct verification): {direct_verify}")
    
    # Print the receipt data for inspection
    print("\nReceipt data:")
    print(json.dumps(receipt.model_dump(), indent=2, default=str))

if __name__ == "__main__":
    import hashlib  # Import here to avoid circular import
    main()
