import json
from ai_trust.core.crypto import verify_receipt, KeyPair
from ai_trust.core.models import Receipt

def main():
    # Load the receipt
    with open('final_receipt.json', 'r') as f:
        receipt_data = json.load(f)
    
    receipt = Receipt(**receipt_data)
    
    # Load the key pair
    with open('keys.json', 'r') as f:
        key_data = json.load(f)
    
    key_pair = KeyPair(
        kid=key_data['kid'],
        public_key=bytes.fromhex(key_data['public_key']),
        private_key=bytes.fromhex(key_data['private_key']) if 'private_key' in key_data else None,
        algorithm=key_data['algorithm']
    )
    
    # Verify the receipt
    is_valid = verify_receipt(receipt, key_pair.public_key)
    print(f"Receipt is valid: {is_valid}")
    
    # Print the receipt data for inspection
    print("\nReceipt data:")
    print(json.dumps(receipt.model_dump(), indent=2))

if __name__ == "__main__":
    main()
