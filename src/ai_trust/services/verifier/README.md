<!-- SPDX-License-Identifier: MPL-2.0 -->

# AI Receipt Verifier

The AI Receipt Verifier is a Python module for validating AI Trust receipts according to the AI Trust Standard v1.0.

## Features

- Validates receipt structure and required fields
- Verifies cryptographic signatures (Ed25519)
- Validates timestamps and hash formats
- Checks policy compliance
- Validates cost metrics
- Provides detailed error messages

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```python
from verifier import AIReceiptVerifier

# Create a verifier instance
verifier = AIReceiptVerifier(verbose=True)

# Verify a receipt (as JSON string)
with open('receipt.json', 'r') as f:
    receipt_json = f.read()

result = verifier.verify_receipt(receipt_json)

if result:
    print("Receipt is valid!")
    print(f"Details: {result.details}")
else:
    print(f"Receipt is invalid: {result.reason}")
```

### Verifying with a Public Key

```python
from verifier import load_public_key, AIReceiptVerifier

# Load public key
public_key = load_public_key('public_key.pem')

# Verify with public key
verifier = AIReceiptVerifier()
result = verifier.verify_receipt(receipt_json, public_key)

print(f"Signature verified: {result.details.get('signature_verified', False)}")
```

### Command Line Interface

```bash
# Basic verification
python -m verifier.verify path/to/receipt.json

# With public key
python -m verifier.verify path/to/receipt.json --pubkey path/to/public_key.pem

# Verbose output
python -m verifier.verify path/to/receipt.json --verbose
```

## API Reference

### `AIReceiptVerifier`

Main class for verifying AI accountability receipts.

#### `__init__(self, verbose: bool = False)`

Initialize the verifier.

- `verbose`: If True, enables verbose output during verification

#### `verify_receipt(self, receipt_json: str, public_key: Optional[ed25519.Ed25519PublicKey] = None) -> VerificationResult`

Verify an AI accountability receipt.

- `receipt_json`: JSON string of the receipt to verify
- `public_key`: Optional public key for signature verification
- Returns: `VerificationResult` object with validation results

### `VerificationResult`

Result of a verification operation.

#### Attributes

- `valid`: Boolean indicating if verification was successful
- `reason`: Human-readable message describing the result
- `details`: Dictionary with additional details about the verification

### Helper Functions

#### `load_public_key(key_path: str) -> ed25519.Ed25519PublicKey`

Load an Ed25519 public key from a file.

- `key_path`: Path to the public key file (PEM or base64-encoded)
- Returns: `Ed25519PublicKey` object
- Raises: `ValueError` if the key cannot be loaded

## Testing

Run the test suite with pytest:

```bash
pytest tests/test_verifier.py -v
```

## License

MIT
