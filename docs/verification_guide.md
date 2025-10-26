<!-- SPDX-License-Identifier: MPL-2.0 -->

# AI Trust Verification Guide

This guide provides comprehensive documentation for the AI Trust verification system, including usage examples, API reference, and best practices.

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Core Concepts](#core-concepts)
5. [API Reference](#api-reference)
6. [Examples](#examples)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)
9. [Performance](#performance)
10. [Contributing](#contributing)

## Overview

The AI Trust verification system provides tools for:
- Verifying digital signatures on accountability receipts
- Validating receipt structure and content
- Verifying inclusion in the transparency log
- Generating and verifying consistency proofs

## Installation

```bash
# Install from source
git clone https://github.com/yourorg/ai-accountability.git
cd ai-accountability
pip install -e .

# Or install with pip
pip install ai-accountability
```

## Quick Start

### Verifying a Receipt

```python
from ai_trust.core.verification import verify_receipt_file

# Verify a receipt file
result = verify_receipt_file(
    file_path="receipt.json",
    db_path="transparency_log.db",
    public_key_path="public_key.pem"
)

print(f"Verification successful: {result.is_valid}")
if not result.is_valid:
    print("Errors:", result.errors)
```

### Using the CLI

```bash
# Verify a receipt
ai-trust verify receipt receipt.json --db transparency_log.db --public-key public_key.pem

# Generate an inclusion proof
ai-trust verify inclusion RECEIPT_ID --db transparency_log.db

# Generate a consistency proof
ai-trust verify consistency 1000 --db transparency_log.db --second-size 2000
```

## Core Concepts

### Receipt Structure

A valid receipt contains:
- `receipt_id`: Unique identifier
- `timestamp`: ISO 8601 timestamp
- `data`: The actual receipt data
- `signature`: Digital signature
- `inclusion_proof` (optional): Proof of inclusion in the Merkle tree

### Verification Process

1. **Signature Verification**: Validates the digital signature
2. **Structural Validation**: Checks required fields and data types
3. **Inclusion Verification**: Verifies the receipt is included in the log
4. **Consistency Verification**: Ensures log consistency over time

## API Reference

### `ReceiptVerifier` Class

```python
class ReceiptVerifier:
    def __init__(self, db: LogDB, public_key: Optional[PublicKey] = None):
        """Initialize with a database and optional public key."""
        pass
    
    def verify_receipt(
        self, 
        receipt_data: Union[Dict[str, Any], str, bytes],
        verify_signature: bool = True,
        verify_inclusion: bool = True
    ) -> VerificationResult:
        """Verify a receipt's signature and inclusion."""
        pass
    
    def get_inclusion_proof(
        self,
        receipt_id: str,
        tree_size: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """Get an inclusion proof for a receipt."""
        pass
    
    def get_consistency_proof(
        self,
        first_size: int,
        second_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get a consistency proof between two tree states."""
        pass
```

### `VerificationResult` Class

```python
@dataclass
class VerificationResult:
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    receipt: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
```

## Examples

### Basic Verification

```python
from ai_trust.core.verification import ReceiptVerifier
from ai_trust.core.db import LogDB

# Initialize verifier
db = LogDB("transparency_log.db")
verifier = ReceiptVerifier(db)

# Verify a receipt
result = verifier.verify_receipt({
    "receipt_id": "test-123",
    "timestamp": "2023-01-01T00:00:00Z",
    "data": {"key": "value"},
    "signature": "..."
})

print(result.is_valid)
```

### Batch Verification

```python
import json
from concurrent.futures import ThreadPoolExecutor

def verify_receipt_file(file_path: str):
    with open(file_path) as f:
        receipt = json.load(f)
    result = verifier.verify_receipt(receipt)
    return file_path, result

# Verify multiple receipts in parallel
with ThreadPoolExecutor() as executor:
    results = list(executor.map(verify_receipt_file, receipt_files))

for file_path, result in results:
    print(f"{file_path}: {'✓' if result.is_valid else '✗'}")
```

## Security Considerations

### Key Management

- Store private keys securely using hardware security modules (HSMs) or key management services
- Rotate keys periodically
- Use strong key sizes (at least 2048 bits for RSA, 256 bits for Ed25519)

### Input Validation

- Always validate receipt data before processing
- Be cautious with large inputs that could cause denial of service
- Sanitize any data before displaying it to users

### Log Verification

- Regularly verify the consistency of the transparency log
- Monitor for unexpected changes in the log
- Keep historical root hashes for audit purposes

## Performance

### Optimizing Verification

- Cache verification results when appropriate
- Use batch verification for multiple receipts
- Consider using a faster hash function for non-security critical operations

### Memory Usage

- Process large receipts as streams when possible
- Use generators for large result sets
- Monitor memory usage in production

## Troubleshooting

### Common Issues

1. **Invalid Signature**
   - Verify the public key matches the private key used for signing
   - Check that the receipt data hasn't been modified
   - Ensure timestamps are in the correct format

2. **Missing Receipt**
   - Verify the receipt ID is correct
   - Check if the receipt was added to the log
   - Ensure you're querying the correct database

3. **Proof Verification Failure**
   - Verify the tree size matches when the proof was generated
   - Check for database corruption
   - Ensure the Merkle tree implementation is consistent

## Contributing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run performance tests
pytest tests/performance/ -v

# Run with coverage
pytest --cov=ai_trust tests/
```

### Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for all public APIs
- Include tests for new features

## License

[Your License Here]

---

For more information, see the [full documentation](https://github.com/yourorg/ai-accountability/docs).
