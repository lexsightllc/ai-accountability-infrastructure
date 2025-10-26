#!/usr/bin/env python3
"""
Generate test keys for AI Accountability system.

This script generates a set of test keys that can be used for development
and testing of the AI Accountability system. It creates both Ed25519 and RSA
key pairs in various formats.
"""

import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def generate_ed25519_keypair():
    """Generate an Ed25519 key pair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_rsa_keypair():
    """Generate an RSA key pair (2048 bits)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_file(key, file_path, format, is_private=True, password=None):
    """Save a key to a file in the specified format."""
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    if format == 'pem':
        if is_private:
            if isinstance(key, ed25519.Ed25519PrivateKey):
                key_bytes = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            else:  # RSA
                key_bytes = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=(
                        serialization.BestAvailableEncryption(password.encode())
                        if password
                        else serialization.NoEncryption()
                    )
                )
        else:  # public key
            key_bytes = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    elif format == 'der':
        if is_private:
            key_bytes = key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:  # public key
            key_bytes = key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    elif format == 'raw':
        if is_private:
            if isinstance(key, ed25519.Ed25519PrivateKey):
                key_bytes = key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            else:  # RSA private key in raw format is not recommended
                raise ValueError("Raw format not supported for RSA private keys")
        else:  # public key
            if isinstance(key, ed25519.Ed25519PublicKey):
                key_bytes = key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:  # RSA public key
                key_bytes = key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.PKCS1
                )
    else:
        raise ValueError(f"Unsupported format: {format}")
    
    with open(file_path, 'wb') as f:
        f.write(key_bytes)
    
    return key_bytes

def main():
    """Generate and save test keys."""
    # Create output directory
    keys_dir = Path("test_keys")
    keys_dir.mkdir(exist_ok=True)
    
    print(f"Generating test keys in {keys_dir.absolute()}")
    
    # Generate Ed25519 keys
    print("\nGenerating Ed25519 keys...")
    ed_private, ed_public = generate_ed25519_keypair()
    
    # Save Ed25519 keys in various formats
    save_key_to_file(ed_private, keys_dir / "ed25519_private.pem", 'pem')
    save_key_to_file(ed_public, keys_dir / "ed25519_public.pem", 'pem', is_private=False)
    save_key_to_file(ed_private, keys_dir / "ed25519_private.der", 'der')
    save_key_to_file(ed_public, keys_dir / "ed25519_public.der", 'der', is_private=False)
    save_key_to_file(ed_private, keys_dir / "ed25519_private.raw", 'raw')
    save_key_to_file(ed_public, keys_dir / "ed25519_public.raw", 'raw', is_private=False)
    
    # Generate RSA keys
    print("Generating RSA keys...")
    rsa_private, rsa_public = generate_rsa_keypair()
    
    # Save RSA keys in various formats
    save_key_to_file(rsa_private, keys_dir / "rsa_private.pem", 'pem')
    save_key_to_file(rsa_public, keys_dir / "rsa_public.pem", 'pem', is_private=False)
    save_key_to_file(rsa_private, keys_dir / "rsa_private.der", 'der')
    save_key_to_file(rsa_public, keys_dir / "rsa_public.der", 'der', is_private=False)
    
    # Create a README file with usage examples
    readme_content = """# Test Keys for AI Accountability

This directory contains test keys for use with the AI Accountability system.

## Key Files

### Ed25519 Keys
- `ed25519_private.pem` - Private key in PEM format
- `ed25519_public.pem` - Public key in PEM format
- `ed25519_private.der` - Private key in DER format
- `ed25519_public.der` - Public key in DER format
- `ed25519_private.raw` - Raw private key (32 bytes)
- `ed25519_public.raw` - Raw public key (32 bytes)

### RSA Keys (2048-bit)
- `rsa_private.pem` - Private key in PEM format
- `rsa_public.pem` - Public key in PEM format
- `rsa_private.der` - Private key in DER format
- `rsa_public.der` - Public key in DER format

## Usage Examples

### Load a PEM private key
```python
from cryptography.hazmat.primitives import serialization

with open("ed25519_private.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )
```

### Load a PEM public key
```python
with open("ed25519_public.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read()
    )
```

### Load a raw Ed25519 private key
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

with open("ed25519_private.raw", "rb") as key_file:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
        key_file.read()
    )
```

## Security Note

These keys are for testing purposes only. Never use these keys in production.
Generate new, secure keys for production use.
"""
    
    with open(keys_dir / "README.md", 'w') as f:
        f.write(readme_content)
    
    print("\nTest keys generated successfully!")
    print(f"Keys saved to: {keys_dir.absolute()}")
    print("\nFor usage examples, see the README.md file in the keys directory.")
    print("\nWARNING: These keys are for testing only. Do not use in production!")

if __name__ == "__main__":
    main()
