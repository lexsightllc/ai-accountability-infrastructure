#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""
Generate Ed25519 key pair for testing the AI Trust Verifier.

This script generates a new Ed25519 key pair and saves them to files.
The private key is saved in PEM format, and the public key is saved in both
PEM and base64-encoded formats.
"""

import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes

# Output directories
KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

# File paths
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PEM_PATH = os.path.join(KEYS_DIR, "public_key.pem")
PUBLIC_KEY_B64_PATH = os.path.join(KEYS_DIR, "public_key.b64")

print("Generating Ed25519 key pair...")

# Generate private key
private_key = ed25519.Ed25519PrivateKey.generate()

# Serialize private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Get public key
public_key = private_key.public_key()

# Serialize public key to PEM format
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Serialize public key to raw bytes and then base64
public_raw = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
public_b64 = base64.b64encode(public_raw).decode('ascii')

# Save keys to files
with open(PRIVATE_KEY_PATH, 'wb') as f:
    f.write(private_pem)
    print(f"Private key saved to: {PRIVATE_KEY_PATH}")

with open(PUBLIC_KEY_PEM_PATH, 'wb') as f:
    f.write(public_pem)
    print(f"Public key (PEM) saved to: {PUBLIC_KEY_PEM_PATH}")

with open(PUBLIC_KEY_B64_PATH, 'w') as f:
    f.write(public_b64)
    print(f"Public key (base64) saved to: {PUBLIC_KEY_B64_PATH}")

print("\nKey generation complete!")
print("\nIMPORTANT: Keep the private key secure and never commit it to version control!")
print("The private key is saved in an unencrypted format for testing purposes only.")
print("In production, use proper key management and never store unencrypted private keys on disk.")
