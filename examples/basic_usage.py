# SPDX-License-Identifier: MPL-2.0
"""Basic usage example for AI Trust."""
from ai_trust import create_receipt, verify_receipt
from ai_trust.core import KeyPair


def main() -> None:
    # Example data
    data = {
        "model": "gpt-4",
        "input": "Hello, world!",
        "output": "Hello! How can I help you today?",
        "timestamp": "2023-09-01T12:00:00Z",
    }

    key_pair = KeyPair.generate()

    # Create a receipt
    receipt = create_receipt(data, key_pair)
    print(f"Created receipt: {receipt.id}")

    # Verify the receipt
    is_valid = verify_receipt(receipt, key_pair.public_bytes())
    print(f"Receipt is valid: {is_valid}")


if __name__ == "__main__":
    main()
