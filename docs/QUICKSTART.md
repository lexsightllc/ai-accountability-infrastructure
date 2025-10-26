<!-- SPDX-License-Identifier: MPL-2.0 -->

# AI Trust - Quick Start Guide

This guide will help you get started with the AI Trust project quickly.

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/ai-accountability.git
   cd ai-accountability
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .[dev]
   ```

## Generate Sample Keys

1. Generate a key pair for testing:
   ```bash
   python tools/generate_keys.py
   ```

   This will create a `keys` directory with the generated keys.

## Generate a Sample Receipt

1. Generate a sample receipt (unsigned):
   ```bash
   python tools/generate_receipt.py -o examples/sample_receipt.json
   ```

2. (Optional) Generate a signed receipt:
   ```bash
   python tools/generate_receipt.py --sign --key keys/private_key.pem -o examples/signed_receipt.json
   ```

## Verify a Receipt

1. Verify a receipt:
   ```bash
   python tools/verify_receipt.py examples/sample_receipt.json
   ```

2. Verify a signed receipt with a public key:
   ```bash
   python tools/verify_receipt.py examples/signed_receipt.json --public-key keys/public_key.pem
   ```

## Run the Transparency Log Server

1. Start the server:
   ```bash
   python start_log_server.py
   ```

   The server will start on `http://localhost:5000` by default.

2. In a new terminal, submit a receipt to the log:
   ```bash
   python submit_receipt.py examples/signed_receipt.json
   ```

3. View the receipt in the log:
   ```
   # Get receipt by index
   curl http://localhost:5000/receipts/0
   
   # Get inclusion proof
   curl http://localhost:5000/proofs/0
   
   # Get Merkle root
   curl http://localhost:5000/tree/root
   ```

## Run Tests

Run the test suite:

```bash
pytest
```

## Next Steps

- Read the full documentation in the `docs/` directory
- Explore the example implementations
- Contribute to the project by following the [CONTRIBUTING.md](CONTRIBUTING.md) guide

## Need Help?

If you have any questions or run into issues, please [open an issue](https://github.com/your-username/ai-accountability/issues) on GitHub.
