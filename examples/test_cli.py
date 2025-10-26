# SPDX-License-Identifier: MPL-2.0
"""
Test script for the AI Trust CLI.

This script demonstrates how to use the CLI to generate keys, sign a receipt, and verify it.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

def run_command(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    print(f"$ {cmd}")
    result = subprocess.run(
        cmd,
        shell=True,
        check=check,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
    elif result.stdout.strip():
        print(result.stdout)
    return result

def main():
    """Test the AI Trust CLI."""
    # Create a temporary directory for test files
    test_dir = Path("test_data")
    test_dir.mkdir(exist_ok=True)
    
    # Paths for test files
    key_file = test_dir / "test_key.json"
    receipt_file = test_dir / "receipt.json"
    
    try:
        # 1. Generate a new key pair
        print("\n=== Generating a new key pair ===")
        run_command(f"python -m ai_trust keys generate --output {key_file} --kid test-key-1")
        
        # 2. Show key information
        print("\n=== Showing key information ===")
        run_command(f"python -m ai_trust keys show {key_file}")
        
        # 3. Create a test receipt
        print("\n=== Creating a test receipt ===")
        with open(test_dir / "output.txt", "w") as f:
            f.write("This is a test output from an AI model.")
        
        run_command(
            f"python -m ai_trust receipt sign "
            f"--key {key_file} "
            f"--output {receipt_file} "
            f"--issuer https://example.com "
            f"--model test-model "
            f"--model-version 1.0 "
            f"--body {test_dir}/output.txt"
        )
        
        # 4. Verify the receipt
        print("\n=== Verifying the receipt ===")
        run_command(f"python -m ai_trust receipt verify {receipt_file}")
        
        # 5. Show the receipt contents
        print("\n=== Receipt contents ===")
        with open(receipt_file, 'r') as f:
            receipt_data = json.load(f)
            print(json.dumps(receipt_data, indent=2))
        
        print("\n[SUCCESS] All tests passed!")
        
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Test failed with error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Clean up
        print("\nCleaning up test files...")
        for f in test_dir.glob("*"):
            try:
                if f.is_file():
                    f.unlink()
            except Exception as e:
                print(f"Warning: Could not delete {f}: {e}")
        
        try:
            test_dir.rmdir()
        except Exception as e:
            print(f"Warning: Could not remove directory {test_dir}: {e}")

if __name__ == "__main__":
    main()
