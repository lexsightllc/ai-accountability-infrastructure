#!/usr/bin/env python3
"""
Submit a receipt to the AI Accountability Transparency Log.

This script helps users submit a receipt to a running transparency log server.
"""

import json
import sys
import requests
import argparse
from pathlib import Path
from urllib.parse import urljoin

def load_receipt(receipt_path: str) -> dict:
    """Load a receipt from a JSON file."""
    try:
        with open(receipt_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in receipt file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading receipt file: {e}", file=sys.stderr)
        sys.exit(1)

def submit_receipt(server_url: str, receipt: dict, verify_ssl: bool = True) -> dict:
    """Submit a receipt to the transparency log server."""
    url = urljoin(server_url, '/receipts')
    
    try:
        response = requests.post(
            url,
            json=receipt,
            headers={'Content-Type': 'application/json'},
            verify=verify_ssl
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error submitting receipt: {e}", file=sys.stderr)
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json()
                print(f"Server response: {json.dumps(error_details, indent=2)}", file=sys.stderr)
            except:
                print(f"Server response: {e.response.text}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Submit a receipt to the AI Accountability Transparency Log')
    parser.add_argument('receipt_file', help='Path to the receipt JSON file')
    parser.add_argument('--server', '-s', default='http://localhost:5000', 
                       help='URL of the transparency log server (default: http://localhost:5000)')
    parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl',
                       help='Disable SSL certificate verification')
    parser.add_argument('--output', '-o', help='Output file to save the response (optional)')
    
    args = parser.parse_args()
    
    # Load the receipt
    receipt = load_receipt(args.receipt_file)
    
    print(f"Submitting receipt to {args.server}...")
    
    # Submit the receipt
    try:
        result = submit_receipt(args.server, receipt, args.verify_ssl)
        
        # Print the result
        print("\nReceipt submitted successfully!")
        print(f"  Index:        {result.get('index')}")
        print(f"  Receipt hash: {result.get('receipt_hash')}")
        print(f"  Merkle root:  {result.get('merkle_root')}")
        print(f"  Timestamp:    {result.get('timestamp')}")
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\nResponse saved to: {args.output}")
        
        return 0
    except Exception as e:
        print(f"Failed to submit receipt: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
