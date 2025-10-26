#!/usr/bin/env python3
"""
Check the status of an AI Accountability Transparency Log.

This script queries a transparency log server to check its status,
including the current Merkle root, tree size, and recent entries.
"""

import argparse
import json
import sys
import requests
from urllib.parse import urljoin

def get_log_status(server_url: str, verify_ssl: bool = True) -> dict:
    """Get the status of a transparency log server.
    
    Args:
        server_url: Base URL of the transparency log server
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Dictionary containing the server status
    """
    endpoints = {
        'health': '/health',
        'tree_root': '/tree/root',
        'tree_size': '/tree/size',
        'latest_receipts': '/receipts?limit=5',
    }
    
    status = {}
    
    for name, endpoint in endpoints.items():
        url = urljoin(server_url, endpoint)
        try:
            response = requests.get(url, verify=verify_ssl)
            response.raise_for_status()
            
            # Special handling for the health endpoint
            if name == 'health':
                status['status'] = response.json().get('status', 'unknown')
                status['timestamp'] = response.json().get('timestamp')
            # Special handling for the latest receipts
            elif name == 'latest_receipts':
                status['latest_receipts'] = response.json()
            else:
                status[name] = response.json()
                
        except requests.exceptions.RequestException as e:
            print(f"Error querying {url}: {e}", file=sys.stderr)
            status[name] = {'error': str(e)}
    
    return status

def format_status(status: dict) -> str:
    """Format the status information for display."""
    output = []
    
    # Basic status
    output.append("=" * 60)
    output.append("AI Accountability Transparency Log Status")
    output.append("=" * 60)
    
    # Health status
    health_status = status.get('status', {}).get('status', 'unknown')
    health_indicator = "[OK]" if health_status == 'healthy' else "[ERROR]"
    output.append(f"{health_indicator} Status: {health_status.upper()}")
    
    # Timestamp
    timestamp = status.get('status', {}).get('timestamp')
    if timestamp:
        output.append(f"[TIME] Last Updated: {timestamp}")
    
    # Tree info
    tree_root = status.get('tree_root', {}).get('root_hash', 'N/A')
    tree_size = status.get('tree_size', {}).get('tree_size', 0)
    output.append(f"[TREE] Merkle Tree: {tree_size} entries")
    output.append(f"   Root Hash: {tree_root[:16]}...{tree_root[-16:] if tree_root else ''}")
    
    # Latest receipts
    latest_receipts = status.get('latest_receipts', [])
    if latest_receipts and isinstance(latest_receipts, list):
        output.append("\n[RECEIPTS] Latest Receipts:")
        for i, receipt in enumerate(latest_receipts[:5], 1):
            receipt_id = receipt.get('index', 'N/A')
            receipt_hash = receipt.get('receipt_hash', 'N/A')
            timestamp = receipt.get('timestamp', 'N/A')
            
            # Truncate the hash for display
            short_hash = f"{receipt_hash[:8]}...{receipt_hash[-6:]}" if len(receipt_hash) > 16 else receipt_hash
            
            output.append(f"   {i}. #{receipt_id}: {short_hash} @ {timestamp}")
    
    # Errors
    errors = [f"Error querying {k}: {v['error']}" for k, v in status.items() 
              if isinstance(v, dict) and 'error' in v]
    if errors:
        output.append("\n[ERROR] Errors:")
        output.extend(f"   • {error}" for error in errors)
    
    output.append("=" * 60)
    return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(description='Check the status of an AI Accountability Transparency Log')
    parser.add_argument('--server', '-s', default='http://localhost:5000',
                      help='URL of the transparency log server (default: http://localhost:5000)')
    parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl',
                      help='Disable SSL certificate verification')
    parser.add_argument('--json', '-j', action='store_true',
                      help='Output raw JSON instead of formatted text')
    
    args = parser.parse_args()
    
    try:
        # Get the status from the server
        status = get_log_status(args.server, args.verify_ssl)
        
        # Output the results
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print(format_status(status))
        
        # Exit with non-zero status if there were errors
        if any('error' in v for v in status.values() if isinstance(v, dict)):
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
