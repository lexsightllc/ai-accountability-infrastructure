#!/usr/bin/env python3
"""
Check the status of an AI Accountability Transparency Log.

This script provides a command-line interface to check the status of a transparency log,
including information about the Merkle tree, recent receipts, and server health.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, Any, Optional, List

import requests
from urllib.parse import urljoin

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class LogChecker:
    """Client for checking the status of a transparency log."""
    
    def __init__(self, base_url: str, verify_ssl: bool = True):
        """Initialize the LogChecker with the base URL of the transparency log server."""
        self.base_url = base_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
    
    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """Make a GET request to the specified endpoint."""
        url = urljoin(f"{self.base_url}/", endpoint.lstrip('/'))
        try:
            response = self.session.get(url, verify=self.verify_ssl, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "status_code": getattr(e.response, 'status_code', None)}
    
    def get_health(self) -> Dict[str, Any]:
        """Get the health status of the server."""
        return self._make_request("/health")
    
    def get_tree_root(self) -> Dict[str, Any]:
        """Get the current Merkle tree root."""
        return self._make_request("/tree/root")
    
    def get_tree_size(self) -> Dict[str, Any]:
        """Get the current size of the Merkle tree."""
        return self._make_request("/tree/size")
    
    def get_receipt(self, receipt_id: str) -> Dict[str, Any]:
        """Get a receipt by its ID or hash."""
        return self._make_request(f"/receipts/{receipt_id}")
    
    def get_inclusion_proof(self, receipt_id: str) -> Dict[str, Any]:
        """Get the inclusion proof for a receipt."""
        return self._make_request(f"/proofs/{receipt_id}")
    
    def get_latest_receipts(self, limit: int = 10) -> Dict[str, Any]:
        """Get the most recent receipts."""
        return self._make_request(f"/receipts?limit={limit}")

def format_timestamp(timestamp: str) -> str:
    """Format a timestamp for display."""
    try:
        # Try to parse ISO 8601 format
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except (ValueError, TypeError):
        return str(timestamp)

def print_health(health_data: Dict[str, Any]) -> None:
    """Print the health status of the server."""
    status = health_data.get('status', 'unknown').upper()
    color = Colors.OKGREEN if status == 'HEALTHY' else Colors.FAIL
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}Server Health{Colors.ENDC}")
    print(f"{'Status:':<15} {color}{status}{Colors.ENDC}")
    
    if 'timestamp' in health_data:
        print(f"{'Timestamp:':<15} {format_timestamp(health_data['timestamp'])}")
    
    if 'version' in health_data:
        print(f"{'Version:':<15} {health_data['version']}")
    
    if 'tree_size' in health_data:
        print(f"{'Tree Size:':<15} {health_data['tree_size']} receipts")
    
    if 'merkle_root' in health_data:
        root = health_data['merkle_root']
        short_root = f"{root[:8]}...{root[-8:]}" if len(root) > 20 else root
        print(f"{'Merkle Root:':<15} {short_root}")
    
    if 'error' in health_data:
        print(f"{Colors.WARNING}Error: {health_data['error']}{Colors.ENDC}")

def print_tree_info(tree_data: Dict[str, Any]) -> None:
    """Print information about the Merkle tree."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}Merkle Tree{Colors.ENDC}")
    
    if 'tree_size' in tree_data:
        print(f"{'Size:':<15} {tree_data['tree_size']} receipts")
    
    if 'root_hash' in tree_data:
        root = tree_data['root_hash']
        short_root = f"{root[:8]}...{root[-8:]}" if len(root) > 20 else root
        print(f"{'Root Hash:':<15} {short_root}")
    
    if 'timestamp' in tree_data:
        print(f"{'Last Updated:':<15} {format_timestamp(tree_data['timestamp'])}")
    
    if 'error' in tree_data:
        print(f"{Colors.WARNING}Error: {tree_data['error']}{Colors.ENDC}")

def print_receipt(receipt_data: Dict[str, Any], show_details: bool = False) -> None:
    """Print information about a receipt."""
    if 'error' in receipt_data:
        print(f"{Colors.FAIL}Error: {receipt_data['error']}{Colors.ENDC}")
        if 'status_code' in receipt_data:
            print(f"Status Code: {receipt_data['status_code']}")
        return
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}Receipt Details{Colors.ENDC}")
    
    # Basic receipt info
    if 'index' in receipt_data:
        print(f"{'Index:':<15} {receipt_data['index']}")
    
    if 'receipt_hash' in receipt_data:
        receipt_hash = receipt_data['receipt_hash']
        short_hash = f"{receipt_hash[:8]}...{receipt_hash[-8:]}" if len(receipt_hash) > 20 else receipt_hash
        print(f"{'Hash:':<15} {short_hash}")
    
    if 'timestamp' in receipt_data:
        print(f"{'Timestamp:':<15} {format_timestamp(receipt_data['timestamp'])}")
    
    # Show more details if requested
    if show_details and 'receipt' in receipt_data:
        receipt = receipt_data['receipt']
        print(f"\n{Colors.UNDERLINE}Receipt Contents:{Colors.ENDC}")
        
        if 'task_description' in receipt:
            print(f"\n{Colors.BOLD}Task:{Colors.ENDC}")
            print(f"  {receipt['task_description']}")
        
        if 'model_name' in receipt:
            print(f"\n{Colors.BOLD}Model:{Colors.ENDC}")
            print(f"  {receipt.get('model_name', 'N/A')} (v{receipt.get('model_version', '?')})")
        
        if 'policies' in receipt:
            print(f"\n{Colors.BOLD}Policies:{Colors.ENDC}")
            policies = receipt['policies']
            
            if 'satisfied' in policies and policies['satisfied']:
                print(f"  {Colors.OKGREEN}[OK] Satisfied:{Colors.ENDC}")
                for policy in policies['satisfied']:
                    print(f"    - {policy}")
            
            if 'relaxed' in policies and policies['relaxed']:
                print(f"  {Colors.WARNING}[!] Relaxed:{Colors.ENDC}")
                for policy in policies['relaxed']:
                    print(f"    - {policy}")
        
        if 'costs' in receipt:
            print(f"\n{Colors.BOLD}Costs:{Colors.ENDC}")
            costs = receipt['costs']
            for key, value in costs.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
        
        if 'attestation' in receipt and receipt['attestation']:
            print(f"\n{Colors.BOLD}Attestation:{Colors.ENDC}")
            attestation = receipt['attestation']
            
            if 'pubkey_id' in attestation:
                print(f"  Public Key ID: {attestation['pubkey_id']}")
            
            if 'signature' in attestation and attestation['signature']:
                sig = attestation['signature']
                if ':' in sig:
                    sig_type, sig_value = sig.split(':', 1)
                    short_sig = f"{sig_value[:8]}...{sig_value[-8:]}" if len(sig_value) > 20 else sig_value
                    print(f"  Signature: {sig_type.upper()}:{short_sig}")
                else:
                    print(f"  Signature: {sig}")

def print_inclusion_proof(proof_data: Dict[str, Any]) -> None:
    """Print the inclusion proof for a receipt."""
    if 'error' in proof_data:
        print(f"{Colors.FAIL}Error: {proof_data['error']}{Colors.ENDC}")
        if 'status_code' in proof_data:
            print(f"Status Code: {proof_data['status_code']}")
        return
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}Inclusion Proof{Colors.ENDC}")
    
    if 'index' in proof_data:
        print(f"{'Index:':<15} {proof_data['index']}")
    
    if 'tree_size' in proof_data:
        print(f"{'Tree Size:':<15} {proof_data['tree_size']} receipts")
    
    if 'leaf_hash' in proof_data:
        leaf_hash = proof_data['leaf_hash']
        short_hash = f"{leaf_hash[:8]}...{leaf_hash[-8:]}" if len(leaf_hash) > 20 else leaf_hash
        print(f"{'Leaf Hash:':<15} {short_hash}")
    
    if 'merkle_root' in proof_data:
        root = proof_data['merkle_root']
        short_root = f"{root[:8]}...{root[-8:]}" if len(root) > 20 else root
        print(f"{'Merkle Root:':<15} {short_root}")
    
    if 'audit_path' in proof_data and proof_data['audit_path']:
        print(f"\n{Colors.UNDERLINE}Audit Path:{Colors.ENDC}")
        for i, node in enumerate(proof_data['audit_path']):
            short_node = f"{node[:8]}...{node[-8:]}" if len(node) > 20 else node
            print(f"  [{i}] {short_node}")
    
    if 'verified' in proof_data:
        status = "Valid" if proof_data['verified'] else "Invalid"
        color = Colors.OKGREEN if proof_data['verified'] else Colors.FAIL
        print(f"\n{color}Proof Verification: {status}{Colors.ENDC}")

def print_latest_receipts(receipts_data: Dict[str, Any], limit: int = 10) -> None:
    """Print a list of the most recent receipts."""
    if 'error' in receipts_data:
        print(f"{Colors.FAIL}Error: {receipts_data['error']}{Colors.ENDC}")
        if 'status_code' in receipts_data:
            print(f"Status Code: {receipts_data['status_code']}")
        return
    
    if not isinstance(receipts_data, list):
        print(f"{Colors.WARNING}Unexpected response format for latest receipts{Colors.ENDC}")
        return
    
    if not receipts_data:
        print(f"{Colors.WARNING}No receipts found in the log{Colors.ENDC}")
        return
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}Latest {min(limit, len(receipts_data))} Receipts{Colors.ENDC}\n")
    
    # Print table header
    print(f"{'Index':<8} {'Timestamp':<25} {'Task'}")
    print("-" * 60)
    
    # Print each receipt
    for receipt in receipts_data[:limit]:
        index = receipt.get('index', 'N/A')
        timestamp = format_timestamp(receipt.get('timestamp', 'N/A'))
        
        # Try to get the task description from the receipt
        task_desc = 'N/A'
        if 'receipt' in receipt and isinstance(receipt['receipt'], dict):
            task_desc = receipt['receipt'].get('task_description', 'N/A')
        
        # Truncate long task descriptions
        if len(task_desc) > 40:
            task_desc = task_desc[:37] + '...'
        
        print(f"{index:<8} {timestamp:<25} {task_desc}")

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Check the status of an AI Accountability Transparency Log')
    parser.add_argument('--url', default='http://localhost:5000',
                      help='Base URL of the transparency log server (default: http://localhost:5000)')
    parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl',
                      help='Disable SSL certificate verification')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Health check command
    health_parser = subparsers.add_parser('health', help='Check server health')
    
    # Tree info command
    tree_parser = subparsers.add_parser('tree', help='Get Merkle tree information')
    
    # Receipt command
    receipt_parser = subparsers.add_parser('receipt', help='Get receipt information')
    receipt_parser.add_argument('receipt_id', help='Receipt ID or hash')
    receipt_parser.add_argument('--details', action='store_true', help='Show detailed receipt information')
    
    # Proof command
    proof_parser = subparsers.add_parser('proof', help='Get inclusion proof for a receipt')
    proof_parser.add_argument('receipt_id', help='Receipt ID or hash')
    
    # Latest command
    latest_parser = subparsers.add_parser('latest', help='Get latest receipts')
    latest_parser.add_argument('--limit', type=int, default=10, help='Maximum number of receipts to show (default: 10)')
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    args = parser.parse_args()
    
    # Create a client
    checker = LogChecker(args.url, args.verify_ssl)
    
    # Execute the appropriate command
    if args.command == 'health':
        health_data = checker.get_health()
        print_health(health_data)
    
    elif args.command == 'tree':
        tree_data = checker.get_tree_root()
        print_tree_info(tree_data)
    
    elif args.command == 'receipt':
        receipt_data = checker.get_receipt(args.receipt_id)
        print_receipt(receipt_data, args.details)
    
    elif args.command == 'proof':
        proof_data = checker.get_inclusion_proof(args.receipt_id)
        print_inclusion_proof(proof_data)
    
    elif args.command == 'latest':
        receipts_data = checker.get_latest_receipts(args.limit)
        print_latest_receipts(receipts_data, args.limit)
    
    else:
        # Default action: show server status
        health_data = checker.get_health()
        print_health(health_data)
        
        if 'error' not in health_data:
            # If health check passed, show tree info and latest receipts
            tree_data = checker.get_tree_root()
            print_tree_info(tree_data)
            
            receipts_data = checker.get_latest_receipts(5)
            print_latest_receipts(receipts_data, 5)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
