# SPDX-License-Identifier: MPL-2.0
"""
CLI Commands for Verifying Receipts

This module provides command-line interface for verifying AI accountability receipts
and checking their inclusion in the transparency log.
"""

import json
import click
from pathlib import Path
from typing import Optional

from ..core.verification import ReceiptVerifier, verify_receipt_file, VerificationResult
from ..core.db import LogDB

# Click command group
@click.group()
def verify():
    """Verify AI accountability receipts and check inclusion in the transparency log."""
    pass

@verify.command()
@click.argument('receipt_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--db', '-d', 'db_path', type=click.Path(exists=True, file_okay=True, dir_okay=False),
              help='Path to the transparency log database')
@click.option('--public-key', '-k', 'public_key_path', type=click.Path(exists=True, dir_okay=False),
              help='Path to the public key for signature verification')
@click.option('--no-signature', is_flag=True, help='Skip signature verification')
@click.option('--no-inclusion', is_flag=True, help='Skip inclusion proof verification')
@click.option('--output', '-o', type=click.Choice(['text', 'json', 'compact']), 
              default='text', help='Output format')
def receipt(receipt_file: str, db_path: Optional[str], public_key_path: Optional[str], 
           no_signature: bool, no_inclusion: bool, output: str):
    """Verify a receipt file."""
    # Set verification flags
    verify_sig = not no_signature
    verify_inc = not no_inclusion
    
    # If we need to verify inclusion, we need a database
    if verify_inc and not db_path:
        click.echo("Error: Database path is required for inclusion verification", err=True)
        return 1
    
    # If we need to verify signatures, we need a public key
    if verify_sig and not public_key_path:
        click.echo("Warning: No public key provided, signature verification will be skipped", err=True)
        verify_sig = False
    
    # Perform verification
    result = verify_receipt_file(
        file_path=receipt_file,
        db_path=db_path,
        public_key_path=public_key_path,
        verify_signature=verify_sig,
        verify_inclusion=verify_inc
    )
    
    # Output the result
    if output == 'json':
        click.echo(result.to_json())
    else:
        if output == 'text':
            click.echo(f"Receipt: {receipt_file}")
            click.echo(f"Status: {'✓ VALID' if result.is_valid else '✗ INVALID'}")
            
            if result.warnings:
                click.echo("\nWarnings:")
                for warning in result.warnings:
                    click.echo(f"  ⚠ {warning}")
            
            if result.errors:
                click.echo("\nErrors:")
                for error in result.errors:
                    click.echo(f"  ✗ {error}")
            
            if 'receipt_id' in result.receipt:
                click.echo("\nReceipt ID:")
                click.echo(f"  {result.receipt['receipt_id']}")
            
            if 'timestamp' in result.receipt:
                click.echo("\nTimestamp:")
                click.echo(f"  {result.receipt['timestamp']}")
                
        else:  # compact
            status = "VALID" if result.is_valid else "INVALID"
            if result.errors:
                status += f" ({len(result.errors)} errors)"
            if result.warnings:
                status += f" ({len(result.warnings)} warnings)"
            
            receipt_id = result.receipt.get('receipt_id', 'unknown')
            click.echo(f"{receipt_id}: {status}")
    
    return 0 if result.is_valid else 1

@verify.command()
@click.argument('receipt_id')
@click.argument('db_path', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option('--tree-size', '-s', type=int, help='Tree size for the proof (default: current size)')
@click.option('--output', '-o', type=click.Path(), help='Output file for the proof (default: stdout)')
def inclusion(receipt_id: str, db_path: str, tree_size: Optional[int], output: Optional[str]):
    """Generate an inclusion proof for a receipt."""
    try:
        db = LogDB(db_path)
        verifier = ReceiptVerifier(db)
        
        proof = verifier.get_inclusion_proof(receipt_id, tree_size)
        if not proof:
            click.echo(f"No receipt found with ID: {receipt_id}", err=True)
            return 1
        
        proof_json = json.dumps(proof, indent=2, default=str)
        
        if output:
            with open(output, 'w') as f:
                f.write(proof_json)
            click.echo(f"Inclusion proof saved to {output}")
        else:
            click.echo(proof_json)
            
        return 0
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return 1

@verify.command()
@click.argument('first_size', type=int)
@click.argument('db_path', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option('--second-size', '-s', type=int, help='Second tree size (default: current size)')
@click.option('--output', '-o', type=click.Path(), help='Output file for the proof (default: stdout)')
def consistency(first_size: int, db_path: str, second_size: Optional[int], output: Optional[str]):
    """Generate a consistency proof between two tree states."""
    try:
        db = LogDB(db_path)
        verifier = ReceiptVerifier(db)
        
        proof = verifier.get_consistency_proof(first_size, second_size)
        
        proof_json = json.dumps(proof, indent=2, default=str)
        
        if output:
            with open(output, 'w') as f:
                f.write(proof_json)
            click.echo(f"Consistency proof saved to {output}")
        else:
            click.echo(proof_json)
            
        return 0
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return 1

def main():
    """Entry point for the verify command-line tool."""
    verify()

if __name__ == "__main__":
    main()
