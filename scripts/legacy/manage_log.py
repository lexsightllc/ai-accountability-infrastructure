#!/usr/bin/env python3
"""
Manage AI Accountability Transparency Log

This script provides utilities for managing the transparency log, including:
- Backing up the log to a file
- Restoring the log from a backup
- Compacting the log database
- Checking log integrity
"""

import argparse
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

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

class LogManager:
    """Class for managing the transparency log database."""
    
    def __init__(self, log_dir: str = "data"):
        """Initialize the LogManager with the log directory."""
        self.log_dir = Path(log_dir)
        self.db_path = self.log_dir / "transparency_log.db"
        self.backup_dir = self.log_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a connection to the database."""
        return sqlite3.connect(str(self.db_path))
    
    def backup(self, output_file: Optional[str] = None, compress: bool = False) -> str:
        """
        Backup the transparency log to a file.
        
        Args:
            output_file: Path to the output file. If None, a default name will be used.
            compress: Whether to compress the backup file.
            
        Returns:
            Path to the backup file.
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database file not found: {self.db_path}")
        
        # Create a timestamp for the backup
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Determine the output file path
        if output_file is None:
            output_file = f"transparency_log_backup_{timestamp}.db"
            output_path = self.backup_dir / output_file
        else:
            output_path = Path(output_file)
        
        # Create the backup
        shutil.copy2(self.db_path, output_path)
        
        # Compress if requested
        if compress:
            import gzip
            compressed_path = f"{output_path}.gz"
            with open(output_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(output_path)
            output_path = Path(compressed_path)
        
        # Verify the backup
        if not output_path.exists():
            raise RuntimeError(f"Failed to create backup at {output_path}")
        
        return str(output_path)
    
    def restore(self, backup_file: str, force: bool = False) -> bool:
        """
        Restore the transparency log from a backup.
        
        Args:
            backup_file: Path to the backup file.
            force: If True, overwrite the existing database without prompting.
            
        Returns:
            True if the restore was successful, False otherwise.
        """
        backup_path = Path(backup_file)
        
        # Check if the backup file exists
        if not backup_path.exists():
            print(f"{Colors.FAIL}Error: Backup file not found: {backup_path}{Colors.ENDC}")
            return False
        
        # Check if the database already exists
        if self.db_path.exists() and not force:
            print(f"{Colors.WARNING}Warning: Database already exists at {self.db_path}{Colors.ENDC}")
            response = input(f"Overwrite existing database? [y/N] ").strip().lower()
            if response != 'y':
                print("Restore cancelled.")
                return False
        
        try:
            # Create a backup of the current database if it exists
            if self.db_path.exists():
                backup_path = self.backup(compress=True)
                print(f"Created backup of existing database at: {backup_path}")
            
            # Copy the backup file to the database location
            shutil.copy2(backup_file, self.db_path)
            
            # Verify the restore
            if not self.db_path.exists():
                print(f"{Colors.FAIL}Error: Failed to restore database{Colors.ENDC}")
                return False
            
            print(f"{Colors.OKGREEN}Successfully restored database from {backup_file}{Colors.ENDC}")
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}Error during restore: {e}{Colors.ENDC}")
            return False
    
    def compact(self) -> bool:
        """
        Compact the database to reduce file size.
        
        Returns:
            True if the operation was successful, False otherwise.
        """
        if not self.db_path.exists():
            print(f"{Colors.FAIL}Error: Database file not found: {self.db_path}{Colors.ENDC}")
            return False
        
        try:
            # Create a backup before compacting
            backup_file = self.backup(compress=False)
            print(f"Created backup at: {backup_file}")
            
            # Connect to the database
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get the current size
            cursor.execute("PRAGMA page_count;")
            page_count = cursor.fetchone()[0]
            cursor.execute("PRAGMA page_size;")
            page_size = cursor.fetchone()[0]
            original_size = page_count * page_size
            
            print(f"Original database size: {self._format_size(original_size)}")
            
            # Vacuum the database to compact it
            print("Compacting database (this may take a while)...")
            cursor.execute("VACUUM;")
            conn.commit()
            
            # Get the new size
            cursor.execute("PRAGMA page_count;")
            new_page_count = cursor.fetchone()[0]
            new_size = new_page_count * page_size
            
            # Calculate savings
            savings = original_size - new_size
            savings_pct = (savings / original_size) * 100 if original_size > 0 else 0
            
            print(f"New database size: {self._format_size(new_size)}")
            print(f"Space saved: {self._format_size(savings)} ({savings_pct:.1f}%)")
            
            conn.close()
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}Error during compaction: {e}{Colors.ENDC}")
            return False
    
    def check_integrity(self) -> Tuple[bool, List[str]]:
        """
        Check the integrity of the database.
        
        Returns:
            A tuple (is_ok, messages) where is_ok is True if the database is OK,
            and messages is a list of informational or error messages.
        """
        if not self.db_path.exists():
            return False, [f"Database file not found: {self.db_path}"]
        
        messages = []
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check integrity
            cursor.execute("PRAGMA integrity_check;")
            result = cursor.fetchone()
            
            if result and result[0] == 'ok':
                messages.append(f"{Colors.OKGREEN}[OK] Database integrity check passed{Colors.ENDC}")
                is_ok = True
            else:
                messages.append(f"{Colors.FAIL}[X] Database integrity check failed{Colors.ENDC}")
                messages.append(str(result))
                is_ok = False
            
            # Check foreign key constraints
            cursor.execute("PRAGMA foreign_key_check;")
            fk_issues = cursor.fetchall()
            
            if fk_issues:
                messages.append(f"{Colors.WARNING}[!] {len(fk_issues)} foreign key constraint violations found{Colors.ENDC}")
                for issue in fk_issues[:5]:  # Show first 5 issues
                    messages.append(f"  - {issue}")
                if len(fk_issues) > 5:
                    messages.append(f"  - ... and {len(fk_issues) - 5} more")
                is_ok = False
            else:
                messages.append(f"{Colors.OKGREEN}[OK] No foreign key constraint violations{Colors.ENDC}")
            
            # Get table info
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall() if not row[0].startswith('sqlite_')]
            
            messages.append(f"\n{Colors.HEADER}Database Information:{Colors.ENDC}")
            messages.append(f"Path: {self.db_path}")
            messages.append(f"Size: {self._format_size(self.db_path.stat().st_size)}")
            messages.append(f"Tables: {', '.join(tables) if tables else 'None'}")
            
            # Get receipt count
            if 'receipts' in tables:
                cursor.execute("SELECT COUNT(*) FROM receipts;")
                receipt_count = cursor.fetchone()[0]
                messages.append(f"Receipts: {receipt_count:,}")
            
            conn.close()
            return is_ok, messages
            
        except Exception as e:
            return False, [f"Error checking database integrity: {e}"]
    
    def list_backups(self) -> List[Dict[str, str]]:
        """
        List all available backups.
        
        Returns:
            A list of dictionaries containing backup file information.
        """
        backups = []
        
        # Find all backup files
        for ext in ['', '.gz', '.db', '.sqlite', '.sqlite3', '.db.backup']:
            for file in self.backup_dir.glob(f"*{ext}"):
                try:
                    stat = file.stat()
                    backups.append({
                        'path': str(file),
                        'name': file.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        'is_compressed': file.suffix == '.gz'
                    })
                except (OSError, AttributeError):
                    continue
        
        # Sort by modification time (newest first)
        backups.sort(key=lambda x: x['modified'], reverse=True)
        return backups
    
    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format a size in bytes as a human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

def print_help():
    """Print help information."""
    print(f"""
{Colors.HEADER}{Colors.BOLD}AI Accountability Transparency Log Manager{Colors.ENDC}

Usage: {sys.argv[0]} [command] [options]

Commands:
  backup     Create a backup of the log database
  restore    Restore the log database from a backup
  compact    Compact the database to reduce file size
  check      Check the integrity of the database
  list       List available backups
  help       Show this help message

Options:
  --dir PATH     Path to the log directory (default: data)
  --help         Show this help message

Examples:
  {sys.argv[0]} backup --dir /path/to/logs
  {sys.argv[0]} restore /path/to/backup.db
  {sys.argv[0]} compact
  {sys.argv[0]} check
  {sys.argv[0]} list
""")

def main():
    """Main entry point for the script."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Manage AI Accountability Transparency Log', add_help=False)
    parser.add_argument('command', nargs='?', default='help', 
                       choices=['backup', 'restore', 'compact', 'check', 'list', 'help'],
                       help='Command to execute')
    parser.add_argument('args', nargs=argparse.REMAINDER, help='Command arguments')
    parser.add_argument('--dir', default='data', help='Path to the log directory')
    
    # Handle the case where no arguments are provided
    if len(sys.argv) == 1:
        print_help()
        return 0
    
    # Parse known args first
    args, remaining_args = parser.parse_known_args()
    
    # Create the log manager
    manager = LogManager(args.dir)
    
    # Execute the command
    if args.command == 'backup':
        # Parse backup-specific arguments
        backup_parser = argparse.ArgumentParser(description='Create a backup of the log database')
        backup_parser.add_argument('--output', '-o', help='Output file path')
        backup_parser.add_argument('--compress', '-z', action='store_true', help='Compress the backup file')
        backup_args = backup_parser.parse_args(remaining_args)
        
        try:
            backup_path = manager.backup(backup_args.output, backup_args.compress)
            print(f"{Colors.OKGREEN}[OK] Backup created successfully: {backup_path}{Colors.ENDC}")
            return 0
        except Exception as e:
            print(f"{Colors.FAIL}[X] Failed to create backup: {e}{Colors.ENDC}")
            return 1
    
    elif args.command == 'restore':
        # Parse restore-specific arguments
        restore_parser = argparse.ArgumentParser(description='Restore the log database from a backup')
        restore_parser.add_argument('backup_file', help='Path to the backup file')
        restore_parser.add_argument('--force', '-f', action='store_true', 
                                   help='Overwrite existing database without prompting')
        restore_args = restore_parser.parse_args(remaining_args)
        
        success = manager.restore(restore_args.backup_file, restore_args.force)
        return 0 if success else 1
    
    elif args.command == 'compact':
        success = manager.compact()
        return 0 if success else 1
    
    elif args.command == 'check':
        is_ok, messages = manager.check_integrity()
        for msg in messages:
            print(msg)
        return 0 if is_ok else 1
    
    elif args.command == 'list':
        backups = manager.list_backups()
        if not backups:
            print(f"{Colors.WARNING}No backups found in {manager.backup_dir}{Colors.ENDC}")
            return 0
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}Available Backups:{Colors.ENDC}\n")
        print(f"{'Modified':<20} {'Size':>10} {'Name'}")
        print("-" * 60)
        
        for backup in backups:
            size = manager._format_size(backup['size'])
            print(f"{backup['modified']:<20} {size:>10} {backup['name']}")
        
        print(f"\nTotal backups: {len(backups)}")
        return 0
    
    else:  # help
        print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main())
