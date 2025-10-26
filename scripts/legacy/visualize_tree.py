#!/usr/bin/env python3
"""
Enhanced Merkle Tree Visualizer for AI Accountability Log

This tool provides interactive visualization of the Merkle tree used in the AI Accountability
Transparency Log. It supports multiple output formats, including terminal output, HTML, and PNG,
with features like search, filtering, and detailed node inspection.

Features:
- Interactive terminal interface with color support
- Multiple output formats (text, HTML, PNG, SVG)
- Search for specific nodes by hash, receipt ID, or task ID
- Detailed node inspection with path proofs
- Customizable display options
- Support for large trees with pagination
"""

import argparse
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Set

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree
    from rich.text import Text
    from rich.progress import track
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Optional dependencies for additional output formats
try:
    import graphviz
    import matplotlib.pyplot as plt
    import networkx as nx
    from networkx.drawing.nx_agraph import graphviz_layout
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    GRAPHVIZ_AVAILABLE = False

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

class MerkleTreeVisualizer:
    """
    Enhanced Merkle Tree Visualizer for AI Accountability Log
    
    This class provides advanced visualization capabilities for the Merkle tree used in
    the transparency log, with support for multiple output formats and interactive features.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the visualizer with the path to the database.
        
        Args:
            db_path: Path to the SQLite database file
            
        Raises:
            FileNotFoundError: If the database file doesn't exist
            sqlite3.Error: If there's an error accessing the database
        """
        self.db_path = Path(db_path).expanduser().resolve()
        
        # Validate database
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database file not found: {self.db_path}")
        if not self._validate_database():
            raise ValueError(f"Invalid database schema in {self.db_path}")
        
        # Tree visualization settings
        self.node_width = 24  # Width of each node in characters
        self.max_depth = 4    # Default maximum depth to visualize
        self.max_width = 120  # Maximum width of the visualization
        self.page_size = 20   # Number of nodes per page
        self.current_page = 0 # Current page for pagination
        
        # Cached data
        self._tree_data = None
        self._tree_structure = None
        
        # Rich console for pretty printing
        self.console = Console() if RICH_AVAILABLE else None
    
    def _validate_database(self) -> bool:
        """
        Validate the database schema and integrity.
        
        Returns:
            bool: True if the database is valid, False otherwise
        """
        required_tables = {'receipts', 'tree_nodes', 'tree_state'}
        
        try:
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            
            # Check if required tables exist
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name IN ('receipts', 'tree_nodes', 'tree_state')
            """)
            existing_tables = {row[0] for row in cursor.fetchall()}
            
            if existing_tables != required_tables:
                missing_tables = required_tables - existing_tables
                self._log_warning(f"Missing required tables: {', '.join(missing_tables)}")
                return False
                
            # Check for required columns in each table
            table_columns = {
                'receipts': {'id', 'receipt_data', 'timestamp', 'signature', 'public_key'},
                'tree_nodes': {'id', 'level', 'node_index', 'hash', 'left_child', 'right_child', 'receipt_id'},
                'tree_state': {'id', 'root_hash', 'size', 'last_updated'}
            }
            
            for table, required_cols in table_columns.items():
                cursor.execute(f"PRAGMA table_info({table})")
                existing_cols = {row[1] for row in cursor.fetchall()}
                missing_cols = required_cols - existing_cols
                if missing_cols:
                    self._log_warning(f"Missing columns in {table}: {', '.join(missing_cols)}")
                    return False
            
            return True
            
        except sqlite3.Error as e:
            self._log_error(f"Database validation error: {e}")
            return False
        finally:
            if 'conn' in locals():
                conn.close()
    
    def get_tree_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Retrieve the Merkle tree data from the database with caching.
        
        Args:
            force_refresh: If True, force a refresh of the cached data
            
        Returns:
            A dictionary containing the tree data with the following structure:
            {
                'tree_size': int,
                'root_hash': str,
                'nodes': List[Dict],
                'receipts': List[Dict],
                'metadata': Dict[str, Any]
            }
            
        Raises:
            sqlite3.Error: If there's an error accessing the database
        """
        if not force_refresh and self._tree_data is not None:
            return self._tree_data
        
        try:
            # Use a read-only connection to avoid locking the database
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get metadata first
            cursor.execute("""
                SELECT root_hash, size, last_updated 
                FROM tree_state 
                WHERE id = 1
            """)
            tree_meta = cursor.fetchone()
            
            if not tree_meta:
                raise ValueError("No tree state found in the database")
            
            # Get all nodes in the tree with pagination
            nodes = []
            cursor.execute("""
                SELECT * FROM tree_nodes 
                ORDER BY level DESC, node_index
                LIMIT ? OFFSET ?
            """, (self.page_size, self.current_page * self.page_size))
            
            nodes = [dict(row) for row in cursor.fetchall()]
            
            # Get receipt IDs from nodes
            receipt_ids = [node['receipt_id'] for node in nodes if node.get('receipt_id')]
            
            # Get receipts for the current page of nodes
            receipts = []
            if receipt_ids:
                placeholders = ','.join(['?'] * len(receipt_ids))
                cursor.execute(
                    f"SELECT * FROM receipts WHERE id IN ({placeholders})", 
                    receipt_ids
                )
                receipts = [dict(row) for row in cursor.fetchall()]
            
            # Build the result
            self._tree_data = {
                'tree_size': tree_meta['size'],
                'root_hash': tree_meta['root_hash'],
                'last_updated': tree_meta['last_updated'],
                'nodes': nodes,
                'receipts': receipts,
                'metadata': {
                    'page': self.current_page,
                    'page_size': self.page_size,
                    'total_pages': math.ceil(tree_meta['size'] / self.page_size) if self.page_size > 0 else 1,
                    'retrieved_at': datetime.utcnow().isoformat()
                }
            }
            
            return self._tree_data
            
        except sqlite3.Error as e:
            self._log_error(f"Database error: {e}")
            raise
        finally:
            if 'conn' in locals():
                conn.close()
    
    def _log_info(self, message: str) -> None:
        """Log an informational message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.console:
            self.console.print(f"[{timestamp}] [cyan]INFO[/]: {message}")
        else:
            print(f"{timestamp} [INFO] {message}")
    
    def _log_warning(self, message: str) -> None:
        """Log a warning message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.console:
            self.console.print(f"[{timestamp}] {Colors.WARNING}WARN{Colors.ENDC}: {message}")
        else:
            print(f"{timestamp} [WARN] {message}")
    
    def _log_error(self, message: str, exc_info: bool = False) -> None:
        """
        Log an error message.
        
        Args:
            message: The error message to log
            exc_info: If True, include exception information
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.console:
            self.console.print(f"[{timestamp}] [red]ERROR[/]: {message}", style="red")
            if exc_info and sys.exc_info() != (None, None, None):
                self.console.print_exception()
        else:
            print(f"{timestamp} [ERROR] {message}")
            if exc_info and sys.exc_info() != (None, None, None):
                import traceback
                traceback.print_exc()
    
    def _get_receipt_by_id(self, receipt_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a receipt by its ID from the database.
        
        Args:
            receipt_id: The ID of the receipt to retrieve
            
        Returns:
            The receipt data as a dictionary, or None if not found
        """
        try:
            conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM receipts WHERE id = ?", (receipt_id,))
            row = cursor.fetchone()
            
            return dict(row) if row else None
            
        except sqlite3.Error as e:
            self._log_error(f"Error retrieving receipt {receipt_id}: {e}", exc_info=True)
            return None
        finally:
            if 'conn' in locals():
                conn.close()
    
    def _format_hash(self, hash_str: str, length: int = 8) -> str:
        """
        Format a hash string for display.
        
        Args:
            hash_str: The hash string to format
            length: The maximum length of the output string
            
        Returns:
            A shortened and formatted hash string
        """
        if not hash_str:
            return ""
            
        if len(hash_str) <= length + 2:
            return hash_str
            
        half = max(2, length // 2)
        return f"{hash_str[:half]}…{hash_str[-half:]}"
    
    def _get_node_label(self, node: Dict[str, Any]) -> str:
        """
        Generate a human-readable label for a tree node.
        
        Args:
            node: The node dictionary
            
        Returns:
            A formatted label string
        """
        if node.get('receipt_id'):
            receipt = self._get_receipt_by_id(node['receipt_id'])
            if receipt:
                receipt_data = json.loads(receipt['receipt_data'])
                task_id = receipt_data.get('task_id', 'unknown')
                timestamp = receipt.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        timestamp = dt.strftime('%Y-%m-%d %H:%M')
                    except (ValueError, TypeError):
                        pass
                return f"[RECEIPT] {node['receipt_id']} | {task_id[:12]} | {timestamp}"
        
        # For non-leaf nodes, show the hash
        return f"[TREE] {self._format_hash(node.get('hash', ''))}"
    
    def build_tree_structure(self, tree_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a hierarchical structure of the Merkle tree.
        
        Args:
            tree_data: The tree data from get_tree_data().
            
        Returns:
            A hierarchical dictionary representing the tree with the following structure:
            {
                'root': Dict,  # Root node of the tree
                'depth': int,  # Maximum depth of the tree
                'size': int,   # Total number of nodes in the tree
                'leaves': List[Dict]  # List of leaf nodes
            }
            
        Raises:
            ValueError: If the tree data is invalid or empty
        """
        if not tree_data or not tree_data.get('nodes'):
            raise ValueError("No tree data or nodes provided")
            
        # Create a mapping of node hashes to their data
        node_map = {}
        for node in tree_data['nodes']:
            node_hash = node.get('hash')
            if node_hash:
                node_map[node_hash] = node
                
        # Find the root node (should be the only node at the highest level)
        max_level = max((n.get('level', 0) for n in tree_data['nodes']), default=0)
        root_nodes = [n for n in tree_data['nodes'] if n.get('level') == max_level]
        
        if not root_nodes:
            raise ValueError("No root node found in tree data")
            
        if len(root_nodes) > 1:
            self._log_warning(f"Found multiple root nodes: {len(root_nodes)}")
            
        root_node = root_nodes[0]
        
        # Build the tree structure recursively
        def build_node(node_data: Dict[str, Any]) -> Dict[str, Any]:
            """Recursively build a node and its children."""
            node = {
                'hash': node_data.get('hash'),
                'level': node_data.get('level', 0),
                'is_leaf': bool(node_data.get('receipt_id')),
                'receipt_id': node_data.get('receipt_id'),
                'left': None,
                'right': None,
                'parent': None
            }
            
            # Add receipt data if this is a leaf node
            if node['is_leaf'] and 'receipts' in tree_data:
                receipt_id = node_data['receipt_id']
                receipt = next(
                    (r for r in tree_data['receipts'] if r.get('id') == receipt_id),
                    None
                )
                if receipt:
                    node['receipt'] = receipt
            
            # Recursively build left and right children if they exist
            left_hash = node_data.get('left_child')
            right_hash = node_data.get('right_child')
            
            if left_hash and left_hash in node_map:
                left_node = build_node(node_map[left_hash])
                left_node['parent'] = node
                node['left'] = left_node
                
            if right_hash and right_hash in node_map:
                right_node = build_node(node_map[right_hash])
                right_node['parent'] = node
                node['right'] = right_node
                
            return node
        
        # Build the tree starting from the root
        tree = build_node(root_node)
        
        # Find all leaf nodes
        def find_leaves(node: Dict[str, Any]) -> List[Dict]:
            """Find all leaf nodes in the tree."""
            if node['is_leaf']:
                return [node]
                
            leaves = []
            if node['left']:
                leaves.extend(find_leaves(node['left']))
            if node['right']:
                leaves.extend(find_leaves(node['right']))
                
            return leaves
        
        leaves = find_leaves(tree)
        
        # Calculate tree depth
        def calculate_depth(node: Dict[str, Any]) -> int:
            """Calculate the depth of the tree."""
            if not node or node['is_leaf']:
                return 1
                
            left_depth = calculate_depth(node.get('left')) if node.get('left') else 0
            right_depth = calculate_depth(node.get('right')) if node.get('right') else 0
            
            return 1 + max(left_depth, right_depth)
        
        depth = calculate_depth(tree)
        
        # Return the complete tree structure
        return {
            'root': tree,
            'depth': depth,
            'size': len(tree_data['nodes']),
            'leaves': leaves,
            'root_hash': tree_data.get('root_hash'),
            'last_updated': tree_data.get('last_updated')
        }
        
        # Calculate the depth of the tree
        depth = max(nodes_by_level.keys()) if nodes_by_level else 0
        
        # Build the tree starting from the root
        root = build_node(depth, 0) if depth >= 0 else None
        
        return {
            'root': root,
            'depth': depth,
            'size': tree_data['tree_size']
        }
    
    def visualize_tree(self, tree_structure: Dict[str, Any]) -> str:
        """
        Generate a text-based visualization of the Merkle tree.
        
        Args:
            tree_structure: The tree structure from build_tree_structure().
            
        Returns:
            A string containing the visualization.
        """
        if not tree_structure or not tree_structure['root']:
            return "Empty tree"
        
        lines = []
        
        # Add header
        lines.append(f"{Colors.HEADER}{Colors.BOLD}Merkle Tree Visualization{Colors.ENDC}")
        lines.append(f"Size: {tree_structure['size']} receipts")
        lines.append(f"Depth: {tree_structure['depth']} levels")
        lines.append(f"Root: {self._short_hash(tree_structure['root']['hash'])}")
        lines.append("")
        
        # Calculate the maximum depth to display
        max_display_depth = min(tree_structure['depth'], self.max_depth)
        
        # Generate the tree visualization level by level
        for level in range(max_display_depth + 1):
            level_nodes = self._get_nodes_at_level(tree_structure['root'], level, 0, max_display_depth)
            
            # Skip empty levels
            if not level_nodes:
                continue
            
            # Add level header
            if level == 0:
                level_name = "Leaf Nodes (Receipts)"
            elif level == tree_structure['depth']:
                level_name = f"Root (Level {level})"
            else:
                level_name = f"Level {level}"
            
            lines.append(f"\n{Colors.UNDERLINE}{level_name}{Colors.ENDC}")
            
            # Add nodes at this level
            for node in level_nodes:
                if node is None:
                    continue
                
                # Format the node
                if node['is_leaf'] and 'receipt' in node:
                    receipt = node['receipt']
                    node_str = (
                        f"Receipt #{receipt['id']} | "
                        f"{receipt.get('task_id', '')[:20]}... | "
                        f"{self._short_hash(node['hash'])}"
                    )
                else:
                    node_str = self._short_hash(node['hash'])
                
                # Add indentation based on the node's position
                indent = ' ' * (node['pos'] * (self.node_width + 2))
                lines.append(f"{indent}{node_str}")
                
                # Add connection lines for non-leaf nodes
                if not node['is_leaf']:
                    conn_indent = ' ' * (node['pos'] * (self.node_width + 2) + 3)
                    conn_line = '|'.ljust(self.node_width - 4, '-')
                    lines.append(f"{conn_indent}/{conn_line}\\ ")
        
        # Add a note if the tree was truncated
        if tree_structure['depth'] > max_display_depth:
            lines.append(
                f"\n{Colors.WARNING}Note: Tree truncated at depth {max_display_depth} "
                f"(total depth: {tree_structure['depth']}){Colors.ENDC}"
            )
        
        return '\n'.join(lines)
    
    def _get_nodes_at_level(self, node: Dict[str, Any], target_level: int, 
                          current_level: int, max_level: int) -> List[Optional[Dict]]:
        """
        Get all nodes at a specific level of the tree.
        
        Args:
            node: The current node.
            target_level: The level to collect nodes from.
            current_level: The level of the current node.
            max_level: Maximum level to traverse.
            
        Returns:
            A list of nodes at the target level, with their positions.
        """
        if current_level > max_level:
            return []
        
        if current_level == target_level:
            # Calculate position based on the node's index at its level
            pos = node['index'] * (2 ** (max_level - current_level))
            return [{'hash': node['hash'], 
                    'is_leaf': node['is_leaf'],
                    'pos': pos,
                    'receipt': node.get('receipt')}]
        
        if current_level < target_level:
            left_nodes = []
            right_nodes = []
            
            if node['left']:
                left_nodes = self._get_nodes_at_level(
                    node['left'], target_level, current_level + 1, max_level
                )
            
            if node['right']:
                right_nodes = self._get_nodes_at_level(
                    node['right'], target_level, current_level + 1, max_level
                )
            
            return left_nodes + right_nodes
        
        return []
    
    @staticmethod
    def _short_hash(hash_str: str, length: int = 8) -> str:
        """Shorten a hash string for display."""
        if not hash_str:
            return ""
        
        if len(hash_str) <= length + 2:
            return hash_str
        
        return f"{hash_str[:length//2]}...{hash_str[-length//2:]}"

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Visualize the Merkle tree of the transparency log')
    parser.add_argument('--db', default='data/transparency_log.db',
                      help='Path to the transparency log database')
    parser.add_argument('--max-depth', type=int, default=4,
                      help='Maximum depth to visualize (default: 4)')
    parser.add_argument('--output', '-o',
                      help='Output file (default: print to console)')
    
    args = parser.parse_args()
    
    try:
        # Create the visualizer
        visualizer = MerkleTreeVisualizer(args.db)
        visualizer.max_depth = args.max_depth
        
        # Get the tree data
        tree_data = visualizer.get_tree_data()
        
        # Build the tree structure
        tree_structure = visualizer.build_tree_structure(tree_data)
        
        # Generate the visualization
        visualization = visualizer.visualize_tree(tree_structure)
        
        # Output the result
        if args.output:
            with open(args.output, 'w') as f:
                # Strip ANSI color codes when writing to file
                import re
                clean_visualization = re.sub(r'\x1b\[[0-9;]*[mK]', '', visualization)
                f.write(clean_visualization)
            print(f"Visualization saved to {args.output}")
        else:
            print(visualization)
        
        return 0
        
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
