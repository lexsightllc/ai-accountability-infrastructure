#!/usr/bin/env python3
"""
Start the AI Trust Transparency Log server.

This script provides a convenient way to start the transparency log server
with configurable options.
"""

import argparse
import os

def main():
    parser = argparse.ArgumentParser(description='Start the AI Trust Transparency Log server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--storage-dir', default='./data', help='Directory to store the database and logs (default: ./data)')
    
    args = parser.parse_args()
    
    # Create storage directory if it doesn't exist
    os.makedirs(args.storage_dir, exist_ok=True)
    
    # Set environment variables for the Flask app
    os.environ['FLASK_APP'] = 'log.server:create_app()'
    os.environ['FLASK_ENV'] = 'development' if args.debug else 'production'
    os.environ['STORAGE_DIR'] = os.path.abspath(args.storage_dir)
    
    # Import Flask here so we can set the environment variables first
    from flask import Flask
    
    # Create the app
    from ai_trust.services.log.server import create_app
    app = create_app({
        'STORAGE_DIR': os.environ['STORAGE_DIR'],
        'TESTING': False,
        'DEBUG': args.debug
    })
    
    # Print startup message
    print("=" * 60)
    print("AI Trust Transparency Log Server")
    print("=" * 60)
    print(f"Storage directory: {os.path.abspath(args.storage_dir)}")
    print(f"Database file: {os.path.join(os.path.abspath(args.storage_dir), 'transparency_log.db')}")
    print(f"Server URL: http://{args.host}:{args.port}")
    print("")
    print("Endpoints:")
    print(f"  • Submit receipt:     POST   http://{args.host}:{args.port}/receipts")
    print(f"  • Get receipt:        GET    http://{args.host}:{args.port}/receipts/<id_or_hash>")
    print(f"  • Get inclusion proof: GET    http://{args.host}:{args.port}/proofs/<id_or_hash>")
    print(f"  • Get Merkle root:    GET    http://{args.host}:{args.port}/tree/root")
    print(f"  • Get tree size:      GET    http://{args.host}:{args.port}/tree/size")
    print(f"  • Health check:       GET    http://{args.host}:{args.port}/health")
    print("")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    # Run the app
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()
