#!/bin/bash
set -e

echo "Setting up development environment..."
python -m pip install -e '.[dev,server,crypto]'

echo "Running tests..."
pytest

echo "Starting development server..."
uvicorn ai_trust.api.main:app --reload
