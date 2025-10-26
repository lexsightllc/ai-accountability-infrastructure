<!-- SPDX-License-Identifier: MPL-2.0 -->

# Project Structure

This document outlines the organization of the AI Trust Infrastructure project.

## Root Directory

- `src/` - Main source code
  - `ai_trust/` - Main package
    - `core/` - Core functionality
      - `__init__.py` - Core package exports
      - `merkle.py` - Merkle tree implementation
      - `app.py` - FastAPI application setup
    - `api/` - API endpoints and routes
    - `cli/` - Command-line interface
    - `models/` - Data models and schemas
    - `services/` - Business logic and services
    - `utils/` - Utility functions
- `tests/` - Test files
  - `unit/` - Unit tests
  - `integration/` - Integration tests
  - `performance/` - Performance tests
- `config/` - Configuration files
- `data/` - Data files and fixtures
- `docs/` - Documentation
- `scripts/` - Utility scripts
- `tools/` - Development tools

## Development

### Setting Up the Development Environment

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -e .[dev]
   ```

### Running Tests

```bash
pytest tests/
```

### Building Documentation

Documentation can be built using Sphinx or MkDocs (TBD).
