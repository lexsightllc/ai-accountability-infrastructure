<!-- SPDX-License-Identifier: MPL-2.0 -->

# Installation Guide

This guide will help you install and set up AI Trust on your system.

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- (Optional) A virtual environment (recommended)

## Installation

### Using pip (recommended)

```bash
pip install ai-trust
```

### From source

Clone the repository:

```bash
git clone https://github.com/your-org/ai-trust.git
cd ai-trust
```

Install in development mode:

```bash
pip install -e '.[dev,server,crypto]'
```

### Using Docker

```bash
docker build -t ai-trust .
docker run -p 8000:8000 ai-trust
```

## Configuration

Copy the example configuration:

```bash
cp config/.env.example .env
```

Edit the `.env` file with your settings.

## Running the Server

```bash
uvicorn ai_trust.api.main:app --reload
```

The API will be available at http://localhost:8000

## Verifying the Installation

Run the test suite to verify the installation:

```bash
pytest
```

## Upgrading

To upgrade to the latest version:

```bash
pip install --upgrade ai-trust
```

## Troubleshooting

### Common Issues

- **Permission denied when installing packages:**
  Try using `pip install --user` or run with `sudo` (not recommended)
- **Module not found errors:**
  Make sure you've activated your virtual environment
  Try reinstalling the package: `pip install -e .`
- **Port already in use:**
  Change the port in the `.env` file or stop the process using the port

## Getting Help

If you encounter any issues, please:

- Check the troubleshooting guide
- Search the issue tracker
- Open a new issue if your problem isn't already reported

## Next Steps

- Getting Started
- API Reference
- Contributing Guide
