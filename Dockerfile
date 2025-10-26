# SPDX-License-Identifier: MPL-2.0
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e '.[server,crypto]'

# Copy the application code
COPY . .

# Run the application
CMD ["uvicorn", "ai_trust.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
