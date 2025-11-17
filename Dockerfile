# SPDX-License-Identifier: MPL-2.0
FROM python:3.9-slim AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --user -e '.[server,crypto]'

# Production stage
FROM python:3.9-slim

WORKDIR /app

# Create non-root user
RUN groupadd -r aitrust && useradd -r -g aitrust aitrust && \
    mkdir -p /app && chown -R aitrust:aitrust /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/aitrust/.local

# Copy the application code
COPY --chown=aitrust:aitrust . .

# Set PATH to include user-installed packages
ENV PATH=/home/aitrust/.local/bin:$PATH

# Switch to non-root user
USER aitrust

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Run the application
CMD ["uvicorn", "ai_trust.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
