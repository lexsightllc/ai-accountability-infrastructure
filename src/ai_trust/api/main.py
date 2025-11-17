# SPDX-License-Identifier: MPL-2.0
"""FastAPI application for AI Trust API."""

import os
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

app = FastAPI(
    title="AI Trust API",
    description="API for AI Trust services - Cryptographic accountability for AI systems",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Configure CORS with environment-based allowed origins
# Default to localhost for development, but should be configured in production
allowed_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:8000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)

# Add trusted host middleware for production
trusted_hosts = os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)


@app.get(
    "/",
    summary="API Root",
    description="Root endpoint providing API information",
    response_description="API information and links",
    tags=["General"]
)
@limiter.limit("200/minute")
async def root(request: Request) -> dict[str, str]:
    """Root endpoint providing API information."""
    return {
        "message": "AI Trust API",
        "version": "0.1.0",
        "description": "Cryptographic accountability for AI systems",
        "documentation": "/api/docs"
    }


@app.get(
    "/health",
    summary="Health Check",
    description="Check the health status of the API service",
    response_description="Health status information",
    tags=["Health"]
)
@limiter.limit("500/minute")
async def health_check(request: Request) -> dict[str, str]:
    """Health check endpoint for monitoring and load balancers."""
    return {
        "status": "healthy",
        "timestamp": str(os.getenv("REQUEST_TIME", "")),
        "service": "ai-trust-api"
    }


@app.get(
    "/api/info",
    summary="API Information",
    description="Get detailed information about the API capabilities",
    response_description="Detailed API information",
    tags=["General"]
)
@limiter.limit("100/minute")
async def api_info(request: Request) -> dict[str, str | list[str]]:
    """Get detailed API information and capabilities."""
    return {
        "name": "AI Trust API",
        "version": "0.1.0",
        "description": "Cryptographic accountability for AI systems",
        "features": [
            "Ed25519 cryptographic signatures",
            "Merkle tree transparency logs (RFC 6962)",
            "Receipt generation and verification",
            "Witness co-signing",
            "Inclusion and consistency proofs"
        ],
        "endpoints": {
            "docs": "/api/docs",
            "redoc": "/api/redoc",
            "health": "/health"
        }
    }
