# SPDX-License-Identifier: MPL-2.0
"""
Main application module for the AI Trust Infrastructure.

This module initializes and configures the FastAPI application,
including all API routes and middleware.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ai_trust.api import router as api_router

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AI Trust Infrastructure",
        description="API for managing AI trust logs and proofs",
        version="0.1.0",
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API routes
    app.include_router(api_router, prefix="/api/v1")

    return app
