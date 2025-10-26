# SPDX-License-Identifier: MPL-2.0
"""FastAPI application for AI Trust API."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="AI Trust API",
    description="API for AI Trust services",
    version="0.1.0",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")  # type: ignore[misc]
async def root() -> dict[str, str]:
    """Root endpoint."""
    return {"message": "AI Trust API"}


@app.get("/health")  # type: ignore[misc]
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}
