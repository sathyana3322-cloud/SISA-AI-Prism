"""Health check endpoint for observability."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "threat-intelligence-platform",
        "version": "1.0.0",
    }
