"""
Main FastAPI Entry Point
"""

from fastapi import FastAPI
from backend.api.detect_api import router as detect_router


app = FastAPI(
    title="Hybrid Intrusion Detection System",
    version="1.0.0",
    description="Production-ready Hybrid IDS backend API"
)

# Register routes
app.include_router(detect_router, prefix="/detect", tags=["Detection"])


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "running",
        "service": "Hybrid IDS Backend"
    }