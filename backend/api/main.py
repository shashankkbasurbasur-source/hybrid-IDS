"""
FastAPI Application Entry Point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.detect_api import router as detect_router

app = FastAPI(
    title="Hybrid Intrusion Detection System",
    version="2.0.0",
    description="Production Hybrid IDS with NIDS and HIDS"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(detect_router, prefix="/api/detect", tags=["Detection"])


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "Hybrid IDS Backend"
    }


@app.get("/", tags=["System"])
def root():
    return {
        "name": "Hybrid IDS v2.0",
        "endpoints": {
            "detect": "/api/detect",
            "health": "/health"
        }
    }