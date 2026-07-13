"""
Complete Hybrid IDS API with Threat Intelligence
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.detect_api import router as detect_router
from backend.api.hids_api import router as hids_router
from backend.api.alert_api import router as alerts_router
from backend.api.threat_intel_api import router as threat_intel_router
from backend.ingestions.hids_ingestor import hids_ingestor
from backend.api.intelligence_api import router as intelligence_router
from backend.api.alert_api import router as alert_router

app = FastAPI(
    title="Hybrid Intrusion Detection System v2.0",
    version="2.0.0",
    description="Complete IDS with NIDS, HIDS, Fusion, and Threat Intelligence"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routes
app.include_router(detect_router, prefix="/api/detect", tags=["NIDS"])
app.include_router(hids_router, prefix="/api/hids", tags=["HIDS"])
app.include_router(alerts_router, prefix="/api/alerts", tags=["Alerts & Fusion"])
app.include_router(threat_intel_router, prefix="/api/threat-intel", tags=["Threat Intelligence"])
app.include_router(intelligence_router, prefix="/intelligence", tags=["Network Intelligence"])
app.include_router(alert_router, prefix="", tags=["Alerts & Incidents"])


@app.on_event("startup")
async def startup_event():
    """Startup initialization"""
    hids_ingestor.start_live_monitoring()
    print("[SYSTEM] === Hybrid IDS v2.0 Started ===")
    print("[SYSTEM] NIDS: Packet capture ready")
    print("[SYSTEM] HIDS: Log monitoring active")
    print("[SYSTEM] Fusion: Correlation engine running")
    print("[SYSTEM] Threat Intel: Analysis engine ready")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup"""
    hids_ingestor.stop_live_monitoring()


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Hybrid IDS v2.0",
        "modules": {
            "nids": "operational",
            "hids": "operational",
            "fusion": "operational",
            "threat_intel": "operational"
        }
    }


@app.get("/")
def root():
    return {
        "name": "Hybrid IDS v2.0",
        "modules": {
            "nids": "Network-based detection",
            "hids": "Host-based detection",
            "fusion": "Multi-source correlation",
            "threat_intel": "Threat analysis and enrichment"
        },
        "endpoints": {
            "nids": "/api/detect",
            "hids": "/api/hids",
            "alerts": "/api/alerts",
            "threat_intel": "/api/threat-intel",
            "incidents": "/api/alerts/incidents"
        }
    }