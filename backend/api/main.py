"""
backend/api/main.py (UPDATED for Phase 2)

Full Hybrid IDS API with real network capture + threat research.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.detect_api import router as detect_router
from backend.api.alert_api  import router as alert_router
from backend.api.ingest_api import router as ingest_router
from backend.api.packet_api import router as packet_router  # NEW
from backend.api.threat_api import router as threat_router  # NEW
from backend.core.logger    import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="Hybrid Intrusion Detection System",
    version="2.0.0 - Network + Host Detection",
    description="Real-time hybrid IDS with NIDS (network) + HIDS (host) + Fusion"
)

app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Core Detection ────────────────────────────────────────────────────────────
app.include_router(detect_router, prefix="/detect", tags=["Detection"])
app.include_router(alert_router,  prefix="/alerts", tags=["Alerts"])
app.include_router(ingest_router, prefix="/ingest", tags=["Ingestion"])

# ── NEW: Live Packet Capture + Scenarios ──────────────────────────────────────
app.include_router(packet_router, prefix="/packets", tags=["Packet Capture"])

# ── NEW: Threat Research & Analysis ───────────────────────────────────────────
app.include_router(threat_router, prefix="/threats", tags=["Threat Research"])

# ── System Health ─────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health():
    return {
        "status": "running",
        "service": "Hybrid IDS v2.0",
        "components": ["NIDS", "HIDS", "Fusion", "Threat Research"]
    }

@app.get("/stats", tags=["System"])
def stats():
    from backend.storage.db_store import alert_store
    return alert_store.stats()

@app.get("/", tags=["System"])
def root():
    return {
        "service": "Hybrid Intrusion Detection System v2.0",
        "status": "operational",
        "endpoints": {
            "detection": "/detect",
            "alerts": "/alerts",
            "ingestion": "/ingest",
            "network_capture": "/packets",
            "threat_research": "/threats",
            "api_docs": "/docs",
            "redoc": "/redoc"
        }
    }