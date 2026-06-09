"""
backend/api/threat_api.py

Threat research and analysis endpoints.
Provides MITRE ATT&CK, IOC, and mitigation info for alerts.
"""

from fastapi import APIRouter, HTTPException
from typing import Optional
from backend.threats.threat_research import (
    get_threat_analysis, get_attack_iocs, get_mitre_info
)
from backend.core.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/analysis/{attack_type}")
def threat_analysis(
    attack_type: str,
    attack_domain: str = "Unknown",
    network_score: float = 0.5,
    host_score: float = 0.5,
    src_ip: Optional[str] = None
):
    """
    Get detailed threat analysis for an attack type.
    Returns MITRE mapping, IOCs, mitigations, risk assessment.
    """
    try:
        analysis = get_threat_analysis(
            attack_type=attack_type,
            attack_domain=attack_domain,
            network_score=network_score,
            host_score=host_score,
            src_ip=src_ip
        )
        return {
            "status": "success",
            "analysis": analysis,
        }
    except Exception as e:
        logger.exception("Threat analysis error")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/iocs/{attack_type}")
def attack_iocs(attack_type: str):
    """Get Indicators of Compromise for an attack."""
    try:
        iocs = get_attack_iocs(attack_type)
        return {"attack_type": attack_type, "iocs": iocs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mitre/{attack_type}")
def mitre_mapping(attack_type: str):
    """Get MITRE ATT&CK framework mapping for an attack."""
    try:
        info = get_mitre_info(attack_type)
        if not info:
            raise HTTPException(status_code=404, detail="No MITRE mapping found")
        return {
            "attack_type": attack_type,
            "mitre": info
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))