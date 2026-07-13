"""
Network Intelligence API
Devices, flows, protocol stats, topology, and aggregated network statistics.
"""

from fastapi import APIRouter, HTTPException

from backend.storage.db_store import fetch_devices, fetch_flows, fetch_latest_network_statistics
from backend.detection.protocols.protocol_analyzer import protocol_analyzer
from backend.detection.topology.topology_manager import topology_manager

router = APIRouter()


@router.get("/devices")
def get_devices():
    return {"devices": fetch_devices()}


@router.get("/devices/{device_ip}")
def get_device(device_ip: str):
    devices = fetch_devices()
    device = next((d for d in devices if d["ip"] == device_ip), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_ip}' not found")
    return device


@router.get("/flows")
def get_flows(limit: int = 100):
    return {"flows": fetch_flows(limit)}


@router.get("/flows/active")
def get_active_flows(limit: int = 100):
    flows = fetch_flows(limit)
    return {"flows": [f for f in flows if f.get("status") == "ACTIVE"]}


@router.get("/protocols")
def get_protocols():
    return {"protocols": protocol_analyzer.summary()}


@router.get("/topology")
def get_topology():
    return topology_manager.build()


@router.get("/statistics")
def get_network_statistics():
    stats = fetch_latest_network_statistics()
    if not stats:
        raise HTTPException(status_code=404, detail="No statistics available yet")
    return stats