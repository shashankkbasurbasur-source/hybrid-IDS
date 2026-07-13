from backend.ingestions.packet_filter import packet_filter_manager
from backend.storage.db_store import fetch_predictions
from pydantic import BaseModel
from fastapi import APIRouter

router = APIRouter()


class FilterConfig(BaseModel):
    bpf_filter: str | None = None
    protocols: list[str] | None = None
    ips: list[str] | None = None
    ports: list[int] | None = None
    enabled: bool = True


@router.post("/filters")
def set_filters(config: FilterConfig):
    packet_filter_manager.set_bpf_filter(config.bpf_filter)
    packet_filter_manager.set_protocol_filter(config.protocols)
    packet_filter_manager.set_ip_filter(config.ips)
    packet_filter_manager.set_port_filter(config.ports)
    if config.enabled:
        packet_filter_manager.enable()
    else:
        packet_filter_manager.disable()
    return packet_filter_manager.current_config()


@router.get("/filters")
def get_filters():
    return packet_filter_manager.current_config()


@router.delete("/filters")
def clear_filters():
    packet_filter_manager.clear_all()
    return packet_filter_manager.current_config()


@router.get("/predictions")
def predictions(limit: int = 100):
    return {"predictions": fetch_predictions(limit)}