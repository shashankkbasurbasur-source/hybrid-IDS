"""
Network Interface API
Exposes interface discovery, selection (with validation + test-capture), and current state.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.ingestions.interface_manager import interface_manager

router = APIRouter()


class InterfaceSelectRequest(BaseModel):
    name: str
    skip_test: bool = False


@router.get("/")
def get_interfaces():
    try:
        return {"interfaces": interface_manager.discover()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Interface discovery failed: {e}")


@router.get("/current")
def get_current_interface():
    try:
        return interface_manager.current()
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get current interface: {e}")


@router.post("/select")
def select_interface(request: InterfaceSelectRequest):
    try:
        return interface_manager.select(request.name, skip_test=request.skip_test)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except RuntimeError as re_:
        # Test-capture failures, or interface validation failures during select
        raise HTTPException(status_code=422, detail=str(re_))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Interface selection failed: {e}")


@router.post("/refresh")
def refresh_interface():
    try:
        return interface_manager.refresh()
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Refresh failed: {e}")