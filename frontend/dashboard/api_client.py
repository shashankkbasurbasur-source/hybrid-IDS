"""
API Client for Hybrid IDS Backend
Handles HTTP requests to the REST API.
"""

import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class APIClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.timeout = 10

    def get(self, endpoint: str) -> Optional[Dict[str, Any]]:
        try:
            res = requests.get(f"{self.base_url}{endpoint}", timeout=self.timeout)
            if res.status_code == 200:
                return res.json()
            return None
        except Exception as e:
            logger.error(f"GET {endpoint} failed: {e}")
            return None

    def post(self, endpoint: str, json_data: Dict = None, files: Dict = None) -> Optional[Dict[str, Any]]:
        try:
            if files:
                res = requests.post(f"{self.base_url}{endpoint}", files=files, timeout=self.timeout)
            else:
                res = requests.post(f"{self.base_url}{endpoint}", json=json_data, timeout=self.timeout)
            
            if res.status_code in [200, 201]:
                return res.json()
            return None
        except Exception as e:
            logger.error(f"POST {endpoint} failed: {e}")
            return None

api_client = APIClient()
