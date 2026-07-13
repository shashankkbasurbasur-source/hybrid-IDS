"""
Decision Engine — Module 6.
Maps raw model output (binary prediction + confidence) into a severity
level and human-readable attack type. Attack-type classification here is
a placeholder heuristic — Step 5/7 refine this with real MITRE-mapped
classification; this module's job is only Normal/Attack + severity now.
"""

from backend.config import CONFIDENCE_THRESHOLD, SEVERITY_THRESHOLDS
from backend.core.logger import get_logger

logger = get_logger(__name__)


class DecisionEngine:

    def decide(self, model_output: dict, flow: dict) -> dict:
        confidence = model_output["confidence"]
        is_attack = model_output["prediction"] == 1 and confidence >= CONFIDENCE_THRESHOLD

        severity = self._severity_for(confidence) if is_attack else "LOW"
        attack_type = self._infer_attack_type(flow) if is_attack else "None"

        return {
            "decision": "Attack" if is_attack else "Normal",
            "severity": severity,
            "attack_type": attack_type,
        }

    def _severity_for(self, confidence: float) -> str:
        for level, threshold in SEVERITY_THRESHOLDS.items():
            if confidence >= threshold:
                return level
        return "LOW"

    def _infer_attack_type(self, flow: dict) -> str:
        """
        Coarse heuristic based on flow shape — NOT a substitute for a real
        multi-class model. Refine in Step 7 (Threat Intelligence).
        """
        packets_per_sec = flow.get("packets_per_sec", 0)
        syn_count = flow.get("flag_counts", {}).get("SYN", 0)
        fwd = flow.get("fwd_packets", 0)
        bwd = flow.get("bwd_packets", 0)

        if syn_count > 10 and bwd == 0:
            return "Port Scan / SYN Flood"
        if packets_per_sec > 1000:
            return "DDoS / Volumetric Attack"
        if fwd > 0 and bwd == 0 and flow.get("dst_port") in (22, 3389):
            return "Brute Force"
        return "Suspicious Activity"


decision_engine = DecisionEngine()