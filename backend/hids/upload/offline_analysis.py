"""Thin wrapper over the unified HIDSDetector for manual log uploads."""

from backend.hids.collector.upload_log_source import UploadedLogSource
from backend.hids.detection.detector import HIDSDetector


def analyze_uploaded_log(file_path: str, decision_threshold: float = 0.5,
                          model_base_path: str = "models",
                          persist_to_incidents: bool = False) -> dict:
    source = UploadedLogSource(file_path)
    detector = HIDSDetector(decision_threshold=decision_threshold, model_base_path=model_base_path)
    report = detector.analyze(source, persist_to_incidents=persist_to_incidents)
    report["file"] = file_path
    return report