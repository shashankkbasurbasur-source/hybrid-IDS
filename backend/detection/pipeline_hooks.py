"""
Detection Pipeline — final version (Step 4, revised).
Pipeline: Feature Extraction -> Feature Snapshot -> Validation -> Scaling
-> Detection Queue -> Prediction Worker -> Model -> Decision -> Storage
-> Alert Queue.
"""

import uuid
from datetime import datetime, timezone

from backend.config import FEATURE_VERSION
from backend.detection.queues.feature_extraction_queue import feature_extraction_queue
from backend.detection.queues.detection_queue import detection_queue
from backend.detection.queues.alert_queue import alert_queue

from backend.detection.features.feature_extraction_engine import feature_extraction_engine
from backend.detection.features.feature_snapshot import snapshot as take_feature_snapshot
from backend.detection.features.feature_validator import feature_validator, FeatureValidationError
from backend.detection.features.feature_scaler import feature_scaler, FeatureScalerError
from backend.detection.features.features_metadata import FeatureMetadataError
from backend.detection.ml.model_manager import model_manager, ModelLoadError
from backend.detection.decision_engine import decision_engine
from backend.detection.performance.performance_monitor import performance_monitor

from backend.storage.db_store import insert_prediction
from backend.core.logger import get_logger
from backend.detection.features.features_metadata import feature_metadata, FeatureMetadataError

from backend.detection.alerts.alert_generator import alert_generator
from backend.detection.alerts.alert_correlator import alert_correlator
from backend.detection.incidents.incident_manager import incident_manager
from backend.detection.fusion.fusion_engine import fusion_engine
from backend.detection.queues.threat_intel_queue import threat_intel_queue

logger = get_logger(__name__)


class FeatureExtractionWorker:
    """
    Pipeline: Completed Flow -> compute() -> validate_keys() -> to_vector()
    -> Feature Snapshot -> validate() (count/NaN/Inf) -> Scale -> Detection Queue.
    """

    def process(self, flow: dict):
        try:
            trained_columns = feature_metadata.feature_columns
        except FeatureMetadataError as e:
            logger.error(f"Feature metadata unavailable, cannot extract for flow {flow.get('flow_key')}: {e}")
            performance_monitor.record_drop()
            return

        try:
            computed = feature_extraction_engine.compute(flow)
            feature_validator.validate_keys(computed, trained_columns)
            raw_vector = feature_extraction_engine.to_vector(computed, trained_columns)
        except FeatureValidationError as e:
            logger.warning(f"Feature key validation failed for flow {flow.get('flow_key')}: {e}")
            performance_monitor.record_drop()
            return
        except Exception as e:
            logger.error(f"Unexpected feature extraction error for flow {flow.get('flow_key')}: {e}")
            performance_monitor.record_drop()
            return

        vector_hash = take_feature_snapshot(flow.get("flow_key"), flow.get("flow_id"), raw_vector)
        expected_count = model_manager.expected_feature_count()

        try:
            validated = feature_validator.validate(raw_vector, expected_count)
            scaled = feature_scaler.transform(validated)
        except FeatureValidationError as e:
            logger.warning(f"Feature validation failed for flow {flow.get('flow_key')}: {e}")
            performance_monitor.record_drop()
            return
        except FeatureScalerError as e:
            logger.error(f"Feature scaling failed for flow {flow.get('flow_key')}: {e}")
            performance_monitor.record_drop()
            return

        detection_queue.enqueue({"flow": flow, "features": scaled, "vector_hash": vector_hash})

    def start(self):
        feature_extraction_queue.start_worker(self.process)

    def stop(self):
        feature_extraction_queue.stop_worker()

# backend/detection/pipeline_hooks.py — PredictionWorker.process(), replace body with:
class PredictionWorker:
    def __init__(self):
        from backend.detection.nids_engine import NIDSDetectionEngine
        self.nids_engine = NIDSDetectionEngine()  # single instance, loaded once

    def process(self, item: dict):
        flow = item["flow"]
        # NIDSDetectionEngine.predict_flow() IS the standardized detection object —
        # {'flow_id','prediction','binary_score','confidence','attack_type', ...}
        nids_detection = self.nids_engine.predict_flow(flow)

        from backend.detection.hybrid_fusion_engine import hybrid_fusion_engine
        hybrid_fusion_engine.submit_nids_detection(nids_detection, flow)

        performance_monitor.record_prediction(0.0)

    def start(self):
        detection_queue.start_worker(self.process)

    def stop(self):
        detection_queue.stop_worker()

class AlertManager:
    """
    Final version — Step 5.
    Prediction -> Decision (already done upstream) -> Alert Generator
    -> Alert Correlation -> Incident Manager -> Fusion Engine
    -> Threat Intelligence Queue.
    """

    def notify(self, prediction_with_flow: dict):
        alert = alert_generator.generate(prediction_with_flow)
        if alert is None:
            return  # Normal prediction — no alert generated, per spec

        incident_id = alert_correlator.correlate(alert)

        if incident_id is None:
            # No matching open incident — create a new one
            incident = incident_manager.create_from_alert(alert)
            incident_id = incident["incident_id"]
        else:
            incident = None  # already merged; fusion check still runs below

        fusion_engine.try_fuse(incident_id)

        threat_intel_queue.enqueue({"incident_id": incident_id})

    def start(self):
        alert_queue.start_worker(self.notify)
        threat_intel_queue.start_worker()  # no-op consumer until Step 7

    def stop(self):
        alert_queue.stop_worker()
        threat_intel_queue.stop_worker()


class ThreatIntel:
    """Deprecated direct-call path — Step 5 now routes through threat_intel_queue instead."""
    def enqueue(self, alert: dict):
        threat_intel_queue.enqueue(alert)

feature_extraction_worker = FeatureExtractionWorker()
prediction_worker = PredictionWorker()
alert_manager = AlertManager()
threat_intel = ThreatIntel()


class DetectionPipeline:
    def start(self):
        feature_extraction_worker.start()
        prediction_worker.start()

    def stop(self):
        feature_extraction_worker.stop()
        prediction_worker.stop()


detection_pipeline = DetectionPipeline()