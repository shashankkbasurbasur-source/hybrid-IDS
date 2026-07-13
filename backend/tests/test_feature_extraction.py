"""
Feature Extraction Verification Test.
Confirms that FeatureExtractionEngine, run on a synthetic flow, produces
a vector matching feature_metadata's expected length and produces
consistent, deterministic output (same flow -> same vector -> same hash).

This does NOT verify semantic correctness against the training pipeline's
actual formulas (that requires side-by-side comparison against
ml_pipeline's CICIDS feature generation code on the same raw traffic,
which is a larger integration test) — it verifies structural correctness:
right count, right order, deterministic, hashes match.
"""

import unittest

from backend.detection.features.feature_extraction_engine import feature_extraction_engine
from backend.detection.features.features_metadata import feature_metadata
from backend.detection.features.feature_snapshot import compute_vector_hash


SAMPLE_FLOW = {
    "flow_key": "10.0.0.5|10.0.0.10|443|51234|TCP",
    "flow_id": "test-flow-1",
    "duration_seconds": 12.5,
    "fwd_packets": 20, "bwd_packets": 15,
    "fwd_bytes": 4000, "bwd_bytes": 12000,
    "bytes_per_sec": 1280.0, "packets_per_sec": 2.8,
    "length_stats": {"min": 60, "max": 1500, "mean": 457.1, "std": 320.5},
    "fwd_length_stats": {"mean": 200.0},
    "bwd_length_stats": {"mean": 800.0},
    "iat_stats": {"mean": 0.35, "std": 0.12},
    "fwd_iat_stats": {"mean": 0.4},
    "bwd_iat_stats": {"mean": 0.3},
    "flag_counts": {"SYN": 1, "ACK": 30, "FIN": 1, "RST": 0, "PSH": 5, "URG": 0},
    "active_stats": {"mean": 5.0, "max": 10.0},
    "idle_stats": {"mean": 2.0, "max": 4.0},
    "ttl_stats": {"mean": 64.0},
    "header_length_stats": {"mean": 20.0},
    "window_size_stats": {"mean": 65535.0},
    "dst_port": 443,
    "protocol": "TCP",
    "direction": "outgoing",
}


class TestFeatureExtraction(unittest.TestCase):

    def setUp(self):
        if not feature_metadata.is_loaded():
            self.skipTest(
                "feature_metadata.json not found — run training scripts first "
                "to generate it before running this test."
            )

    def test_vector_length_matches_metadata(self):
        computed = feature_extraction_engine.compute(SAMPLE_FLOW)
        vector = feature_extraction_engine.to_vector(computed)
        self.assertEqual(len(vector), feature_metadata.feature_count)

    def test_vector_is_deterministic(self):
        computed1 = feature_extraction_engine.compute(SAMPLE_FLOW)
        vector1 = feature_extraction_engine.to_vector(computed1)

        computed2 = feature_extraction_engine.compute(SAMPLE_FLOW)
        vector2 = feature_extraction_engine.to_vector(computed2)

        self.assertEqual(vector1, vector2)
        self.assertEqual(compute_vector_hash(vector1), compute_vector_hash(vector2))

    def test_vector_all_numeric_no_nan(self):
        import math
        computed = feature_extraction_engine.compute(SAMPLE_FLOW)
        vector = feature_extraction_engine.to_vector(computed)
        for v in vector:
            self.assertIsInstance(v, float)
            self.assertFalse(math.isnan(v))
            self.assertFalse(math.isinf(v))

    def test_no_missing_training_columns(self):
        """
        The real correctness check: every column the model was trained on
        must be computable by compute(). If this fails, it prints exactly
        which columns are missing so compute() can be extended.
        """
        computed = feature_extraction_engine.compute(SAMPLE_FLOW)
        trained_columns = set(feature_metadata.feature_columns)
        computed_columns = set(computed.keys())

        missing = trained_columns - computed_columns
        self.assertEqual(
            missing, set(),
            f"FeatureExtractionEngine.compute() does not produce these trained "
            f"columns: {missing}. Add them before trusting live predictions."
        )


if __name__ == "__main__":
    unittest.main()