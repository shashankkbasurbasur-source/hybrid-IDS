"""
Feature Validator — final version.
Two checks: (1) computed feature keys exactly cover the trained columns
BEFORE reordering, (2) the ordered numeric vector is well-formed BEFORE
scaling. Both use the model/metadata as authority, never a config constant.
"""

import math

from backend.core.logger import get_logger

logger = get_logger(__name__)


class FeatureValidationError(Exception):
    pass


class FeatureValidator:

    def validate_keys(self, computed: dict, trained_columns: list):
        """Raises if compute() failed to produce any trained column. Should
        never fire in normal operation after the full feature set is implemented —
        if it does, it means compute() has a genuine gap that needs fixing."""
        missing = set(trained_columns) - set(computed.keys())
        if missing:
            raise FeatureValidationError(
                f"Computed features are missing {len(missing)} trained columns: {sorted(missing)}"
            )

    def validate(self, vector: list, expected_count: int) -> list:
        if not isinstance(vector, list):
            raise FeatureValidationError(f"Feature vector must be a list, got {type(vector)}")

        if expected_count is not None and len(vector) != expected_count:
            raise FeatureValidationError(
                f"Feature count mismatch: model expects {expected_count}, got {len(vector)}"
            )

        cleaned = []
        for i, value in enumerate(vector):
            try:
                fvalue = float(value)
            except (TypeError, ValueError):
                logger.warning(f"Feature index {i} non-numeric ({value!r}); defaulting to 0.0")
                cleaned.append(0.0)
                continue

            if math.isnan(fvalue) or math.isinf(fvalue):
                logger.warning(f"Feature index {i} is NaN/Inf ({fvalue}); defaulting to 0.0")
                cleaned.append(0.0)
                continue

            cleaned.append(fvalue)

        return cleaned


feature_validator = FeatureValidator()