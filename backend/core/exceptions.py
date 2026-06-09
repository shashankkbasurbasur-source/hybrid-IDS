"""backend/core/exceptions.py"""

class HybridIDSError(Exception):
    pass

class FeatureError(HybridIDSError):
    pass

class FeatureSizeMismatch(FeatureError):
    def __init__(self, expected: int, got: int, source: str = ""):
        super().__init__(f"{source} feature size mismatch: expected {expected}, got {got}")

class ModelLoadError(HybridIDSError):
    pass

class PredictionError(HybridIDSError):
    pass

class FusionError(HybridIDSError):
    pass

class IngestionError(HybridIDSError):
    pass

class ParserNotFound(IngestionError):
    def __init__(self, source: str):
        super().__init__(f"No parser registered for source: '{source}'")

class AlertError(HybridIDSError):
    pass

class StorageError(HybridIDSError):
    pass