"""
NIDS Detection Engine
Binary classification + multi-class attack classification
"""

import numpy as np
from typing import Dict, Tuple, Optional
import pickle
from pathlib import Path

from backend.features.flow_feature_extractor import FlowFeatureExtractor
from backend.storage.nids_store import nids_db


class NIDSDetectionEngine:
    """NIDS prediction engine with binary + multiclass classification"""
    
    def __init__(self):
        self.feature_extractor = FlowFeatureExtractor()
        self.binary_model = None
        self.multiclass_model = None
        self.scaler = None
        self._load_models()
        
        # Attack class mapping
        self.attack_classes = {
            0: "Normal",
            1: "DoS Hulk",
            2: "DoS GoldenEye",
            3: "DoS Slowhttptest",
            4: "DoS Slowloris",
            5: "Heartbleed",
            6: "Web Attack – Brute Force",
            7: "Web Attack – XSS",
            8: "Web Attack – SQL Injection",
            9: "Infiltration",
            10: "Bot",
            11: "PortScan",
            12: "DDoS"
        }
    
    def _load_models(self):
        """Load trained ML models"""
        
        try:
            model_dir = Path("models")
            
            # Load binary model
            with open(model_dir / "random_forest_model.pkl", "rb") as f:
                self.binary_model = pickle.load(f)
            
            # Try to load multiclass model
            try:
                with open(model_dir / "multiclass_model.pkl", "rb") as f:
                    self.multiclass_model = pickle.load(f)
            except:
                print("[NIDS] Multiclass model not found, using binary only")
                self.multiclass_model = None
            
            # Load scaler
            with open(model_dir / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            
            print("[NIDS] Models loaded successfully")
        
        except Exception as e:
            raise RuntimeError(f"Failed to load NIDS models: {e}")
    
    def predict_flow(self, flow: Dict) -> Dict:
        """
        Predict if flow is attack or normal
        Returns: {
            'flow_id': str,
            'prediction': 'Normal' or 'Intrusion',
            'binary_score': float (0-1),
            'confidence': float (0-1),
            'attack_type': str,
            'multiclass_scores': dict,
            'features_used': int
        }
        """
        
        result = {
            "flow_id": flow.get("flow_id"),
            "prediction": "Normal",
            "binary_score": 0.0,
            "confidence": 0.0,
            "attack_type": "Normal",
            "multiclass_scores": {},
            "features_used": 0,
            "error": None
        }
        
        try:
            # Extract features
            features = self.feature_extractor.extract(flow)
            
            # Validate features
            if not self._validate_features(features):
                result["error"] = "Invalid features"
                return result
            
            # Convert to array
            features_array = np.array(features).reshape(1, -1)
            
            # Scale features
            features_scaled = self.scaler.transform(features_array)
            
            # Binary prediction
            binary_pred = self.binary_model.predict(features_scaled)[0]
            binary_proba = self.binary_model.predict_proba(features_scaled)[0]
            
            # Probability of intrusion
            intrusion_prob = binary_proba[1] if len(binary_proba) > 1 else 0.0
            
            result["binary_score"] = float(intrusion_prob)
            result["confidence"] = float(intrusion_prob)
            result["features_used"] = len(features)
            
            # Decision threshold
            threshold = 0.5
            
            if intrusion_prob >= threshold:
                result["prediction"] = "Intrusion"
                
                # Multi-class prediction (if available)
                if self.multiclass_model:
                    multiclass_pred = self.multiclass_model.predict(features_scaled)[0]
                    multiclass_proba = self.multiclass_model.predict_proba(features_scaled)[0]
                    
                    # Get attack type
                    attack_type_idx = multiclass_pred
                    result["attack_type"] = self.attack_classes.get(
                        attack_type_idx,
                        f"Unknown Attack ({attack_type_idx})"
                    )
                    
                    # Store multiclass scores
                    for idx, prob in enumerate(multiclass_proba):
                        attack_name = self.attack_classes.get(idx, f"Class {idx}")
                        result["multiclass_scores"][attack_name] = float(prob)
            
            else:
                result["prediction"] = "Normal"
                result["attack_type"] = "Normal"
            
            # Store in database
            nids_db.insert_detection({
                "flow_id": flow.get("flow_id"),
                "timestamp": flow.get("end_time"),
                "prediction": result["prediction"],
                "probability": result["binary_score"],
                "attack_type": result["attack_type"],
                "confidence": result["confidence"],
                "binary_score": result["binary_score"],
                "multiclass_scores": result["multiclass_scores"]
            })
        
        except Exception as e:
            result["error"] = str(e)
            print(f"[NIDS] Prediction error: {e}")
        
        return result
    
    def _validate_features(self, features: list) -> bool:
        """Validate extracted features"""
        
        if len(features) != FlowFeatureExtractor.FEATURE_SIZE:
            return False
        
        # Check for NaN or Inf
        for f in features:
            if not isinstance(f, (int, float)):
                return False
            if f != f or f == float('inf') or f == float('-inf'):
                return False
        
        return True