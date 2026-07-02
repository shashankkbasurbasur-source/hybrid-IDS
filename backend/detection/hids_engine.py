"""
HIDS Detection Engine
Host-based intrusion detection with ML
"""

import numpy as np
import pickle
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

from backend.features.host_feature_extractor import HostFeatureExtractor
from backend.storage.nids_store import nids_db


class HIDSDetectionEngine:
    """Host-based intrusion detection engine"""
    
    def __init__(self):
        self.feature_extractor = HostFeatureExtractor()
        self.model = None
        self.scaler = None
        self._load_model()
        
        # Attack classification
        self.attack_types = {
            0: "Normal",
            1: "SSH Brute Force",
            2: "Credential Stuffing",
            3: "Unauthorized Access",
            4: "Privilege Escalation",
            5: "Suspicious Authentication"
        }
    
    def _load_model(self):
        """Load trained HIDS model"""
        
        try:
            model_dir = Path("models")
            
            # Try to load HIDS-specific model first
            try:
                with open(model_dir / "hids_model.pkl", "rb") as f:
                    model_data = pickle.load(f)
                    if isinstance(model_data, tuple):
                        self.model, vocab = model_data
                    else:
                        self.model = model_data
            except:
                # Fallback to generic RF model
                with open(model_dir / "random_forest_model.pkl", "rb") as f:
                    self.model = pickle.load(f)
            
            # Load scaler
            with open(model_dir / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            
            print("[HIDS] Model loaded successfully")
        
        except Exception as e:
            print(f"[HIDS] Warning: Could not load model: {e}")
            print("[HIDS] HIDS will operate in analysis mode only")
    
    def predict_session(self, session: Dict) -> Dict:
        """
        Predict if authentication session is attack
        
        Returns: {
            'session_id': str,
            'prediction': 'Normal' or 'Attack',
            'host_score': float (0-1),
            'confidence': float (0-1),
            'attack_type': str,
            'reason': str,
            'severity': str,
            'features': list
        }
        """
        
        result = {
            "session_id": session.get("session_id"),
            "prediction": "Normal",
            "host_score": 0.0,
            "confidence": 0.0,
            "attack_type": "Normal",
            "reason": "",
            "severity": "LOW",
            "features": [],
            "error": None
        }
        
        try:
            # Extract features
            features = self.feature_extractor.extract(session)
            result["features"] = features
            
            # Validate features
            if not self.feature_extractor.validate(features):
                result["error"] = "Invalid features"
                result["reason"] = "Feature validation failed"
                return result
            
            # Convert to array
            features_array = np.array(features).reshape(1, -1)
            
            # Scale features
            if self.scaler:
                features_scaled = self.scaler.transform(features_array)
            else:
                features_scaled = features_array
            
            # Make prediction
            if self.model:
                prediction = self.model.predict(features_scaled)[0]
                probabilities = self.model.predict_proba(features_scaled)[0]
                
                # Get confidence (max probability)
                confidence = float(np.max(probabilities))
                
                # Determine if intrusion
                is_intrusion = int(prediction) == 1
                
                result["host_score"] = confidence if is_intrusion else 1.0 - confidence
                result["confidence"] = confidence
                result["prediction"] = "Attack" if is_intrusion else "Normal"
            
            else:
                # Fallback to heuristic detection
                result = self._heuristic_detection(session, features)
            
            # Determine attack type based on session characteristics
            if result["prediction"] == "Attack":
                attack_type, reason = self._classify_attack(session, features)
                result["attack_type"] = attack_type
                result["reason"] = reason
                result["severity"] = self._calculate_severity(attack_type)
            
            # Store detection in database
            nids_db.insert_detection({
                "flow_id": session.get("session_id"),
                "timestamp": datetime.now().isoformat(),
                "prediction": result["prediction"],
                "probability": result["host_score"],
                "attack_type": result["attack_type"],
                "confidence": result["confidence"],
                "binary_score": result["host_score"]
            })
        
        except Exception as e:
            result["error"] = str(e)
            print(f"[HIDS] Prediction error: {e}")
        
        return result
    
    def _heuristic_detection(self, session: Dict, features: list) -> Dict:
        """Fallback heuristic-based detection"""
        
        failed_logins = session.get("failed_attempts", 0)
        successful_logins = session.get("successful_attempts", 0)
        unique_users = session.get("unique_users", 0)
        
        score = 0.0
        reasons = []
        
        # Brute force detection
        if failed_logins >= 5:
            score += 0.4
            reasons.append(f"Multiple failed logins ({failed_logins})")
        
        if failed_logins >= 10:
            score += 0.3
            reasons.append("High-rate authentication failures")
        
        # Success after many failures
        if failed_logins >= 3 and successful_logins > 0:
            score += 0.3
            reasons.append("Success after multiple failures")
        
        # Multiple user attempts from same IP
        if unique_users > 3:
            score += 0.2
            reasons.append(f"Multiple users from same IP ({unique_users})")
        
        # Rapid authentication
        duration = session.get("duration", 1.0)
        rate = (failed_logins + successful_logins) / duration if duration > 0 else 0
        if rate > 2:  # More than 2 attempts per second
            score += 0.3
            reasons.append("Rapid authentication attempts")
        
        return {
            "session_id": session.get("session_id"),
            "prediction": "Attack" if score >= 0.5 else "Normal",
            "host_score": min(score, 1.0),
            "confidence": min(score, 1.0),
            "attack_type": "SSH Brute Force" if score >= 0.5 else "Normal",
            "reason": "; ".join(reasons) if reasons else "No suspicious activity",
            "severity": self._calculate_severity("SSH Brute Force") if score >= 0.5 else "LOW",
            "features": []
        }
    
    def _classify_attack(self, session: Dict, features: list) -> tuple:
        """Classify type of attack"""
        
        failed_logins = session.get("failed_attempts", 0)
        successful_logins = session.get("successful_attempts", 0)
        unique_users = session.get("unique_users", 0)
        duration = session.get("duration", 1.0)
        
        reasons = []
        
        # SSH Brute Force
        if failed_logins >= 5:
            reasons.append(f"Failed SSH attempts: {failed_logins}")
            return "SSH Brute Force", "; ".join(reasons)
        
        # Credential Stuffing (many users, many IPs in real scenario)
        if unique_users > 5:
            reasons.append(f"Multiple user accounts targeted: {unique_users}")
            return "Credential Stuffing", "; ".join(reasons)
        
        # Success after failures (likely compromise after brute force)
        if failed_logins >= 3 and successful_logins > 0:
            reasons.append("Successful login after authentication failures")
            return "Unauthorized Access", "; ".join(reasons)
        
        # Rapid attempts
        if duration > 0:
            rate = (failed_logins + successful_logins) / duration
            if rate > 5:
                return "Suspicious Authentication", f"High rate: {rate:.1f} attempts/sec"
        
        return "Suspicious Authentication", "Unusual authentication pattern detected"
    
    def _calculate_severity(self, attack_type: str) -> str:
        """Calculate attack severity"""
        
        if attack_type == "Privilege Escalation":
            return "CRITICAL"
        elif attack_type in ["SSH Brute Force", "Unauthorized Access"]:
            return "HIGH"
        elif attack_type in ["Credential Stuffing", "Suspicious Authentication"]:
            return "MEDIUM"
        else:
            return "LOW"