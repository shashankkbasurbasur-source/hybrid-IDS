"""
Host-Based Feature Extraction for HIDS
Extracts features from authentication sessions
"""

import numpy as np
from typing import Dict, List


class HostFeatureExtractor:
    """Extract features from authentication sessions"""
    
    FEATURE_NAMES = [
        'Failed_Login_Count',
        'Successful_Login_Count',
        'Failed_Login_Rate',
        'Successful_Login_Rate',
        'Unique_User_Count',
        'Unique_IP_Count',
        'Authentication_Interval_Mean',
        'Authentication_Interval_Std',
        'Success_After_Failure_Count',
        'Session_Duration',
        'Events_Per_Second',
        'User_Diversity',
        'IP_Diversity',
        'Login_Frequency',
        'Time_Between_Events_Mean',
        'Time_Between_Events_Std',
        'Failed_Login_Sequence',
        'Rapid_Authentication_Attempts',
        'Service_Diversity',
        'Unusual_Login_Time',
        'Failed_SSH_Attempts',
        'Privilege_Escalation_Attempts',
        'Invalid_User_Attempts',
        'Authentication_Success_Ratio',
        'Disconnection_Events'
    ]
    
    FEATURE_SIZE = 25  # Can be adjusted based on model training
    
    def extract(self, session: Dict) -> List[float]:
        """Extract features from authentication session"""
        
        features = [0.0] * self.FEATURE_SIZE
        
        try:
            # Basic session statistics
            failed_logins = float(session.get("failed_attempts", 0))
            successful_logins = float(session.get("successful_attempts", 0))
            total_events = failed_logins + successful_logins
            
            features[0] = failed_logins  # Failed login count
            features[1] = successful_logins  # Successful login count
            
            # Rates (per minute)
            duration_sec = float(session.get("duration", 1.0))
            if duration_sec <= 0:
                duration_sec = 1.0
            duration_min = duration_sec / 60.0
            
            features[2] = failed_logins / duration_min if duration_min > 0 else 0  # Failed rate
            features[3] = successful_logins / duration_min if duration_min > 0 else 0  # Success rate
            
            # Unique counts
            unique_users = float(session.get("unique_users", 0))
            unique_ips = 1.0  # This session is from one IP
            
            features[4] = unique_users  # Unique user count
            features[5] = unique_ips  # Unique IP count
            
            # Time intervals (if multiple events)
            if total_events > 1:
                # Average time between events (simplified)
                interval_mean = duration_sec / (total_events - 1)
                features[6] = interval_mean
                features[7] = 0.0  # Std (would need actual times)
            
            # Success after failure indicator
            if failed_logins > 0 and successful_logins > 0:
                features[8] = 1.0
            
            # Session duration
            features[9] = duration_sec
            
            # Event rate (events per second)
            features[10] = total_events / duration_sec if duration_sec > 0 else 0
            
            # User diversity (entropy-like)
            if unique_users > 0:
                features[11] = unique_users / max(1, total_events)
            
            # IP diversity
            features[12] = 1.0  # Single IP per session
            
            # Login frequency (attempts per hour)
            features[13] = (total_events / duration_sec) * 3600 if duration_sec > 0 else 0
            
            # Time statistics
            features[14] = duration_sec / total_events if total_events > 0 else 0  # Mean time
            features[15] = 0.0  # Std
            
            # Failed login sequence (consecutive failures)
            if failed_logins > 3:
                features[16] = failed_logins
            
            # Rapid authentication (high rate indicator)
            if features[10] > 1.0:  # More than 1 event per second
                features[17] = 1.0
            
            # Service diversity
            features[18] = float(len(session.get("services", [])))
            
            # Unusual login time (simplified - would need hour analysis)
            features[19] = 0.0
            
            # SSH-specific
            if "ssh" in session.get("services", []):
                features[20] = failed_logins
            
            # Privilege escalation attempts
            features[21] = 0.0
            
            # Invalid user attempts
            features[22] = 0.0
            
            # Authentication success ratio
            if total_events > 0:
                features[23] = successful_logins / total_events
            
            # Disconnection events
            features[24] = 0.0
            
            # Ensure no NaN or Inf
            features = [
                0.0 if (f != f or f == float('inf') or f == float('-inf')) else f
                for f in features
            ]
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
        
        return features[:self.FEATURE_SIZE]
    
    def validate(self, features: List[float]) -> bool:
        """Validate extracted features"""
        
        if len(features) != self.FEATURE_SIZE:
            return False
        
        for f in features:
            if not isinstance(f, (int, float)):
                return False
            if f != f or f == float('inf') or f == float('-inf'):
                return False
        
        return True