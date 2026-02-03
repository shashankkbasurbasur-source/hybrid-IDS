class SSHRuleDetector:
    """
    Rule-based intrusion detection for SSH authentication behavior.
    """

    def detect(self, features):
        alerts = []

        for f in features:
            severity = None
            reason = None

            if f["fail_count"] >= 5:
                severity = "HIGH"
                reason = "Multiple failed login attempts detected"

            elif f["fail_count"] >= 2:
                severity = "MEDIUM"
                reason = "Suspicious repeated authentication failures"

            if f["success_after_fail"] == 1:
                severity = "HIGH"
                reason = "Successful login after multiple failures"

            if severity:
                alerts.append({
                    "ip": f["ip"],
                    "severity": severity,
                    "reason": reason,
                    "features": f
                })

        return alerts
