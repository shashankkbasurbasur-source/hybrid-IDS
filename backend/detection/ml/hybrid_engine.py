class HybridDecisionEngine:
    """
    Combines rule-based and ML-based detection results
    to generate final intrusion decisions.
    """

    def decide(self, rule_alerts, ml_results):
        final_alerts = []

        # Index ML results by IP
        ml_map = {r["ip"]: r for r in ml_results}

        for alert in rule_alerts:
            ip = alert["ip"]
            rule_severity = alert["severity"]
            rule_reason = alert["reason"]

            ml_votes = ml_map.get(ip, {}).get("ml_prediction", {})
            attack_votes = sum(1 for v in ml_votes.values() if v == "attack")

            # -------------------------
            # BALANCED HYBRID LOGIC
            # -------------------------

            # Strong agreement → confirmed attack
            if rule_severity == "HIGH" and attack_votes >= 1:
                final_severity = "HIGH"
                final_reason = "Rule + ML agreement on attack"

            # Rule suspects but ML disagrees → downgrade
            elif rule_severity == "HIGH" and attack_votes == 0:
                final_severity = "MEDIUM"
                final_reason = "Rule-based suspicion (ML disagreement)"

            # Rule MEDIUM + ML support → escalate
            elif rule_severity == "MEDIUM" and attack_votes >= 1:
                final_severity = "HIGH"
                final_reason = "Rule + ML agreement on attack"

            # Pure ML detection
            elif attack_votes >= 2:
                final_severity = "MEDIUM"
                final_reason = "ML-based anomaly detected"

            else:
                continue  # ignore low-confidence events

            final_alerts.append({
                "ip": ip,
                "severity": final_severity,
                "reason": final_reason,
                "rule_reason": rule_reason,
                "ml_votes": ml_votes,
                "features": alert["features"]
            })

        return final_alerts
