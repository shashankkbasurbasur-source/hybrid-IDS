from dataclasses import dataclass

@dataclass
class NormalizedDecision:
    source: str        # "NIDS" or "HIDS"
    decision: int      # 0 = Normal, 1 = Attack
    confidence: float  # 0.0 – 1.0


class DecisionNormalizer:
    """
    Normalizes outputs from different IDS components (NIDS/HIDS)
    into a common decision format.
    """

    @staticmethod
    def from_supervised_model(source, prediction, probability):
        """
        Used for Logistic Regression / Random Forest (NIDS).
        """
        return NormalizedDecision(
            source=source,
            decision=int(prediction),
            confidence=float(probability)
        )

    @staticmethod
    def from_anomaly_model(source, anomaly_score, threshold):
        """
        Used for Isolation Forest / HIDS anomaly detectors.
        """
        decision = 1 if anomaly_score >= threshold else 0

        # Confidence = distance from threshold (normalized)
        confidence = min(abs(anomaly_score - threshold) / threshold, 1.0)

        return NormalizedDecision(
            source=source,
            decision=decision,
            confidence=confidence
        )

if __name__ == "__main__":
    # Simulate NIDS output
    nids_decision = DecisionNormalizer.from_supervised_model(
        source="NIDS",
        prediction=1,
        probability=0.97
    )

    # Simulate HIDS output
    hids_decision = DecisionNormalizer.from_anomaly_model(
        source="HIDS",
        anomaly_score=0.82,
        threshold=0.6
    )

    print(nids_decision)
    print(hids_decision)
