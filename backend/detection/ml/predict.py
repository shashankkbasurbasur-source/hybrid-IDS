import pickle
import numpy as np

class MLPredictor:
    """
    Loads trained ML models and performs intrusion prediction.
    """

    def __init__(self, model_path="backend/detection/ml/models.pkl"):
        with open(model_path, "rb") as f:
            self.models = pickle.load(f)

    def predict(self, feature_rows):
        results = []

        for f in feature_rows:
            X = np.array([[
                f["fail_count"],
                f["unique_users"],
                f["success_after_fail"]
            ]])

            predictions = {}

            for name, model in self.models.items():

                # Isolation Forest logic
                if name == "isolation_forest":
                    pred = model.predict(X)[0]
                    predictions[name] = "attack" if pred == -1 else "normal"

                # Supervised models
                else:
                    pred = model.predict(X)[0]
                    predictions[name] = "attack" if pred == 1 else "normal"

            results.append({
                "ip": f["ip"],
                "ml_prediction": predictions,
                "features": f
            })

        return results
