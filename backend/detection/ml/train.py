import pickle
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest

class MLTrainer:
    """
    Trains ML models for intrusion detection
    """

    def prepare_data(self, feature_rows):
        X = []
        y = []

        for f in feature_rows:
            X.append([
                f["fail_count"],
                f["unique_users"],
                f["success_after_fail"]
            ])
            y.append(1 if f["label"] == "attack" else 0)

        unique, counts = np.unique(y, return_counts=True)
        print("class distribution:", dict(zip(unique, counts)))

        return np.array(X), np.array(y)

    def train(self, features):
        X, y = self.prepare_data(features)

        models = {}

        # Logistic Regression
        lr = LogisticRegression(max_iter=500)
        lr.fit(X, y)
        models["logistic"] = lr

        # Random Forest
        rf = RandomForestClassifier(n_estimators=50, random_state=42)
        rf.fit(X, y)
        models["random_forest"] = rf

        # Isolation Forest (unsupervised)
        iso = IsolationForest(
            n_estimators=100,
            contamination=0.2,
            random_state=42
        )
        iso.fit(X)
        models["isolation_forest"] = iso

        # Save models
        with open("backend/detection/ml/models.pkl", "wb") as f:
            pickle.dump(models, f)

        return models
