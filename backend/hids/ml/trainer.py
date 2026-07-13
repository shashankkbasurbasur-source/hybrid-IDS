"""
HIDS Trainer
=============
PRIMARY / PRODUCTION PATH: train() trains hids_model.pkl on REAL
labeled auth-log data via dataset_builder.py. This is the only
training path whose results should be reported in the paper/thesis.

SECONDARY / DEV-ONLY PATH: train_bootstrap() trains on synthetic data
from research/hids_bootstrap/synthetic_data.py. Prints a warning,
saves to a distinct filename (hids_model_bootstrap.pkl).
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

from backend.hids.features.feature_extractor import AuthLogFeatureExtractor
from backend.hids.features.feature_schema import FEATURE_VECTOR_LENGTH
from backend.hids.ml.dataset_builder import build_dataset_from_logs

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
MODEL_DIR = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")


class HIDSTrainer:
    def __init__(self):
        self.extractor = AuthLogFeatureExtractor()

    def build_feature_matrix(self, labeled_windows):
        X, y = [], []
        for events, label in labeled_windows:
            vector = self.extractor.extract(events)
            X.append(vector)
            y.append(label)
        return np.array(X), np.array(y)

    def _fit_and_evaluate(self, X, y, seed=42):
        assert X.shape[1] == FEATURE_VECTOR_LENGTH

        unique, counts = np.unique(y, return_counts=True)
        print("[*] Class distribution:", dict(zip(unique.tolist(), counts.tolist())))
        if len(unique) < 2:
            raise ValueError(
                "Training data contains only one class. Provide labeled "
                "examples of both normal (0) and attack (1) behavior."
            )

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=seed, stratify=y
        )

        rf = RandomForestClassifier(
            n_estimators=200, random_state=seed, n_jobs=-1, class_weight="balanced",
        )
        rf.fit(X_train, y_train)

        y_pred = rf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, zero_division=0)
        print(f"\n[*] Test accuracy: {acc:.4f}")
        print(report)
        return rf, acc, report

    def _save(self, rf, acc, report, tag):
        os.makedirs(MODEL_DIR, exist_ok=True)
        model_path = os.path.join(MODEL_DIR, f"{tag}.pkl")
        with open(model_path, "wb") as f:
            pickle.dump(rf, f)
        print(f"[✓] HIDS model saved to {model_path}")

        os.makedirs(RESULTS_DIR, exist_ok=True)
        report_path = os.path.join(RESULTS_DIR, f"{tag}_report.txt")
        with open(report_path, "w") as f:
            f.write("HIDS (auth-log schema) Evaluation\n")
            f.write(f"Test accuracy: {acc:.4f}\n\n")
            f.write(report)
        print(f"[✓] Report saved to {report_path}")

    def train(self, log_file_paths: list, labels_csv_path: str, seed: int = 42, save: bool = True):
        """PRODUCTION: trains hids_model.pkl on real labeled auth-log windows."""
        print("[*] Loading real labeled auth-log dataset...")
        labeled_windows = build_dataset_from_logs(log_file_paths, labels_csv_path)

        print(f"[*] Extracting features for {len(labeled_windows)} labeled windows...")
        X, y = self.build_feature_matrix(labeled_windows)

        rf, acc, report = self._fit_and_evaluate(X, y, seed=seed)
        if save:
            self._save(rf, acc, report, tag="hids_model")
        return rf, acc, report

    def train_bootstrap(self, n_windows: int = 4000, seed: int = 42, save: bool = True):
        """DEV-ONLY: synthetic bootstrap. Never cite results from this."""
        print("=" * 70)
        print("[!] WARNING: training on SYNTHETIC bootstrap data.")
        print("[!] This model is for local development/demo only.")
        print("[!] Do NOT report results from this model as HIDS performance.")
        print("=" * 70)

        from research.hids_bootstrap.synthetic_data import generate_dataset
        labeled_windows = generate_dataset(n_windows=n_windows, seed=seed)
        X, y = self.build_feature_matrix(labeled_windows)

        rf, acc, report = self._fit_and_evaluate(X, y, seed=seed)
        if save:
            self._save(rf, acc, report, tag="hids_model_bootstrap")
        return rf, acc, report


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]

    if args and args[0] == "--bootstrap":
        HIDSTrainer().train_bootstrap()
    elif len(args) >= 2:
        log_files = args[0].split(",")
        labels_csv = args[1]
        HIDSTrainer().train(log_files, labels_csv)
    else:
        print("Usage:")
        print("  python -m backend.hids.ml.trainer <log_file[,log_file2,...]> <labels.csv>   # production")
        print("  python -m backend.hids.ml.trainer --bootstrap                                # dev-only, synthetic")
        sys.exit(1)