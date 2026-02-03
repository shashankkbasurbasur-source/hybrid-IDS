import pandas as pd
import numpy as np
import os
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

# -------------------------------
# Paths
# -------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_FILE = os.path.join(
    BASE_DIR, "datasets", "cicids2017", "cleaned", "cicids_clean.csv"
)

MODEL_DIR = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# -------------------------------
# Load data
# -------------------------------
print("[*] Loading cleaned dataset...")
df = pd.read_csv(DATA_FILE)

X = df.drop(columns=["Label"])
y = df["Label"]

print("[*] Dataset shape:", X.shape)

# -------------------------------
# Train-test split
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("[*] Train size:", X_train.shape)
print("[*] Test size :", X_test.shape)

# -------------------------------
# Train Random Forest
# -------------------------------
print("[*] Training Random Forest...")

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    random_state=42,
    n_jobs=-1
)

rf.fit(X_train, y_train)

# -------------------------------
# Evaluate
# -------------------------------
print("[*] Evaluating model...")
y_pred = rf.predict(X_test)

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n--- Random Forest Metrics ---")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1-score : {f1:.4f}")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# -------------------------------
# Save model
# -------------------------------
with open(os.path.join(MODEL_DIR, "random_forest_model.pkl"), "wb") as f:
    pickle.dump(rf, f)

# -------------------------------
# Append results to metrics_summary.csv
# -------------------------------
metrics_path = os.path.join(RESULTS_DIR, "metrics_summary.csv")

new_metrics = pd.DataFrame([{
    "model": "Random Forest",
    "accuracy": acc,
    "precision": prec,
    "recall": rec,
    "f1_score": f1
}])

if os.path.exists(metrics_path):
    new_metrics.to_csv(metrics_path, mode="a", header=False, index=False)
else:
    new_metrics.to_csv(metrics_path, index=False)

print("\n[✓] Random Forest model saved")
print("[✓] Metrics appended to results/")
