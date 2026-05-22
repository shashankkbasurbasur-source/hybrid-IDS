import pandas as pd
import numpy as np
import os
import pickle

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
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
# Feature scaling
# -------------------------------
print("[*] Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# -------------------------------
# Train Logistic Regression
# -------------------------------
print("[*] Training Logistic Regression...")
lr = LogisticRegression(
    max_iter=1000,
    n_jobs=-1,
    solver="lbfgs"
)

lr.fit(X_train_scaled, y_train)

# -------------------------------
# Evaluate
# -------------------------------
print("[*] Evaluating model...")
y_pred = lr.predict(X_test_scaled)

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n--- Logistic Regression Metrics ---")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1-score : {f1:.4f}")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# -------------------------------
# Save model & scaler
# -------------------------------
with open(os.path.join(MODEL_DIR, "logistic_model.pkl"), "wb") as f:
    pickle.dump(lr, f)

with open(os.path.join(MODEL_DIR, "scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)

# -------------------------------
# Save results
# -------------------------------
metrics_path = os.path.join(RESULTS_DIR, "metrics_summary.csv")

metrics_df = pd.DataFrame([{
    "model": "Logistic Regression",
    "accuracy": acc,
    "precision": prec,
    "recall": rec,
    "f1_score": f1
}])

metrics_df.to_csv(metrics_path, index=False)

report_path = os.path.join(RESULTS_DIR, "evaluation_report.txt")

with open(report_path, "w") as f:
    f.write("Logistic Regression Evaluation\n")
    f.write(classification_report(y_test, y_pred))

print("\n[✓] Logistic Regression model saved")
print("[✓] Scaler saved")
print("[✓] Metrics written to results/")
