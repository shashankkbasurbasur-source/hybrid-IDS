"""
ml_pipeline/train_random_forest.py

FIXED:
 - Label column is already 0/1 integers in cicids_clean.csv — skip str encoding
 - Drops NaN/Inf rows
 - Saves scaler.pkl (required by model_loader.py)
 - average='binary' for metrics
"""

import pandas as pd
import numpy as np
import os
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE   = os.path.join(BASE_DIR, "datasets", "cicids2017", "cleaned", "cicids_clean.csv")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(MODEL_DIR,   exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# ── Load ──────────────────────────────────────────────────────────────────────
print("[*] Loading cleaned dataset...")
df = pd.read_csv(DATA_FILE, low_memory=False)
df.columns = df.columns.str.strip()
print(f"[*] Raw dataset shape: {df.shape}")
print(f"[*] Label dtype: {df['Label'].dtype}  |  unique: {df['Label'].unique()}")

# ── Label is already 0/1 int — use it directly ────────────────────────────────
y = df["Label"].astype(int)

# ── Features: drop Label + any non-numeric / ID columns ──────────────────────
DROP_COLS = ["Label", "attack_type", "Flow ID",
             "Source IP", "Destination IP", "Timestamp", "timestamp"]
feature_cols = [c for c in df.columns if c not in DROP_COLS]
X = df[feature_cols]

# Drop any remaining object columns
obj_cols = X.select_dtypes(include=["object"]).columns.tolist()
if obj_cols:
    print(f"[!] Dropping non-numeric columns: {obj_cols}")
    X = X.drop(columns=obj_cols)

print(f"[*] Feature count: {X.shape[1]}")
print(f"[*] Class distribution — 0(BENIGN): {(y==0).sum()}  1(ATTACK): {(y==1).sum()}")

# ── Drop NaN / Inf ────────────────────────────────────────────────────────────
X = X.replace([np.inf, -np.inf], np.nan)
mask = X.notna().all(axis=1)
dropped = (~mask).sum()
if dropped:
    print(f"[!] Dropping {dropped} rows with NaN/Inf")
X = X[mask].astype(float)
y = y[mask]
print(f"[*] Clean shape: {X.shape}")

# ── Split ─────────────────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"[*] Train: {X_train.shape}  Test: {X_test.shape}")

# ── Scale ─────────────────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
with open(scaler_path, "wb") as f:
    pickle.dump(scaler, f)
print(f"[OK] Scaler saved: {scaler_path}")

# ── Train ─────────────────────────────────────────────────────────────────────
print("[*] Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_leaf=5,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
    verbose=1,
)
rf.fit(X_train_s, y_train)

# ── Evaluate ──────────────────────────────────────────────────────────────────
y_pred = rf.predict(X_test_s)
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average="binary", zero_division=0)
rec  = recall_score(y_test, y_pred,    average="binary", zero_division=0)
f1   = f1_score(y_test, y_pred,        average="binary", zero_division=0)

print(f"\n--- Random Forest ---")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1-score : {f1:.4f}")
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred,
      target_names=["BENIGN","ATTACK"], zero_division=0))

# ── Save model + feature columns ──────────────────────────────────────────────
model_path = os.path.join(MODEL_DIR, "random_forest_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump(rf, f)
print(f"[OK] Model saved: {model_path}")

cols_path = os.path.join(MODEL_DIR, "network_feature_columns.pkl")
with open(cols_path, "wb") as f:
    pickle.dump(list(X.columns), f)
print(f"[OK] Feature columns saved: {cols_path}")

# ── Save metrics ──────────────────────────────────────────────────────────────
metrics_path = os.path.join(RESULTS_DIR, "metrics_summary.csv")
row = pd.DataFrame([{"model":"Random Forest",
                      "accuracy":acc,"precision":prec,"recall":rec,"f1_score":f1}])
if os.path.exists(metrics_path):
    row.to_csv(metrics_path, mode="a", header=False, index=False)
else:
    row.to_csv(metrics_path, index=False)
print("[OK] Metrics saved: results/metrics_summary.csv")
print("[OK] Training completed successfully")