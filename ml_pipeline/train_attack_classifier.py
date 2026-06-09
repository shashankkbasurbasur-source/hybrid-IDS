# ml_pipeline/train_attack_classifier.py
"""
Trains a multi-class attack classifier on CICIDS2017.
Saves: models/attack_classifier.pkl  (RandomForest, multi-class)
       models/attack_label_encoder.pkl (LabelEncoder)
       models/attack_scaler.pkl
"""

import os, pickle
import pandas as pd
import numpy as np

from sklearn.model_selection   import train_test_split
from sklearn.preprocessing     import LabelEncoder, StandardScaler
from sklearn.ensemble          import RandomForestClassifier
from sklearn.metrics           import classification_report, accuracy_score

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE   = os.path.join(BASE_DIR, "datasets", "cicids2017", "cleaned", "cicids_clean.csv")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

os.makedirs(MODEL_DIR,   exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# ── Load ──────────────────────────────────────────────────────────────────────
print("[*] Loading dataset...")
df = pd.read_csv(DATA_FILE)

# attack_type column must exist (run preprocess_cicids.py first)
if "attack_type" not in df.columns:
    raise Exception("attack_type column missing — re-run preprocess_cicids.py")

X = df.drop(columns=["Label", "attack_type"])
y_str = df["attack_type"]

print("[*] Class distribution:")
print(y_str.value_counts())

# ── Encode labels ─────────────────────────────────────────────────────────────
le = LabelEncoder()
y  = le.fit_transform(y_str)

print("[*] Label mapping:", dict(zip(le.classes_, le.transform(le.classes_))))

# ── Split ─────────────────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Scale ─────────────────────────────────────────────────────────────────────
scaler       = StandardScaler()
X_train_sc   = scaler.fit_transform(X_train)
X_test_sc    = scaler.transform(X_test)

# ── Train ─────────────────────────────────────────────────────────────────────
print("[*] Training multi-class Random Forest...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=2,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
)
rf.fit(X_train_sc, y_train)

# ── Evaluate ──────────────────────────────────────────────────────────────────
y_pred = rf.predict(X_test_sc)
acc    = accuracy_score(y_test, y_pred)
print(f"\n[*] Accuracy: {acc:.4f}")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ── Save ──────────────────────────────────────────────────────────────────────
with open(os.path.join(MODEL_DIR, "attack_classifier.pkl"),     "wb") as f: pickle.dump(rf, f)
with open(os.path.join(MODEL_DIR, "attack_label_encoder.pkl"),  "wb") as f: pickle.dump(le, f)
with open(os.path.join(MODEL_DIR, "attack_scaler.pkl"),         "wb") as f: pickle.dump(scaler, f)

report_path = os.path.join(RESULTS_DIR, "attack_classifier_report.txt")
with open(report_path, "w") as f:
    f.write(f"Multi-class Attack Classifier\nAccuracy: {acc:.4f}\n\n")
    f.write(classification_report(y_test, y_pred, target_names=le.classes_))

print(f"\n[✓] attack_classifier.pkl saved")
print(f"[✓] attack_label_encoder.pkl saved")
print(f"[✓] attack_scaler.pkl saved")
print(f"[✓] Report saved to {report_path}")