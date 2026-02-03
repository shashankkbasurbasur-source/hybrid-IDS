import os
import pickle
import numpy as np
import pandas as pd

from sklearn.metrics import classification_report

# -------------------------------
# Paths
# -------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_FILE = os.path.join(
    BASE_DIR, "datasets", "cicids2017", "cleaned", "cicids_clean.csv"
)

# -------------------------------
# Load trained models
# -------------------------------
print("[*] Loading trained models...")

with open(os.path.join(MODEL_DIR, "logistic_model.pkl"), "rb") as f:
    lr = pickle.load(f)

with open(os.path.join(MODEL_DIR, "random_forest_model.pkl"), "rb") as f:
    rf = pickle.load(f)

with open(os.path.join(MODEL_DIR, "isolation_forest_model.pkl"), "rb") as f:
    iso = pickle.load(f)

with open(os.path.join(MODEL_DIR, "scaler.pkl"), "rb") as f:
    scaler = pickle.load(f)

print("[✓] All models loaded successfully")

# -------------------------------
# Load sample data
# -------------------------------
print("[*] Loading sample data for fusion test...")
df = pd.read_csv(DATA_FILE).sample(n=10000, random_state=42)

X = df.drop(columns=["Label"])
y_true = df["Label"]

# -------------------------------
# Individual model predictions
# -------------------------------
X_scaled = scaler.transform(X)

lr_pred = lr.predict(X_scaled)               # 0 / 1
rf_pred = rf.predict(X)                      # 0 / 1
iso_raw = iso.predict(X)                     # 1 / -1
iso_pred = np.where(iso_raw == 1, 0, 1)      # map to 0 / 1

# -------------------------------
# DEBUG: verify predictions
# -------------------------------
print("\n[DEBUG] Prediction distribution:")
print("Logistic Regression:", np.unique(lr_pred, return_counts=True))
print("Random Forest      :", np.unique(rf_pred, return_counts=True))
print("Isolation Forest   :", np.unique(iso_pred, return_counts=True))

# -------------------------------
# Hybrid fusion (weighted voting)
# -------------------------------
hybrid_score = (
    0.3 * lr_pred +
    0.5 * rf_pred +
    0.2 * iso_pred
)

hybrid_pred = (hybrid_score >= 0.5).astype(int)

# -------------------------------
# Evaluation
# -------------------------------
print("\n--- HYBRID IDS RESULTS ---")
print(classification_report(y_true, hybrid_pred))
