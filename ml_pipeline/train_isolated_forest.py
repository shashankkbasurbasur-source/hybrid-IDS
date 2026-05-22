import pandas as pd
import os
import pickle

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report

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
# Load dataset
# -------------------------------
print("[*] Loading cleaned dataset...")
df = pd.read_csv(DATA_FILE)

print("[*] Total samples:", df.shape)

# -------------------------------
# Train Isolation Forest on BENIGN data only
# -------------------------------
print("[*] Selecting BENIGN traffic only...")
df_benign = df[df["Label"] == 0]

X_benign = df_benign.drop(columns=["Label"])

print("[*] Benign samples used for training:", X_benign.shape)

# -------------------------------
# Train Isolation Forest
# -------------------------------
print("[*] Training Isolation Forest...")

iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.1,     # expected anomaly proportion
    random_state=42,
    n_jobs=-1
)

iso_forest.fit(X_benign)

# -------------------------------
# Save model
# -------------------------------
with open(os.path.join(MODEL_DIR, "isolation_forest_model.pkl"), "wb") as f:
    pickle.dump(iso_forest, f)

print("[✓] Isolation Forest model saved")

# -------------------------------
# Sanity check on mixed data
# -------------------------------
print("[*] Performing sanity check...")

df_sample = df.sample(n=50000, random_state=42)
X_sample = df_sample.drop(columns=["Label"])
y_true = df_sample["Label"]

# Isolation Forest prediction
# IF output:  1 = normal, -1 = anomaly
y_pred_raw = iso_forest.predict(X_sample)

# Convert to IDS format: 0 = normal, 1 = attack
y_pred = [0 if x == 1 else 1 for x in y_pred_raw]

print("\n--- Isolation Forest Sanity Check ---")
print(classification_report(y_true, y_pred))

# -------------------------------
# Save report
# -------------------------------
report_path = os.path.join(RESULTS_DIR, "isolation_forest_report.txt")

with open(report_path, "w") as f:
    f.write("Isolation Forest Sanity Check\n")
    f.write(classification_report(y_true, y_pred))

print("[✓] Isolation Forest evaluation saved")
