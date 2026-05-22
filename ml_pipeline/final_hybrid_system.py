import os
import pickle
import numpy as np
import pandas as pd

from decision_normalizer import NormalizedDecision
from adfa_feature_extractor import extract_bigram_features

# -------------------------------
# Paths
# -------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
DATASET_DIR = os.path.join(BASE_DIR, "datasets")

# -------------------------------
# Load Models
# -------------------------------
with open(os.path.join(MODEL_DIR, "random_forest_model.pkl"), "rb") as f:
    nids_model = pickle.load(f)

with open(os.path.join(MODEL_DIR, "hids_model.pkl"), "rb") as f:
    hids_model, hids_vocab = pickle.load(f)

with open(os.path.join(MODEL_DIR, "scaler.pkl"), "rb") as f:
    scaler = pickle.load(f)

print("[✓] Models Loaded")


# =========================================================
# NIDS REAL INFERENCE (CICIDS SAMPLE)
# =========================================================
print("\n[*] Running NIDS inference...")

cleaned_cicids = os.path.join(DATASET_DIR, "cicids2017", "cleaned", "cicids_clean.csv")
df = pd.read_csv(cleaned_cicids)

sample_row = df.sample(1)

X_nids = sample_row.drop("Label", axis=1)
X_nids_scaled = scaler.transform(X_nids)

# Convert back to DataFrame with same column names
X_nids_scaled = pd.DataFrame(
    X_nids_scaled,
    columns=X_nids.columns
)


nids_pred = nids_model.predict(X_nids_scaled)[0]
nids_prob = max(nids_model.predict_proba(X_nids_scaled)[0])

nids_decision = NormalizedDecision(
    source="NIDS",
    decision=int(nids_pred),
    confidence=float(nids_prob)
)

print("NIDS Prediction:", nids_decision)


# =========================================================
# HIDS REAL INFERENCE (ADFA SAMPLE)
# =========================================================
print("\n[*] Running HIDS inference...")

adfa_validation_path = os.path.join(DATASET_DIR, "adfa-ld", "Validation_Data_Master")
sample_file = os.listdir(adfa_validation_path)[0]

with open(os.path.join(adfa_validation_path, sample_file), "r") as f:
    sequence = [int(x) for x in f.read().strip().split()]

hids_features = extract_bigram_features(sequence, hids_vocab)
hids_features = np.array(hids_features).reshape(1, -1)

hids_pred = hids_model.predict(hids_features)[0]
hids_prob = max(hids_model.predict_proba(hids_features)[0])

hids_decision = NormalizedDecision(
    source="HIDS",
    decision=int(hids_pred),
    confidence=float(hids_prob)
)

print("HIDS Prediction:", hids_decision)


# =========================================================
# INTELLIGENT FUSION
# =========================================================
def intelligent_hybrid_fusion(nids, hids):

    result = {
        "final_decision": None,
        "attack_domain": None,
        "confidence": 0.0,
        "triggered_by": [],
        "details": {
            "NIDS": {
                "decision": nids.decision,
                "confidence": round(nids.confidence, 4)
            },
            "HIDS": {
                "decision": hids.decision,
                "confidence": round(hids.confidence, 4)
            }
        }
    }

    if nids.decision == 0 and hids.decision == 0:
        result["final_decision"] = "NORMAL"
        result["attack_domain"] = "NONE"
        result["confidence"] = 1 - max(nids.confidence, hids.confidence)

    elif nids.decision == 1 and hids.decision == 0:
        result["final_decision"] = "ATTACK"
        result["attack_domain"] = "NETWORK_ONLY"
        result["confidence"] = nids.confidence
        result["triggered_by"].append("NIDS")

    elif nids.decision == 0 and hids.decision == 1:
        result["final_decision"] = "ATTACK"
        result["attack_domain"] = "HOST_ONLY"
        result["confidence"] = hids.confidence
        result["triggered_by"].append("HIDS")

    elif nids.decision == 1 and hids.decision == 1:
        result["final_decision"] = "CONFIRMED_INTRUSION"
        result["attack_domain"] = "NETWORK_AND_HOST"
        result["confidence"] = (nids.confidence + hids.confidence) / 2
        result["triggered_by"] = ["NIDS", "HIDS"]

    return result


fusion_output = intelligent_hybrid_fusion(nids_decision, hids_decision)

print("\n--- FINAL HYBRID INTELLIGENT OUTPUT ---")
for key, value in fusion_output.items():
    print(f"{key}: {value}")
 
