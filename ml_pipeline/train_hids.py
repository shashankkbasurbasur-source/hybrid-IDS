import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from adfa_parser import load_adfa_sequences
from adfa_feature_extractor import (
    build_bigram_vocabulary,
    build_feature_matrix
)

# -------------------------------
# Paths
# -------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADFA_PATH = os.path.join(BASE_DIR, "datasets", "adfa-ld")
MODEL_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# -------------------------------
# Load ADFA-LD
# -------------------------------
normal_sequences, attack_sequences, validation_sequences = load_adfa_sequences(ADFA_PATH)

# -------------------------------
# Build Bigram Vocabulary (from NORMAL only)
# -------------------------------
print("[*] Building bigram vocabulary...")
vocab = build_bigram_vocabulary(normal_sequences, top_k=100)

# -------------------------------
# Feature Extraction
# -------------------------------
print("[*] Extracting bigram features...")

X_normal = build_feature_matrix(normal_sequences, vocab)
X_attack = build_feature_matrix(attack_sequences, vocab)

# Labels
y_normal = np.zeros(len(X_normal))
y_attack = np.ones(len(X_attack))

# Combine dataset
X = np.vstack([X_normal, X_attack])
y = np.concatenate([y_normal, y_attack])

print("Feature shape:", X.shape)

# -------------------------------
# Train Random Forest
# -------------------------------
print("[*] Training HIDS Random Forest...")

rf = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)

rf.fit(X, y)

# -------------------------------
# Save model
# -------------------------------
with open(os.path.join(MODEL_DIR, "hids_model.pkl"), "wb") as f:
    pickle.dump((rf, vocab), f)

print("[✓] HIDS Random Forest model saved")

# -------------------------------
# Evaluate
# -------------------------------

# Split into train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,
    random_state=42,
    stratify=y
)

rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)

print("[*] Proper Evaluation:")
print(classification_report(y_test, y_pred))
