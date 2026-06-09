# ml_pipeline/train_hids_ssh.py
"""
Trains HIDS model on SSH behavioral log features.
Generates synthetic-but-realistic training data from SSH log patterns.

Saves: models/hids_ssh_model.pkl

Feature vector (100-dim, matches LogFeatureExtractor.extract()):
  [0]  total_fail
  [1]  total_success
  [2]  total_ips
  [3]  total_unique_users
  [4]  success_after_fail
  [5]  fail_success_ratio
  [6]  max_fail_per_ip
  [7]  events_per_ip
  [8..99] reserved / zero (for future extension)
"""

import os, pickle
import numpy as np
import pandas as pd

from sklearn.ensemble          import RandomForestClassifier
from sklearn.model_selection   import train_test_split
from sklearn.preprocessing     import StandardScaler
from sklearn.metrics           import classification_report, accuracy_score

BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(MODEL_DIR,   exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

rng = np.random.default_rng(42)

def make_normal(n=3000):
    """Simulate normal SSH sessions — low fail count, occasional success."""
    rows = []
    for _ in range(n):
        total_ips     = rng.integers(1, 8)
        total_fail    = rng.integers(0, 3)
        total_success = rng.integers(1, 10)
        unique_users  = rng.integers(1, 4)
        saf           = 0
        ratio         = total_fail / (total_success + 1)
        max_fail      = rng.integers(0, 3)
        evt_per_ip    = rng.uniform(1, 5)

        v = [0.0] * 100
        v[0], v[1], v[2], v[3] = float(total_fail), float(total_success), float(total_ips), float(unique_users)
        v[4], v[5], v[6], v[7] = float(saf), ratio, float(max_fail), evt_per_ip
        rows.append((v, 0))
    return rows

def make_brute_force(n=2000):
    """Simulate SSH brute-force — many failures, many users, sometimes success after fail."""
    rows = []
    for _ in range(n):
        total_ips     = rng.integers(1, 5)
        total_fail    = rng.integers(8, 60)
        total_success = rng.integers(0, 3)
        unique_users  = rng.integers(5, 30)
        saf           = 1 if (total_success > 0 and total_fail >= 5) else 0
        ratio         = total_fail / (total_success + 1)
        max_fail      = rng.integers(5, 50)
        evt_per_ip    = rng.uniform(8, 40)

        v = [0.0] * 100
        v[0], v[1], v[2], v[3] = float(total_fail), float(total_success), float(total_ips), float(unique_users)
        v[4], v[5], v[6], v[7] = float(saf), ratio, float(max_fail), evt_per_ip
        rows.append((v, 1))
    return rows

def make_credential_stuffing(n=1500):
    """Many IPs, each with a few attempts — credential stuffing pattern."""
    rows = []
    for _ in range(n):
        total_ips     = rng.integers(10, 50)
        total_fail    = rng.integers(10, 100)
        total_success = rng.integers(0, 5)
        unique_users  = rng.integers(10, 80)
        saf           = 1 if total_success > 0 else 0
        ratio         = total_fail / (total_success + 1)
        max_fail      = rng.integers(2, 10)
        evt_per_ip    = rng.uniform(1, 4)

        v = [0.0] * 100
        v[0], v[1], v[2], v[3] = float(total_fail), float(total_success), float(total_ips), float(unique_users)
        v[4], v[5], v[6], v[7] = float(saf), ratio, float(max_fail), evt_per_ip
        rows.append((v, 1))
    return rows

def make_insider(n=800):
    """Insider threat — single user, low fail count, success after fail."""
    rows = []
    for _ in range(n):
        total_ips     = rng.integers(1, 3)
        total_fail    = rng.integers(3, 8)
        total_success = rng.integers(1, 4)
        unique_users  = rng.integers(1, 2)
        saf           = 1
        ratio         = total_fail / (total_success + 1)
        max_fail      = rng.integers(3, 8)
        evt_per_ip    = rng.uniform(3, 10)

        v = [0.0] * 100
        v[0], v[1], v[2], v[3] = float(total_fail), float(total_success), float(total_ips), float(unique_users)
        v[4], v[5], v[6], v[7] = float(saf), ratio, float(max_fail), evt_per_ip
        rows.append((v, 1))
    return rows

# ── Build dataset ─────────────────────────────────────────────────────────────
print("[*] Generating training data...")
all_rows = make_normal() + make_brute_force() + make_credential_stuffing() + make_insider()
rng.shuffle(all_rows)   # type: ignore[arg-type]

X = np.array([r[0] for r in all_rows])
y = np.array([r[1] for r in all_rows])

print("[*] Dataset shape:", X.shape)
print("[*] Class balance — 0:", (y==0).sum(), "  1:", (y==1).sum())

# ── Split ─────────────────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Scale ─────────────────────────────────────────────────────────────────────
scaler      = StandardScaler()
X_train_sc  = scaler.fit_transform(X_train)
X_test_sc   = scaler.transform(X_test)

# ── Train ─────────────────────────────────────────────────────────────────────
print("[*] Training SSH HIDS model...")
rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
)
rf.fit(X_train_sc, y_train)

# ── Evaluate ──────────────────────────────────────────────────────────────────
y_pred = rf.predict(X_test_sc)
acc    = accuracy_score(y_test, y_pred)
print(f"\n[*] HIDS SSH Model Accuracy: {acc:.4f}")
print(classification_report(y_test, y_pred, target_names=["Normal", "Intrusion"]))

# ── Save as (model, scaler) tuple ─────────────────────────────────────────────
# model_loader checks for tuple and unpacks [0]=model, [1]=scaler
# We save (rf, scaler) so host_model.py can scale before predict
with open(os.path.join(MODEL_DIR, "hids_ssh_model.pkl"), "wb") as f:
    pickle.dump((rf, scaler), f)

report_path = os.path.join(RESULTS_DIR, "hids_ssh_report.txt")
with open(report_path, "w") as f:
    f.write(f"HIDS SSH Model\nAccuracy: {acc:.4f}\n\n")
    f.write(classification_report(y_test, y_pred, target_names=["Normal", "Intrusion"]))

print(f"\n[✓] hids_ssh_model.pkl saved")
print(f"[✓] Report saved to {report_path}")