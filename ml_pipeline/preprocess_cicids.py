import pandas as pd
import numpy as np
import os

# Project root (HYBRID-IDS)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MERGED_FILE = os.path.join(
    BASE_DIR, "datasets", "cicids2017", "merged", "cicids_merged.csv"
)

CLEAN_DIR = os.path.join(
    BASE_DIR, "datasets", "cicids2017", "cleaned"
)

CLEAN_FILE = os.path.join(CLEAN_DIR, "cicids_clean.csv")

print("[*] Loading merged dataset...")
df = pd.read_csv(MERGED_FILE)

# ✅ CRITICAL FIX: STRIP COLUMN NAMES
df.columns = df.columns.str.strip()

print("[*] Columns after strip:")
print(df.columns.tolist())

print("[*] Original shape:", df.shape)

# -------------------------------
# Drop leakage columns (if present)
# -------------------------------
DROP_COLS = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp"
]

df.drop(columns=DROP_COLS, inplace=True, errors="ignore")
print("[*] After dropping leakage columns:", df.shape)

# -------------------------------
# Convert labels to binary
# -------------------------------
if "Label" not in df.columns:
    raise Exception("❌ Label column still not found after stripping")

print("[*] Converting labels to binary...")

df["Label"] = df["Label"].apply(
    lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
)

print("[*] Label distribution:")
print(df["Label"].value_counts())

# -------------------------------
# Handle Inf and NaN
# -------------------------------
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
print("[*] After NaN/Inf cleanup:", df.shape)

# -------------------------------
# Ensure numeric features
# -------------------------------
for col in df.columns:
    if col != "Label":
        df[col] = pd.to_numeric(df[col], errors="coerce")

df.dropna(inplace=True)
print("[*] After numeric conversion:", df.shape)

# -------------------------------
# Save cleaned dataset
# -------------------------------
os.makedirs(CLEAN_DIR, exist_ok=True)
df.to_csv(CLEAN_FILE, index=False)

print("[✓] Clean dataset saved to:", CLEAN_FILE)
