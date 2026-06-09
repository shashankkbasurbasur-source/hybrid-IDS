# ml_pipeline/preprocess_cicids.py

import pandas as pd
import numpy as np
import os

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MERGED_FILE = os.path.join(BASE_DIR, "datasets", "cicids2017", "merged", "cicids_merged.csv")
CLEAN_DIR   = os.path.join(BASE_DIR, "datasets", "cicids2017", "cleaned")
CLEAN_FILE  = os.path.join(CLEAN_DIR, "cicids_clean.csv")

# ── Attack type mapping (CICIDS2017 labels → canonical names) ─────────────────
ATTACK_MAP = {
    "BENIGN"                      : "BENIGN",
    "DoS Hulk"                    : "DoS",
    "DoS GoldenEye"               : "DoS",
    "DoS slowloris"               : "DoS",
    "DoS Slowhttptest"            : "DoS",
    "DDoS"                        : "DDoS",
    "PortScan"                    : "PortScan",
    "FTP-Patator"                 : "BruteForce",
    "SSH-Patator"                 : "BruteForce",
    "Bot"                         : "Botnet",
    "Web Attack \x96 Brute Force": "WebAttack",
    "Web Attack – Brute Force"    : "WebAttack",
    "Web Attack \x96 XSS"        : "WebAttack",
    "Web Attack – XSS"            : "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Web Attack – Sql Injection"  : "WebAttack",
    "Infiltration"                : "Infiltration",
    "Heartbleed"                  : "Heartbleed",
}

print("[*] Loading merged dataset...")
df = pd.read_csv(MERGED_FILE)
df.columns = df.columns.str.strip()

print("[*] Shape:", df.shape)

DROP_COLS = ["Flow ID", "Source IP", "Destination IP", "Timestamp",
             "Source Port", "Destination Port"]
df.drop(columns=DROP_COLS, inplace=True, errors="ignore")

if "Label" not in df.columns:
    raise Exception("Label column not found")

# ── Preserve attack_type BEFORE binarising ────────────────────────────────────
df["Label"] = df["Label"].str.strip()
df["attack_type"] = df["Label"].map(ATTACK_MAP).fillna("Unknown")

print("[*] Attack type distribution:")
print(df["attack_type"].value_counts())

# ── Binary label ──────────────────────────────────────────────────────────────
df["Label"] = (df["attack_type"] != "BENIGN").astype(int)

print("[*] Binary label distribution:")
print(df["Label"].value_counts())

# ── Clean ─────────────────────────────────────────────────────────────────────
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

for col in df.columns:
    if col not in ("Label", "attack_type"):
        df[col] = pd.to_numeric(df[col], errors="coerce")

df.dropna(inplace=True)
print("[*] Final shape:", df.shape)

os.makedirs(CLEAN_DIR, exist_ok=True)
df.to_csv(CLEAN_FILE, index=False)
print("[✓] Saved:", CLEAN_FILE)