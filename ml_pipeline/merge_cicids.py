import pandas as pd
import os

# Get project root (HYBRID-IDS/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RAW_DIR = os.path.join(
    BASE_DIR, "datasets", "cicids2017", "raw_csv"
)

MERGED_DIR = os.path.join(
    BASE_DIR, "datasets", "cicids2017", "merged"
)

MERGED_FILE = os.path.join(MERGED_DIR, "cicids_merged.csv")

print("[*] Raw CSV directory:", RAW_DIR)

# List all CSV files
csv_files = [f for f in os.listdir(RAW_DIR) if f.endswith(".csv")]

print(f"[*] Found {len(csv_files)} CSV files")

df_list = []

for file in csv_files:
    file_path = os.path.join(RAW_DIR, file)
    print("Reading:", file)
    df = pd.read_csv(file_path)
    df_list.append(df)

# Merge all CSVs
merged_df = pd.concat(df_list, ignore_index=True)
print("[*] Merged shape:", merged_df.shape)

# Ensure merged directory exists
os.makedirs(MERGED_DIR, exist_ok=True)

# Save merged dataset
merged_df.to_csv(MERGED_FILE, index=False)

print("[✓] Saved merged dataset to:", MERGED_FILE)
