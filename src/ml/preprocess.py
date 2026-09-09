import pandas as pd
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "raw"

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]

# Features we will eventually reproduce from TShark
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
]

frames = []

for filename in FILES:

    path = DATA_DIR / filename

    print(f"\nLoading: {filename}")

    df = pd.read_csv(path, encoding="latin1")

    # Clean column names
    df.columns = df.columns.str.strip()

    # Remove completely empty columns
    df = df.dropna(axis=1, how="all")

    # Remove duplicate rows
    before = len(df)
    df = df.drop_duplicates()
    print(f"Removed duplicates: {before - len(df)}")

    # Check required columns
    missing_features = [
        f for f in FEATURES
        if f not in df.columns
    ]

    if missing_features:
        print("Missing features:")
        print(missing_features)
        continue

    # Keep only required features + label
    df = df[FEATURES + ["Label"]]

    # Clean labels
    df["Label"] = df["Label"].astype(str).str.strip()

    # Convert features to numeric
    for feature in FEATURES:
        df[feature] = pd.to_numeric(
            df[feature],
            errors="coerce"
        )

    frames.append(df)

    print("Rows:", len(df))


# Combine everything
data = pd.concat(frames, ignore_index=True)

print("\n" + "=" * 60)
print("COMBINED DATASET")
print("=" * 60)

print("Shape:", data.shape)

print("\nLabels:")
print(data["Label"].value_counts())


# Replace infinity with NaN
data = data.replace([np.inf, -np.inf], np.nan)

# Remove rows containing missing values
before = len(data)
data = data.dropna()

print("\nRows removed because of NaN/inf:", before - len(data))

# Save processed dataset

output = PROJECT_ROOT / "data" / "processed" / "processed_dataset.csv"

data.to_csv(output, index=False)

print("\nSaved:", output)
print("Final shape:", data.shape)