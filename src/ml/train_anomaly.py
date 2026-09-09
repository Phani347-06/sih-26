import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from pathlib import Path


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BENIGN_SAMPLES = 100_000

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


# --------------------------------------------------
# 1. Load benign traffic
# --------------------------------------------------

print("Loading processed dataset...")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

df = pd.read_csv(
    PROJECT_ROOT / "data" / "processed" / "processed_dataset.csv"
)

benign = df[df["Label"] == "BENIGN"].copy()

print("Total benign flows:", len(benign))


# --------------------------------------------------
# 2. Sample benign traffic
# --------------------------------------------------

if len(benign) > BENIGN_SAMPLES:
    benign = benign.sample(
        BENIGN_SAMPLES,
        random_state=42
    )

print("Training samples:", len(benign))


# --------------------------------------------------
# 3. Prepare features
# --------------------------------------------------

X_train = benign[FEATURES].copy()

X_train = X_train.replace(
    [np.inf, -np.inf],
    np.nan
)

X_train = X_train.fillna(0)


# --------------------------------------------------
# 4. Train Isolation Forest
# --------------------------------------------------

print("\nTraining Isolation Forest...")

model = IsolationForest(
    n_estimators=150,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train)


# --------------------------------------------------
# 5. Save model
# --------------------------------------------------

joblib.dump(
    model,
    PROJECT_ROOT / "models" / "isolation_forest.pkl"
)

print("\nModel saved as isolation_forest.pkl")


# --------------------------------------------------
# 6. Test against Web Attacks
# --------------------------------------------------

print("\nLoading Web Attack dataset...")

web_file = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
)

web = pd.read_csv(
    web_file,
    encoding="latin1"
)

web.columns = web.columns.str.strip()

web["Label"] = (
    web["Label"]
    .astype(str)
    .str.strip()
)

web = web.drop_duplicates()

web[FEATURES] = web[FEATURES].apply(
    pd.to_numeric,
    errors="coerce"
)

web[FEATURES] = web[FEATURES].replace(
    [np.inf, -np.inf],
    np.nan
)

web[FEATURES] = web[FEATURES].fillna(0)


# --------------------------------------------------
# 7. Detect anomalies
# --------------------------------------------------

X_test = web[FEATURES]

predictions = model.predict(X_test)

# Isolation Forest:
# -1 = anomaly
#  1 = normal

web["Anomaly"] = predictions

print("\n" + "=" * 60)
print("ANOMALY RESULTS")
print("=" * 60)

for label, group in web.groupby("Label"):

    total = len(group)

    anomalies = (group["Anomaly"] == -1).sum()

    percentage = (
        anomalies / total
    ) * 100

    print(
        f"{label:<35} "
        f"{anomalies:>6}/{total:<6} "
        f"({percentage:>6.2f}% anomalous)"
    )