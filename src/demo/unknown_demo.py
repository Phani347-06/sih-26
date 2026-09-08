import json
import uuid
import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN


# ============================================================
# CONFIG
# ============================================================

RF_MODEL_FILE = "../../models/random_forest_model.pkl"
IF_MODEL_FILE = "../../models/isolation_forest.pkl"
PATTERN_STORE_FILE = "../output/pattern_store.json"

RF_CONFIDENCE_THRESHOLD = 0.70

# Deliberately permissive for the controlled demo
DBSCAN_EPS = 5.0
DBSCAN_MIN_SAMPLES = 3


# ============================================================
# FEATURES
# ============================================================

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
    "Down/Up Ratio"
]


# ============================================================
# LOAD MODELS
# ============================================================

print("=" * 65)
print(" SYNTHETIC UNKNOWN BEHAVIOR DEMO")
print("=" * 65)

rf_model = joblib.load(RF_MODEL_FILE)
print("Random Forest loaded.")

isolation_forest = joblib.load(IF_MODEL_FILE)
print("Isolation Forest loaded.")


# ============================================================
# GENERATE SYNTHETIC UNKNOWN BEHAVIOR
# ============================================================

rng = np.random.default_rng(42)

base_behavior = np.array([
    5000,       # Flow Duration
    220,        # Total Fwd Packets
    5,          # Total Backward Packets
    30000,      # Total Length Fwd
    500,        # Total Length Bwd
    136,        # Fwd Packet Length Mean
    100,        # Bwd Packet Length Mean
    600000,     # Flow Bytes/s
    50,         # Flow Packets/s
    20,         # Flow IAT Mean
    4,          # Flow IAT Std
    20,         # Fwd IAT Mean
    40,         # Bwd IAT Mean
    0,          # Fwd PSH
    0,          # Bwd PSH
    4400,       # Fwd Header Length
    100,        # Bwd Header Length
    135,        # Packet Length Mean
    10,         # Packet Length Std
    0,          # SYN
    2,          # ACK
    0.023       # Down/Up
], dtype=float)


# Very small variation around the same behavior.
# This makes observations similar but not identical.

noise_scale = np.array([
    30,
    2,
    0.5,
    100,
    10,
    1,
    1,
    3000,
    0.3,
    0.2,
    0.1,
    0.2,
    0.2,
    0,
    0,
    20,
    5,
    1,
    0.5,
    0,
    0,
    0.001
], dtype=float)


rows = []

for _ in range(30):

    values = base_behavior + rng.normal(
        0,
        noise_scale
    )

    # Keep discrete/count features valid
    values[13] = 0
    values[14] = 0
    values[19] = 0
    values[20] = 2

    rows.append(values)


df = pd.DataFrame(
    rows,
    columns=FEATURES
)

X = df[FEATURES].astype(float)


# ============================================================
# RANDOM FOREST
# ============================================================

rf_predictions = rf_model.predict(X)
rf_probabilities = rf_model.predict_proba(X)
rf_confidences = np.max(
    rf_probabilities,
    axis=1
)


print()
print("Random Forest predictions:")

prediction_counts = pd.Series(
    rf_predictions
).value_counts()

for label, count in prediction_counts.items():
    print(f"  {label}: {count}")


# ============================================================
# ISOLATION FOREST
# ============================================================

if_predictions = isolation_forest.predict(X)

unknown_indices = []

for i in range(len(X)):

    rf_prediction = rf_predictions[i]
    rf_confidence = rf_confidences[i]

    is_anomalous = (
        if_predictions[i] == -1
    )

    known_threat = (
        rf_prediction != "BENIGN"
        and
        rf_confidence >= RF_CONFIDENCE_THRESHOLD
    )

    if is_anomalous and not known_threat:
        unknown_indices.append(i)


print()
print(
    f"Unknown candidates: "
    f"{len(unknown_indices)} / {len(X)}"
)


# ============================================================
# DBSCAN
# ============================================================

if len(unknown_indices) < DBSCAN_MIN_SAMPLES:

    print()
    print("Not enough unknown observations for DBSCAN.")

    with open(
        PATTERN_STORE_FILE,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump([], f, indent=2)

    raise SystemExit


unknown_X = X.iloc[
    unknown_indices
]


scaler = StandardScaler()

unknown_scaled = scaler.fit_transform(
    unknown_X
)


dbscan = DBSCAN(
    eps=DBSCAN_EPS,
    min_samples=DBSCAN_MIN_SAMPLES
)

cluster_labels = dbscan.fit_predict(
    unknown_scaled
)


cluster_ids = sorted(
    set(cluster_labels) - {-1}
)


print()
print(
    f"DBSCAN clusters: "
    f"{len(cluster_ids)}"
)


# ============================================================
# PATTERN DISCOVERY
# ============================================================

patterns = []


for cluster_id in cluster_ids:

    cluster_positions = np.where(
        cluster_labels == cluster_id
    )[0]

    cluster_original_indices = [
        unknown_indices[i]
        for i in cluster_positions
    ]

    cluster_data = X.iloc[
        cluster_original_indices
    ]

    cluster_size = len(
        cluster_data
    )


    if cluster_size < DBSCAN_MIN_SAMPLES:
        continue


    pattern_id = (
        "P-" +
        str(uuid.uuid4())[:6].upper()
    )


    # --------------------------------------------------------
    # Behavioral signature
    # --------------------------------------------------------

    signature = {

        "avg_flow_duration":
            float(
                cluster_data[
                    "Flow Duration"
                ].mean()
            ),

        "avg_forward_packets":
            float(
                cluster_data[
                    "Total Fwd Packets"
                ].mean()
            ),

        "avg_backward_packets":
            float(
                cluster_data[
                    "Total Backward Packets"
                ].mean()
            ),

        "avg_forward_bytes":
            float(
                cluster_data[
                    "Total Length of Fwd Packets"
                ].mean()
            ),

        "avg_backward_bytes":
            float(
                cluster_data[
                    "Total Length of Bwd Packets"
                ].mean()
            ),

        "avg_packet_rate":
            float(
                cluster_data[
                    "Flow Packets/s"
                ].mean()
            ),

        "avg_byte_rate":
            float(
                cluster_data[
                    "Flow Bytes/s"
                ].mean()
            ),

        "avg_packet_size":
            float(
                cluster_data[
                    "Packet Length Mean"
                ].mean()
            ),

        "avg_packet_size_std":
            float(
                cluster_data[
                    "Packet Length Std"
                ].mean()
            ),

        "avg_flow_iat":
            float(
                cluster_data[
                    "Flow IAT Mean"
                ].mean()
            )
    }


    pattern = {

        "pattern_id":
            pattern_id,

        "classification":
            "UNKNOWN_BEHAVIOR",

        "status":
            "NEW",

        "cluster_id":
            int(cluster_id),

        "cluster_size":
            cluster_size,

        "observations":
            cluster_size,

        "source":
            "IsolationForest + DBSCAN",

        "first_detected":
            pd.Timestamp.utcnow().isoformat(),

        "behavioral_signature":
            signature
    }


    patterns.append(pattern)


# ============================================================
# SAVE PATTERN STORE
# ============================================================

with open(
    PATTERN_STORE_FILE,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        patterns,
        f,
        indent=2
    )


# ============================================================
# RESULT
# ============================================================

print()
print("=" * 65)
print(
    f"NEW PATTERNS DISCOVERED: "
    f"{len(patterns)}"
)
print("=" * 65)


for pattern in patterns:

    print()
    print(
        f"Pattern: "
        f"{pattern['pattern_id']}"
    )

    print(
        f"Classification: "
        f"{pattern['classification']}"
    )

    print(
        f"Status: "
        f"{pattern['status']}"
    )

    print(
        f"Observations: "
        f"{pattern['observations']}"
    )


print()
print(
    f"Saved: {PATTERN_STORE_FILE}"
)