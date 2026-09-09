import json
import os
import uuid
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN


# ============================================================
# CONFIG
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = PROJECT_ROOT / "models" / "random_forest_model.pkl"
ANOMALY_MODEL_FILE = PROJECT_ROOT / "models" / "isolation_forest.pkl"

PATTERN_FILE = PROJECT_ROOT / "output" / "pattern_store.json"

DATA_FILE = PROJECT_ROOT / "flows_bidirectional.csv"

NUM_ROWS = 100

# RF confidence below this is considered uncertain
RF_CONFIDENCE_THRESHOLD = 0.70

# DBSCAN parameters
DBSCAN_EPS = 2.5
DBSCAN_MIN_SAMPLES = 2


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
# LOAD PATTERN STORE
# ============================================================

def load_pattern_store():

    if not os.path.exists(PATTERN_FILE):
        return []

    try:

        with open(
            PATTERN_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except Exception:

        return []


# ============================================================
# SAVE PATTERN STORE
# ============================================================

def save_pattern_store(patterns):

    with open(
        PATTERN_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            patterns,
            f,
            indent=2
        )


# ============================================================
# LOAD MODELS
# ============================================================

print("=" * 65)
print(" UNKNOWN BEHAVIOR DISCOVERY")
print("=" * 65)

rf_model = joblib.load(
    MODEL_FILE
)

anomaly_model = joblib.load(
    ANOMALY_MODEL_FILE
)

print("Random Forest loaded.")
print("Isolation Forest loaded.")


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv(
    DATA_FILE
)

df.columns = df.columns.str.strip()

df = df.head(
    NUM_ROWS
).copy()


X = df[FEATURES].copy()

X = X.replace(
    [np.inf, -np.inf],
    0
)

X = X.fillna(0)


# ============================================================
# RANDOM FOREST
# ============================================================

rf_predictions = rf_model.predict(X)

rf_probabilities = rf_model.predict_proba(X)

rf_confidences = (
    rf_probabilities.max(axis=1)
)


# ============================================================
# ISOLATION FOREST
# ============================================================

# Isolation Forest:
#  1  = normal
# -1  = anomaly

anomaly_predictions = (
    anomaly_model.predict(X)
)


anomaly_scores = (
    anomaly_model.decision_function(X)
)


# ============================================================
# FIND UNKNOWN CANDIDATES
# ============================================================

unknown_indices = []


for i in range(len(X)):

    prediction = rf_predictions[i]

    confidence = rf_confidences[i]

    anomaly = anomaly_predictions[i]


    # --------------------------------------------------------
    # Known threat
    # --------------------------------------------------------

    if (
        prediction != "BENIGN"
        and confidence >= RF_CONFIDENCE_THRESHOLD
    ):

        continue


    # --------------------------------------------------------
    # Unknown candidate
    # --------------------------------------------------------

    if anomaly == -1:

        unknown_indices.append(i)


print()
print(
    "Rows analysed:",
    len(X)
)

print(
    "Unknown candidates:",
    len(unknown_indices)
)


# ============================================================
# NO UNKNOWN BEHAVIOR
# ============================================================

if len(unknown_indices) == 0:

    print()
    print(
        "No previously unseen anomalous behavior "
        "detected in this replay."
    )

    print()
    print(
        "This is valid: the system did not force "
        "an unknown classification."
    )

    raise SystemExit


# ============================================================
# EXTRACT UNKNOWN FEATURES
# ============================================================

unknown_X = X.iloc[
    unknown_indices
].copy()


# ============================================================
# SCALE FOR DBSCAN
# ============================================================

scaler = StandardScaler()

unknown_scaled = scaler.fit_transform(
    unknown_X
)
print("Unknown scaled data:")
print(unknown_scaled)


# ============================================================
# DBSCAN
# ============================================================

dbscan = DBSCAN(

    eps=DBSCAN_EPS,

    min_samples=DBSCAN_MIN_SAMPLES

)


cluster_labels = dbscan.fit_predict(
    unknown_scaled
)
print("DBSCAN labels:", cluster_labels)


# ============================================================
# PATTERN STORE
# ============================================================

patterns = load_pattern_store()


existing_pattern_ids = {
    p["pattern_id"]
    for p in patterns
}


# ============================================================
# DISCOVER CLUSTERS
# ============================================================

unique_clusters = sorted(
    set(cluster_labels)
)


new_patterns = 0


for cluster_id in unique_clusters:

    # DBSCAN -1 = noise
    if cluster_id == -1:
        continue


    cluster_indices = [

        unknown_indices[i]

        for i, label
        in enumerate(cluster_labels)

        if label == cluster_id

    ]


    if len(cluster_indices) < DBSCAN_MIN_SAMPLES:
        continue


    # --------------------------------------------------------
    # Check whether this pattern already exists
    # --------------------------------------------------------

    pattern_id = None


    for pattern in patterns:

        if (
            pattern.get("cluster_size")
            == len(cluster_indices)
        ):

            pattern_id = pattern[
                "pattern_id"
            ]

            break


    # --------------------------------------------------------
    # Create new pattern
    # --------------------------------------------------------

    if pattern_id is None:

        pattern_id = (
            "P-"
            + uuid.uuid4().hex[:6].upper()
        )


        representative_index = (
            cluster_indices[0]
        )


        representative = X.iloc[
            representative_index
        ]


        pattern = {

            "pattern_id":
                pattern_id,

            "cluster_size":
                len(cluster_indices),

            "status":
                "NEW",

            "first_detected":
                pd.Timestamp.now(
                    tz="UTC"
                ).isoformat(),

            "source":
                "IsolationForest + DBSCAN",

            "behavioral_signature": {

                "flow_duration":
                    float(
                        representative[
                            "Flow Duration"
                        ]
                    ),

                "packet_rate":
                    float(
                        representative[
                            "Flow Packets/s"
                        ]
                    ),

                "byte_rate":
                    float(
                        representative[
                            "Flow Bytes/s"
                        ]
                    ),

                "packet_size_mean":
                    float(
                        representative[
                            "Packet Length Mean"
                        ]
                    ),

                "packet_size_std":
                    float(
                        representative[
                            "Packet Length Std"
                        ]
                    ),

                "syn_count":
                    float(
                        representative[
                            "SYN Flag Count"
                        ]
                    ),

                "ack_count":
                    float(
                        representative[
                            "ACK Flag Count"
                        ]
                    )
            }

        }


        patterns.append(
            pattern
        )

        new_patterns += 1


# ============================================================
# SAVE
# ============================================================

save_pattern_store(
    patterns
)


# ============================================================
# DISPLAY
# ============================================================

print()
print("=" * 65)

print(
    "DISCOVERED PATTERNS:",
    new_patterns
)

print("=" * 65)


for pattern in patterns:

    print()

    print(
        "Pattern:",
        pattern["pattern_id"]
    )

    print(
        "Status:",
        pattern["status"]
    )

    print(
        "Cluster size:",
        pattern["cluster_size"]
    )

    print(
        "Source:",
        pattern["source"]
    )


print()
print(
    "Saved:",
    PATTERN_FILE
)