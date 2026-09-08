import os
import glob
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

warnings.filterwarnings("ignore")


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "raw"

TRAIN_RATIO = 0.70

RANDOM_STATE = 42


# ============================================================
# SAME 22 FEATURES USED BY OUR MAIN MODEL
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
    "Down/Up Ratio",
]


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_label(label):

    label = str(label).strip()

    if label == "BENIGN":
        return "BENIGN"

    # DoS variants
    if label in [
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
    ]:
        return "DOS"

    # DDoS
    if label == "DDoS":
        return "DDOS"

    # Port scanning
    if label == "PortScan":
        return "PORT_SCAN"

    # Brute force
    if label in [
        "FTP-Patator",
        "SSH-Patator",
    ]:
        return "BRUTE_FORCE"

    # Bot
    if label == "Bot":
        return "BOT"

    # Everything else
    return "OTHER"


# ============================================================
# FILE SELECTION
# ============================================================

# We deliberately exclude:
#
# - Thursday Infiltration
# - Thursday WebAttacks
#
# because these contain attack families that are not part of
# our current known-threat model.
#
# We also exclude Heartbleed because it has only 11 samples.

SELECTED_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
]


# ============================================================
# LOAD AND PREPARE ONE FILE
# ============================================================

def load_file(filepath):

    filename = os.path.basename(filepath)

    print()
    print("-" * 75)
    print("Loading:", filename)

    try:
        df = pd.read_csv(
            filepath,
            low_memory=False
        )
    except Exception as e:
        print("ERROR loading file:", e)
        return None

    # Remove whitespace from column names
    df.columns = df.columns.str.strip()

    # Check label
    if "Label" not in df.columns:
        print("WARNING: Label column not found.")
        return None

    # Check required features
    missing_features = [
        feature for feature in FEATURES
        if feature not in df.columns
    ]

    if missing_features:
        print("WARNING: Missing features:")
        for feature in missing_features:
            print("  ", feature)
        return None

    # Keep only required columns
    df = df[FEATURES + ["Label"]].copy()

    # Normalize labels
    df["Label"] = df["Label"].apply(normalize_label)

    # Remove OTHER classes
    df = df[df["Label"] != "OTHER"]

    # Convert features to numeric
    for feature in FEATURES:
        df[feature] = pd.to_numeric(
            df[feature],
            errors="coerce"
        )

    # Replace infinity
    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    # Remove missing values
    before = len(df)

    df.dropna(
        subset=FEATURES,
        inplace=True
    )

    removed = before - len(df)

    print("Rows:", len(df))

    if removed > 0:
        print("Removed invalid rows:", removed)

    print("Labels:")
    print(df["Label"].value_counts().to_string())

    return df


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 75)
    print("TEMPORAL / UNSEEN CAPTURE EVALUATION")
    print("=" * 75)

    print()
    print("Purpose:")
    print("Evaluate a fresh Random Forest on temporally unseen")
    print("network-flow observations.")
    print()
    print("Training portion :", int(TRAIN_RATIO * 100), "%")
    print("Testing portion  :", int((1 - TRAIN_RATIO) * 100), "%")
    print()
    print("The existing saved model will NOT be modified.")

    # --------------------------------------------------------
    # Locate files
    # --------------------------------------------------------

    all_files = []

    for filename in SELECTED_FILES:

        filepath = os.path.join(
            DATA_DIR,
            filename
        )

        if not os.path.exists(filepath):

            print()
            print("WARNING: File not found:")
            print(filepath)

            continue

        all_files.append(filepath)

    if not all_files:

        print()
        print("ERROR: No dataset files found.")
        return

    # --------------------------------------------------------
    # Load files
    # --------------------------------------------------------

    datasets = []

    for filepath in all_files:

        df = load_file(filepath)

        if df is not None and len(df) > 0:

            datasets.append(
                (
                    os.path.basename(filepath),
                    df
                )
            )

    if not datasets:

        print()
        print("ERROR: No valid datasets loaded.")
        return

    # --------------------------------------------------------
    # Temporal split
    # --------------------------------------------------------

    train_parts = []
    test_parts = []

    print()
    print("=" * 75)
    print("TEMPORAL SPLITTING")
    print("=" * 75)

    for filename, df in datasets:

        split_index = int(
            len(df) * TRAIN_RATIO
        )

        train_df = df.iloc[:split_index].copy()
        test_df = df.iloc[split_index:].copy()

        train_parts.append(train_df)
        test_parts.append(test_df)

        print()
        print(filename)
        print("  Total :", len(df))
        print("  Train :", len(train_df))
        print("  Test  :", len(test_df))

    train = pd.concat(
        train_parts,
        ignore_index=True
    )

    test = pd.concat(
        test_parts,
        ignore_index=True
    )

    print()
    print("=" * 75)
    print("TRAINING DATA")
    print("=" * 75)

    print("Training samples:", len(train))

    print()
    print(
        train["Label"]
        .value_counts()
        .to_string()
    )

    print()
    print("=" * 75)
    print("UNSEEN TEST DATA")
    print("=" * 75)

    print("Testing samples:", len(test))

    print()
    print(
        test["Label"]
        .value_counts()
        .to_string()
    )

    # --------------------------------------------------------
    # Remove classes that are not available in training
    # --------------------------------------------------------

    train_classes = set(
        train["Label"].unique()
    )

    test_classes = set(
        test["Label"].unique()
    )

    unseen_test_classes = (
        test_classes - train_classes
    )

    if unseen_test_classes:

        print()
        print("=" * 75)
        print("IMPORTANT")
        print("=" * 75)

        print(
            "The following test classes do not exist in training:"
        )

        for cls in sorted(unseen_test_classes):
            print("  ", cls)

        print()
        print(
            "Random Forest cannot predict a class that it was"
        )
        print(
            "never trained on. These classes will therefore"
        )
        print(
            "be reported separately rather than treated as"
        )
        print(
            "normal classification performance."
        )

    # --------------------------------------------------------
    # Create training matrices
    # --------------------------------------------------------

    X_train = train[FEATURES]
    y_train = train["Label"]

    X_test = test[FEATURES]
    y_test = test["Label"]

    # --------------------------------------------------------
    # Train fresh Random Forest
    # --------------------------------------------------------

    print()
    print("=" * 75)
    print("TRAINING FRESH RANDOM FOREST")
    print("=" * 75)

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight="balanced"
    )

    model.fit(
        X_train,
        y_train
    )

    print("Training complete.")

    # --------------------------------------------------------
    # Predict
    # --------------------------------------------------------

    print()
    print("=" * 75)
    print("RUNNING PREDICTIONS")
    print("=" * 75)

    predictions = model.predict(
        X_test
    )

    # --------------------------------------------------------
    # Overall evaluation
    # --------------------------------------------------------

    known_mask = y_test.isin(
        train_classes
    )

    known_actual = y_test[known_mask]

    known_predictions = predictions[known_mask]

    print()
    print("=" * 75)
    print("OVERALL RESULTS")
    print("=" * 75)

    if len(known_actual) > 0:

        accuracy = accuracy_score(
            known_actual,
            known_predictions
        )

        precision, recall, f1, _ = (
            precision_recall_fscore_support(
                known_actual,
                known_predictions,
                average="weighted",
                zero_division=0
            )
        )

        print()
        print(
            f"Accuracy          : {accuracy:.4f}"
        )

        print(
            f"Weighted Precision : {precision:.4f}"
        )

        print(
            f"Weighted Recall    : {recall:.4f}"
        )

        print(
            f"Weighted F1        : {f1:.4f}"
        )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    print()
    print("=" * 75)
    print("CLASSIFICATION REPORT")
    print("=" * 75)

    if len(known_actual) > 0:

        print(
            classification_report(
                known_actual,
                known_predictions,
                zero_division=0
            )
        )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    print()
    print("=" * 75)
    print("CONFUSION MATRIX")
    print("=" * 75)

    if len(known_actual) > 0:

        labels = sorted(
            train_classes
        )

        cm = confusion_matrix(
            known_actual,
            known_predictions,
            labels=labels
        )

        print()

        header = "Actual \\ Pred".ljust(18)

        for label in labels:
            header += label[:12].ljust(14)

        print(header)

        for i, label in enumerate(labels):

            row = label.ljust(18)

            for value in cm[i]:

                row += str(value).ljust(14)

            print(row)

    # --------------------------------------------------------
    # Unseen attack-family analysis
    # --------------------------------------------------------

    if unseen_test_classes:

        print()
        print("=" * 75)
        print("UNSEEN ATTACK-FAMILY ANALYSIS")
        print("=" * 75)

        for cls in sorted(
            unseen_test_classes
        ):

            mask = (
                y_test.values == cls
            )

            cls_predictions = predictions[mask]

            print()
            print(
                "Actual class:",
                cls
            )

            print(
                "Samples:",
                len(cls_predictions)
            )

            print(
                "Random Forest predictions:"
            )

            unique, counts = np.unique(
                cls_predictions,
                return_counts=True
            )

            for prediction, count in zip(
                unique,
                counts
            ):

                percentage = (
                    count /
                    len(cls_predictions)
                    * 100
                )

                print(
                    f"  {prediction:15s}"
                    f"{count:8d}"
                    f" ({percentage:6.2f}%)"
                )

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------

    print()
    print("=" * 75)
    print("EVALUATION COMPLETE")
    print("=" * 75)

    print()
    print("Important interpretation:")

    print(
        "This is a temporal hold-out evaluation."
    )

    print(
        "The model was trained using earlier observations"
    )

    print(
        "and tested on later observations."
    )

    print(
        "It is stronger than a random row split, but it is"
    )

    print(
        "not yet a cross-dataset real-world evaluation."
    )

    print()
    print(
        "Existing model file was NOT changed."
    )


if __name__ == "__main__":
    main()