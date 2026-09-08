import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from pathlib import Path

# --------------------------------------------------
# 1. Load processed dataset
# --------------------------------------------------

print("Loading dataset...")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

df = pd.read_csv(
    PROJECT_ROOT / "data" / "processed" / "processed_dataset.csv"
)

print("Original shape:", df.shape)


# --------------------------------------------------
# 2. Normalize labels
# --------------------------------------------------

def normalize_label(label):

    label = label.strip()

    if label == "BENIGN":
        return "BENIGN"

    if label in [
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest"
    ]:
        return "DOS"

    if label == "DDoS":
        return "DDOS"

    if label == "PortScan":
        return "PORT_SCAN"

    if label in [
        "FTP-Patator",
        "SSH-Patator"
    ]:
        return "BRUTE_FORCE"

    if label == "Bot":
        return "BOT"

    if label == "Heartbleed":
        return "HEARTBLEED"

    return "OTHER"


df["Label"] = df["Label"].apply(normalize_label)


# --------------------------------------------------
# 3. Remove OTHER
# --------------------------------------------------

df = df[df["Label"] != "OTHER"]


print("\nNormalized labels:")
print(df["Label"].value_counts())


# --------------------------------------------------
# 4. Separate features and labels
# --------------------------------------------------

X = df.drop(columns=["Label"])
y = df["Label"]


# --------------------------------------------------
# 5. Replace problematic values
# --------------------------------------------------

X = X.replace([np.inf, -np.inf], np.nan)

X = X.fillna(0)


# --------------------------------------------------
# 6. Train/test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# 7. Train Random Forest
# --------------------------------------------------

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)


# --------------------------------------------------
# 8. Evaluate
# --------------------------------------------------

print("\nMODEL RESULTS")
print("=" * 60)

y_pred = model.predict(X_test)

print(
    classification_report(
        y_test,
        y_pred,
        digits=4
    )
)


print("\nCONFUSION MATRIX")
print("=" * 60)

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)


# --------------------------------------------------
# 9. Save model
# --------------------------------------------------

joblib.dump(
    model,
    PROJECT_ROOT / "models" / "random_forest_model.pkl"
)

print("\nModel saved as:")
print("random_forest_model.pkl")