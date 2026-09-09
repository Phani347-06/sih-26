import pandas as pd
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

df = pd.read_csv(
    PROJECT_ROOT / "data" / "processed" / "processed_dataset.csv"
)

print("BOT samples:")
print(df[df["Label"] == "Bot"].describe())

print("\nBENIGN samples:")
print(df[df["Label"] == "BENIGN"].sample(1948, random_state=42).describe())