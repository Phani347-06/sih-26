import pandas as pd

df = pd.read_csv("data/processed/processed_dataset.csv")

print("BOT samples:")
print(df[df["Label"] == "Bot"].describe())

print("\nBENIGN samples:")
print(df[df["Label"] == "BENIGN"].sample(1948, random_state=42).describe())