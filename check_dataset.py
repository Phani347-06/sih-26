import pandas as pd
from pathlib import Path

# Change this to your dataset folder
DATASET_DIR = Path(r"C:\Users\manoj\Desktop\n8n\SIH-26\CICIDS 2017")

for file in DATASET_DIR.glob("*.csv"):

    print("\n" + "=" * 80)
    print("FILE:", file.name)

    try:
        df = pd.read_csv(file, encoding="latin1")

        print("Shape:", df.shape)

        # Find label column
        label_col = None
        for col in df.columns:
            if col.strip().lower() in ["label", "class"]:
                label_col = col
                break

        if label_col:
            print("\nLABEL COUNTS:")
            print(df[label_col].value_counts(dropna=False))

        print("\nMISSING VALUES:")
        missing = df.isnull().sum()
        print("Columns with missing values:", (missing > 0).sum())
        print("Total missing values:", missing.sum())

        print("\nDUPLICATES:", df.duplicated().sum())

        print("\nNUMBER OF FEATURES:", len(df.columns) - 1)

    except Exception as e:
        print("ERROR:", e)

print("\n" + "=" * 80)
print("Inspection complete.")
