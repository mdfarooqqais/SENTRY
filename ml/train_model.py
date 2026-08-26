import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

INPUT_FILE = "data/processed_cicids2017.csv"
MODEL_DIR = "ml/models"
MODEL_FILE = os.path.join(MODEL_DIR, "random_forest.pkl")

MAX_PER_CLASS = 20000
RANDOM_STATE = 42

print("Loading processed dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Original rows: {len(df)}")

df["Label"] = df["Label"].astype(str).str.strip()

print("\nOriginal class distribution:")
print(df["Label"].value_counts())

print("\nBalancing dataset...")

balanced_parts = []

for label, group in df.groupby("Label"):
    if len(group) > MAX_PER_CLASS:
        group = group.sample(
            MAX_PER_CLASS,
            random_state=RANDOM_STATE
        )

    balanced_parts.append(group)

df = pd.concat(
    balanced_parts,
    ignore_index=True
)

print(f"\nRows after balancing: {len(df)}")

print("\nBalanced class distribution:")
print(df["Label"].value_counts())

X = df.drop(columns=["Label"])
y = df["Label"]

X = X.apply(
    pd.to_numeric,
    errors="coerce"
)

X = X.fillna(0)

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=RANDOM_STATE,
    stratify=y
)

print(f"Training rows: {len(X_train)}")
print(f"Testing rows: {len(X_test)}")

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    n_jobs=-1,
    random_state=RANDOM_STATE,
    class_weight="balanced"
)

model.fit(X_train, y_train)

print("\nModel training completed.")

print("\nTesting model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)

os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(
    {
        "model": model,
        "features": X.columns.tolist()
    },
    MODEL_FILE
)

print(f"\nModel saved to: {MODEL_FILE}")