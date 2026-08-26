import joblib
import pandas as pd
import os

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "random_forest.pkl"
)

model_data = joblib.load(MODEL_PATH)

model = model_data["model"]
features = model_data["features"]


def predict_attack(feature_data):
    df = pd.DataFrame([feature_data])

    for feature in features:
        if feature not in df.columns:
            df[feature] = 0

    df = df[features]

    prediction = model.predict(df)[0]

    probabilities = model.predict_proba(df)[0]
    confidence = max(probabilities) * 100

    return {
        "attack": prediction,
        "confidence": round(confidence, 2)
    }