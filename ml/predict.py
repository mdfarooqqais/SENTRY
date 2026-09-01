import joblib
import pandas as pd
import os

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "random_forest.pkl"
)

_loaded_model_data = None

def get_model_data():
    global _loaded_model_data
    if _loaded_model_data is not None:
        return _loaded_model_data

    if os.path.exists(MODEL_PATH):
        try:
            _loaded_model_data = joblib.load(MODEL_PATH)
            return _loaded_model_data
        except Exception as e:
            print(f"Error loading model from {MODEL_PATH}: {e}")
            return None
    return None


def predict_attack(feature_data):
    data = get_model_data()
    if data is None:
        return {
            "attack": "BENIGN",
            "confidence": 95.0,
            "trained": False
        }

    model = data["model"]
    features = data["features"]

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
        "confidence": round(confidence, 2),
        "trained": True
    }