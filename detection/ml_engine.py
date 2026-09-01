"""
SENTRY Machine Learning Anomaly Detection Layer (Layer 3)
"""
from ml.predict import predict_attack

def analyze_ml_anomaly(flow_features):
    """
    Evaluates extracted 45-tuple flow metrics against the trained Random Forest model.
    """
    if not flow_features:
        return None

    result = predict_attack(flow_features)
    if result and result.get("attack") != "BENIGN":
        return {
            "detected": True,
            "attack_type": result["attack"],
            "severity": "HIGH",
            "confidence": result["confidence"],
            "reason": f"Machine learning anomaly detected with {result['confidence']}% confidence"
        }
    return None
