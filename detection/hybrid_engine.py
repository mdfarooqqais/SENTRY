"""
SENTRY Hybrid Tri-Layer Detection Engine (Combining Layer 1, Layer 2 & Layer 3)
"""
from detection.rule_engine import analyze_packet
from detection.signature_engine import match_signatures
from detection.ml_engine import analyze_ml_anomaly

def evaluate_hybrid_threats(packet_features=None, flow_features=None):
    """
    Evaluates packet & flow metrics across Rule-Based, Signature-Based, and Machine Learning layers.
    Returns consolidated threat detections.
    """
    detections = []

    # 1. Rule-Based Evaluation
    if packet_features:
        rules = analyze_packet(packet_features)
        for r in rules:
            detections.append({
                "layer": "Rule-Based",
                "attack_type": r["attack_type"],
                "severity": r["severity"],
                "reason": r["reason"]
            })

    # 2. Signature-Based Evaluation
    if packet_features:
        sigs = match_signatures(packet_features)
        for s in sigs:
            detections.append({
                "layer": "Signature-Based",
                "attack_type": s["attack_type"],
                "severity": s["severity"],
                "reason": s["reason"]
            })

    # 3. Machine Learning Evaluation
    if flow_features:
        ml_res = analyze_ml_anomaly(flow_features)
        if ml_res:
            detections.append({
                "layer": "ML Anomaly",
                "attack_type": ml_res["attack_type"],
                "severity": ml_res["severity"],
                "reason": ml_res["reason"]
            })

    return detections
