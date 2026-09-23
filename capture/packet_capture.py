import threading
import time
import random

from scapy.all import sniff

from capture.packet_processor import extract_packet_features
from capture.flow_tracker import FlowTracker
from capture.flow_features import extract_flow_features

from detection.rule_engine import analyze_packet
from detection.signature_engine import match_signatures

from ml.predict import predict_attack
from database.database import save_alert, init_database, log_traffic, log_raw_packets_batch
from capture.firewall import block_ip

flow_tracker = FlowTracker(timeout=10)

traffic_lock = threading.Lock()
normal_packet_count = 0
suspicious_packet_count = 0
total_bytes_count = 0

alert_cache = {}
ALERT_COOLDOWN = 10  # Seconds to wait before logging the same alert for the same IP

raw_packet_buffer = []

def log_raw_packets_thread():
    global raw_packet_buffer
    while True:
        time.sleep(1)
        with traffic_lock:
            if not raw_packet_buffer:
                continue
            to_log = raw_packet_buffer[:]
            raw_packet_buffer = []
        log_raw_packets_batch(to_log)

def log_traffic_stats_thread():
    global normal_packet_count, suspicious_packet_count, total_bytes_count
    while True:
        time.sleep(3)
        with traffic_lock:
            normal = normal_packet_count
            suspicious = suspicious_packet_count
            bytes_val = total_bytes_count
            normal_packet_count = 0
            suspicious_packet_count = 0
            total_bytes_count = 0
        mbps = (bytes_val * 8) / (1_000_000 * 3)
        log_traffic(normal, suspicious, mbps)

def evaluate_ml_flow(key, flow):
    try:
        flow_features = extract_flow_features(flow)
        if flow_features:
            prediction = predict_attack(flow_features)
            
            if prediction["attack"] != "BENIGN":
                alert_key = f"{key[0]}_ML_{prediction['attack']}"
                now = time.time()
                
                if alert_key not in alert_cache or (now - alert_cache[alert_key] > ALERT_COOLDOWN):
                    alert_cache[alert_key] = now
                    
                    print(f"\n!!! ML SECURITY ALERT: {prediction['attack']} from {key[0]} ({prediction['confidence']}%) !!!")
                    save_alert(
                        source_ip=key[0],
                        destination_ip=key[2],
                        source_port=key[1],
                        destination_port=key[3],
                        protocol=str(key[4]),
                        detection_type="ML",
                        attack_type=prediction["attack"],
                        severity="HIGH",
                        confidence=prediction["confidence"]
                    )
                    
                    if prediction["confidence"] > 75:
                        block_ip(key[0], reason=f"ML Anomaly ({prediction['attack']})")
    except Exception as e:
        print(f"ML flow prediction error: {e}")

def process_expired_flows():
    while True:
        time.sleep(2)
        expired_flows = flow_tracker.get_expired_flows()
        for key in expired_flows:
            flow = flow_tracker.get_flow(key)
            if flow:
                evaluate_ml_flow(key, flow)
            flow_tracker.remove_flow(key)

def process_packet(packet):
    global normal_packet_count, suspicious_packet_count, total_bytes_count

    features = extract_packet_features(packet)
    if features["source_ip"] is None:
        return

    key = flow_tracker.add_packet(packet)
    if key:
        flow = flow_tracker.get_flow(key)
        if flow:
            packet_count = len(flow["packets"])
            if packet_count in [5, 25, 100, 500]:
                evaluate_ml_flow(key, flow)

    with traffic_lock:
        total_bytes_count += features["packet_size"]

    rule_detections = analyze_packet(features)
    signature_detections = match_signatures(features)

    if rule_detections or signature_detections:
        with traffic_lock:
            suspicious_packet_count += 1

        for detection in rule_detections:
            alert_key = f"{features['source_ip']}_RULE_{detection['attack_type']}"
            now = time.time()
            if alert_key not in alert_cache or (now - alert_cache[alert_key] > ALERT_COOLDOWN):
                alert_cache[alert_key] = now
                print(f"\n!!! RULE SECURITY ALERT: {detection['attack_type']} from {features['source_ip']} !!!")
                save_alert(
                    source_ip=features["source_ip"],
                    destination_ip=features["destination_ip"],
                    source_port=features["source_port"],
                    destination_port=features["destination_port"],
                    protocol=features["protocol"],
                    detection_type="RULE",
                    attack_type=detection["attack_type"],
                    severity=detection["severity"],
                    confidence=1.0
                )
                block_ip(features["source_ip"], reason=f"Rule: {detection['attack_type']}")

        for detection in signature_detections:
            alert_key = f"{features['source_ip']}_SIG_{detection['attack_type']}"
            now = time.time()
            if alert_key not in alert_cache or (now - alert_cache[alert_key] > ALERT_COOLDOWN):
                alert_cache[alert_key] = now
                print(f"\n!!! SIGNATURE SECURITY ALERT: {detection['attack_type']} from {features['source_ip']} !!!")
                save_alert(
                    source_ip=features["source_ip"],
                    destination_ip=features["destination_ip"],
                    source_port=features["source_port"],
                    destination_port=features["destination_port"],
                    protocol=features["protocol"],
                    detection_type="SIGNATURE",
                    attack_type=detection["attack_type"],
                    severity=detection["severity"],
                    confidence=1.0
                )
                block_ip(features["source_ip"], reason=f"Signature: {detection['attack_type']}")
    else:
        with traffic_lock:
            normal_packet_count += 1

# Calculate suspicion score
    if rule_detections or signature_detections:
        max_sev = "HIGH" if any(d["severity"] == "HIGH" for d in rule_detections + signature_detections) else "MEDIUM"
        base_score = random.randint(75, 95) if max_sev == "HIGH" else random.randint(50, 70)
    else:
        base_score = random.randint(15, 25)

    # Apply Packet Size Heuristics
    pkt_size = features.get("packet_size", 0)
    if pkt_size > 0 and pkt_size < 64:
        score = base_score + 15
    elif 64 <= pkt_size <= 1500:
        score = base_score - 10
    elif pkt_size > 9000:
        score = base_score + 30
    elif pkt_size > 1500:
        score = base_score + 10
    else:
        score = base_score
    
    # Clamp score between 0 and 100
    score = max(0, min(100, score))

    if score <= 30:
        classification = "White/Benign"
        tag = "BENIGN"
    elif score <= 70:
        classification = "Suspicious/Anomaly"
        tag = "SUSPICIOUS"
    else:
        classification = "Malicious/Attack"
        tag = "MALICIOUS"

    flags_str = f" FLAGS={features['flags']}" if features.get("flags") else ""
    ttl_str   = f" TTL={features['ttl']}" if features.get("ttl") else ""
    src = f"{features['source_ip']}:{features['source_port']}" if features.get("source_port") else features["source_ip"]
    dst = f"{features['destination_ip']}:{features['destination_port']}" if features.get("destination_port") else features["destination_ip"]

    if rule_detections or signature_detections:
        reason = " | ".join(
            [d["attack_type"] for d in rule_detections] +
            [d["attack_type"] for d in signature_detections]
        )
        log_string = f"SCORE:{score}% [{tag}] {features['protocol']} {src} -> {dst} [LEN {features['packet_size']}b]{flags_str}{ttl_str} | {classification} | {reason}"
    else:
        log_string = f"SCORE:{score}% [{tag}] {features['protocol']} {src} -> {dst} [LEN {features['packet_size']}b]{flags_str}{ttl_str} | {classification}"

    with traffic_lock:
        raw_packet_buffer.append(log_string)
    if score > 30:
        with traffic_lock:
            raw_packet_buffer.append(log_string)

def start_capture():
    init_database()
    print("SENTRY Packet Capture Started")
    print("Rule-Based Detection: ENABLED")
    print("Signature-Based Detection: ENABLED")
    print("Flow Tracking: ENABLED")
    print("ML Detection: ENABLED")
    print("Active Mitigation (Firewall Blocking): ENABLED")
    print("Raw Packet Logging: ENABLED")
    print("Capturing packets... Press CTRL+C to stop.")

    thread = threading.Thread(target=process_expired_flows, daemon=True)
    thread.start()

    logger_thread = threading.Thread(target=log_traffic_stats_thread, daemon=True)
    logger_thread.start()
    
    raw_logger_thread = threading.Thread(target=log_raw_packets_thread, daemon=True)
    raw_logger_thread.start()

    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_capture()

