import threading
import time

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
                    confidence=100
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
                    confidence=100
                )
                block_ip(features["source_ip"], reason=f"Signature: {detection['attack_type']}")
    else:
        with traffic_lock:
            normal_packet_count += 1

    status_flag = "THREAT" if (rule_detections or signature_detections) else "BENIGN"
    log_string = f"{features['protocol']} {features['source_ip']}:{features['source_port']} -> {features['destination_ip']}:{features['destination_port']} [LEN {features['packet_size']}b] SENTRY_EVAL={status_flag}"
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