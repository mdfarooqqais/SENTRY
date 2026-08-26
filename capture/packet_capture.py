import threading
import time

from scapy.all import sniff

from capture.packet_processor import extract_packet_features
from capture.flow_tracker import FlowTracker
from capture.flow_features import extract_flow_features

from detection.rule_engine import analyze_packet
from detection.signature_engine import match_signatures

from ml.predict import predict_attack
from database.database import save_alert, init_database


flow_tracker = FlowTracker(timeout=10)


def process_expired_flows():
    while True:
        time.sleep(2)

        expired_flows = flow_tracker.get_expired_flows()

        for key in expired_flows:
            flow = flow_tracker.get_flow(key)

            if flow is None:
                continue

            try:
                flow_features = extract_flow_features(flow)

                if flow_features:
                    prediction = predict_attack(flow_features)

                    print("\n========== ML FLOW DETECTION ==========")
                    print(f"Source: {key[0]}:{key[1]}")
                    print(f"Destination: {key[2]}:{key[3]}")
                    print(f"Protocol: {key[4]}")
                    print(f"Attack: {prediction['attack']}")
                    print(f"Confidence: {prediction['confidence']}%")

                    if prediction["attack"] != "BENIGN":
                        print("!!! ML SECURITY ALERT !!!")

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

                        print("ML alert saved to database.")

                    else:
                        print("Status: Normal")

                    print("=======================================\n")

            except Exception as e:
                print(f"ML flow prediction error: {e}")

            flow_tracker.remove_flow(key)


def process_packet(packet):

    features = extract_packet_features(packet)

    if features["source_ip"] is None:
        return

    flow_tracker.add_packet(packet)

    print("\n--- Packet ---")
    print(f"{features['source_ip']} -> {features['destination_ip']}")
    print(f"Protocol: {features['protocol']}")
    print(f"Source Port: {features['source_port']}")
    print(f"Destination Port: {features['destination_port']}")
    print(f"Packet Size: {features['packet_size']}")

    rule_detections = analyze_packet(features)
    signature_detections = match_signatures(features)

    if rule_detections or signature_detections:

        print("\n!!! SECURITY ALERT !!!")

        for detection in rule_detections:

            print(f"[RULE] {detection['attack_type']}")
            print(f"Severity: {detection['severity']}")
            print(f"Reason: {detection['reason']}")

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

            print("Rule alert saved to database.")

        for detection in signature_detections:

            print(f"[SIGNATURE] {detection['signature']}")
            print(f"Attack Type: {detection['attack_type']}")
            print(f"Severity: {detection['severity']}")
            print(f"Reason: {detection['reason']}")

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

            print("Signature alert saved to database.")

    else:
        print("Status: Normal")


def start_capture():

    init_database()

    print("SENTRY Packet Capture Started")
    print("Rule-Based Detection: ENABLED")
    print("Signature-Based Detection: ENABLED")
    print("Flow Tracking: ENABLED")
    print("ML Detection: ENABLED")
    print("Database Logging: ENABLED")
    print("Capturing packets... Press CTRL+C to stop.")

    thread = threading.Thread(
        target=process_expired_flows,
        daemon=True
    )

    thread.start()

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_capture()