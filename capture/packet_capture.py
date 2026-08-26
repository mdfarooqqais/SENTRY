from scapy.all import sniff

from capture.packet_processor import extract_packet_features
from detection.rule_engine import analyze_packet


def process_packet(packet):
    features = extract_packet_features(packet)

    if features["source_ip"] is None:
        return

    print("\n--- Packet ---")
    print(f"{features['source_ip']} -> {features['destination_ip']}")
    print(f"Protocol: {features['protocol']}")
    print(f"Source Port: {features['source_port']}")
    print(f"Destination Port: {features['destination_port']}")
    print(f"Packet Size: {features['packet_size']}")

    detections = analyze_packet(features)

    if detections:
        print("\n!!! SECURITY ALERT !!!")

        for detection in detections:
            print(f"Attack Type : {detection['attack_type']}")
            print(f"Severity    : {detection['severity']}")
            print(f"Reason      : {detection['reason']}")

    else:
        print("Status: Normal")


def start_capture():
    print("SENTRY Packet Capture Started")
    print("Rule-Based Detection Enabled")
    print("Capturing packets... Press CTRL+C to stop.")

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_capture()