from scapy.all import sniff
from capture.packet_processor import extract_packet_features, display_features


def process_packet(packet):
    features = extract_packet_features(packet)

    if features["source_ip"] is not None:
        display_features(features)


def start_capture():
    print("SENTRY Packet Capture Started")
    print("Capturing packets... Press CTRL+C to stop.")

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_capture()