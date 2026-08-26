from scapy.all import IP, TCP, UDP, ICMP


def extract_packet_features(packet):
    features = {
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": "OTHER",
        "packet_size": len(packet),
        "ttl": None,
        "flags": None
    }

    if IP not in packet:
        return features

    features["source_ip"] = packet[IP].src
    features["destination_ip"] = packet[IP].dst
    features["ttl"] = packet[IP].ttl

    if TCP in packet:
        features["protocol"] = "TCP"
        features["source_port"] = packet[TCP].sport
        features["destination_port"] = packet[TCP].dport
        features["flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        features["protocol"] = "UDP"
        features["source_port"] = packet[UDP].sport
        features["destination_port"] = packet[UDP].dport

    elif ICMP in packet:
        features["protocol"] = "ICMP"

    return features


def display_features(features):
    print("\n--- Packet Features ---")
    print(f"Source IP      : {features['source_ip']}")
    print(f"Destination IP : {features['destination_ip']}")
    print(f"Source Port    : {features['source_port']}")
    print(f"Destination Port: {features['destination_port']}")
    print(f"Protocol       : {features['protocol']}")
    print(f"Packet Size    : {features['packet_size']}")
    print(f"TTL            : {features['ttl']}")
    print(f"TCP Flags      : {features['flags']}")