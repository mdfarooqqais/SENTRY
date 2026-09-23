from collections import defaultdict
from time import time


SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    445: "SMB",
    3389: "RDP",
    4444: "Common Remote Access Port",
    5900: "VNC"
}

connection_history = defaultdict(list)


def check_suspicious_port(features):
    destination_port = features.get("destination_port")

    if destination_port in SUSPICIOUS_PORTS:
        service = SUSPICIOUS_PORTS[destination_port]

        return {
            "detected": True,
            "attack_type": "Suspicious Port",
            "severity": "MEDIUM",
            "reason": f"Connection to {service} port {destination_port}"
        }

    return None


def check_large_packet(features):
    packet_size = features.get("packet_size", 0)

    # Only flag truly abnormal packets (jumbo frames > 9000 bytes)
    # Normal traffic can easily reach 1500 bytes (standard Ethernet MTU)
    if packet_size > 9000:
        return {
            "detected": True,
            "attack_type": "Oversized Packet (Possible DoS)",
            "severity": "MEDIUM",
            "reason": f"Jumbo packet detected: {packet_size} bytes (> 9000 byte threshold)"
        }

    return None


def check_tcp_flags(features):
    flags = features.get("flags")

    if not flags:
        return None

    if "S" in flags and "F" in flags:
        return {
            "detected": True,
            "attack_type": "Suspicious TCP Flags",
            "severity": "MEDIUM",
            "reason": "TCP SYN and FIN flags detected together"
        }

    return None


def check_port_scan(features):
    source_ip = features.get("source_ip")
    destination_ip = features.get("destination_ip")
    destination_port = features.get("destination_port")

    if not source_ip or not destination_ip or not destination_port:
        return None

    key = (source_ip, destination_ip)
    current_time = time()

    connection_history[key] = [
        port_time
        for port_time in connection_history[key]
        if current_time - port_time[1] < 10
    ]

    connection_history[key].append((destination_port, current_time))

    unique_ports = {
        port
        for port, port_time in connection_history[key]
    }

    if len(unique_ports) >= 10:
        return {
            "detected": True,
            "attack_type": "Possible Port Scan",
            "severity": "HIGH",
            "reason": f"{len(unique_ports)} destination ports contacted within 10 seconds"
        }

    return None


def check_tiny_packet(features):
    packet_size = features.get("packet_size", 0)

    # Ethernet frames less than 64 bytes are often anomalous (e.g. malformed or pure header scans)
    if packet_size < 64 and packet_size > 0:
        return {
            "detected": True,
            "attack_type": "Tiny Packet (Possible Scan/Flood)",
            "severity": "LOW",
            "reason": f"Abnormally small packet detected: {packet_size} bytes"
        }
    return None


def analyze_packet(features):
    rules = [
        check_suspicious_port,
        check_large_packet,
        check_tcp_flags,
        check_port_scan
    ]

    detections = []

    for rule in rules:
        result = rule(features)

        if result:
            detections.append(result)

    return detections


def is_threat(features):
    detections = analyze_packet(features)

    return {
        "detected": len(detections) > 0,
        "detections": detections
    }