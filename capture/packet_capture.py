from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)

        protocol = "OTHER"
        source_port = None
        destination_port = None

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        print(
            f"[{timestamp}] "
            f"{source_ip}:{source_port} -> "
            f"{destination_ip}:{destination_port} | "
            f"{protocol} | "
            f"Size: {packet_size}"
        )


def start_capture():
    print("SENTRY Packet Capture Started")
    print("Capturing packets... Press CTRL+C to stop.")

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_capture()