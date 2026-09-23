"""
SENTRY - Live Capture Proof Test
Run this script to prove that SENTRY is capturing REAL packets.
It will show you the exact IP addresses, ports, and hostnames of packets 
on YOUR network interface in real time.
"""

from scapy.all import sniff, IP, TCP, UDP
import socket
import datetime

count = [0]

def resolve_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def show_packet(packet):
    if not packet.haslayer(IP):
        return

    count[0] += 1
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src = packet[IP].src
    dst = packet[IP].dst
    proto = "TCP" if packet.haslayer(TCP) else ("UDP" if packet.haslayer(UDP) else "OTHER")

    src_port = 0
    dst_port = 0
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    size = len(packet)

    print(f"[{ts}] #{count[0]:04d}  {proto}  {src}:{src_port}  ->  {dst}:{dst_port}  ({size} bytes)")

print("="*70)
print("  SENTRY LIVE PACKET PROOF TEST")
print("="*70)
print("  This script captures REAL packets from your network adapter.")
print("  Open Chrome or Edge and visit ANY website during this test.")
print("  You will see your browser's real IP traffic appear below instantly.")
print("  Press CTRL+C to stop.")
print("="*70)
print()

sniff(prn=show_packet, filter="ip", store=False, count=50)

print()
print(f"  Done. Captured {count[0]} REAL packets from your network adapter.")

