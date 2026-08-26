import time
from collections import defaultdict


class FlowTracker:

    def __init__(self, timeout=10):
        self.flows = {}
        self.timeout = timeout

    def get_flow_key(self, packet):
        if not packet.haslayer("IP"):
            return None

        ip = packet["IP"]

        protocol = ip.proto

        src_port = 0
        dst_port = 0

        if packet.haslayer("TCP"):
            src_port = packet["TCP"].sport
            dst_port = packet["TCP"].dport

        elif packet.haslayer("UDP"):
            src_port = packet["UDP"].sport
            dst_port = packet["UDP"].dport

        forward = (
            ip.src,
            src_port,
            ip.dst,
            dst_port,
            protocol
        )

        backward = (
            ip.dst,
            dst_port,
            ip.src,
            src_port,
            protocol
        )

        if forward in self.flows:
            return forward

        if backward in self.flows:
            return backward

        return forward

    def add_packet(self, packet):

        if not packet.haslayer("IP"):
            return None

        key = self.get_flow_key(packet)

        if key is None:
            return None

        now = time.time()

        if key not in self.flows:

            self.flows[key] = {
                "start_time": now,
                "last_time": now,
                "packets": [],
                "forward_packets": [],
                "backward_packets": []
            }

        flow = self.flows[key]

        flow["last_time"] = now
        flow["packets"].append(packet)

        ip = packet["IP"]

        if ip.src == key[0]:
            flow["forward_packets"].append(packet)
        else:
            flow["backward_packets"].append(packet)

        return key

    def get_flow(self, key):

        return self.flows.get(key)

    def remove_flow(self, key):

        if key in self.flows:
            del self.flows[key]

    def get_expired_flows(self):

        now = time.time()

        expired = []

        for key, flow in self.flows.items():

            if now - flow["last_time"] > self.timeout:
                expired.append(key)

        return expired