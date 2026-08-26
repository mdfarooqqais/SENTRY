import math


def packet_length(packet):
    if packet.haslayer("IP"):
        return len(packet["IP"])
    return len(packet)


def get_tcp_flags(packet):
    flags = {
        "FIN": 0,
        "SYN": 0,
        "RST": 0,
        "PSH": 0,
        "ACK": 0,
        "URG": 0
    }

    if packet.haslayer("TCP"):
        tcp = packet["TCP"]

        flags["FIN"] = int(tcp.flags.F)
        flags["SYN"] = int(tcp.flags.S)
        flags["RST"] = int(tcp.flags.R)
        flags["PSH"] = int(tcp.flags.P)
        flags["ACK"] = int(tcp.flags.A)
        flags["URG"] = int(tcp.flags.U)

    return flags


def calculate_stats(lengths):
    if not lengths:
        return 0, 0, 0, 0

    minimum = min(lengths)
    maximum = max(lengths)
    mean = sum(lengths) / len(lengths)

    if len(lengths) > 1:
        variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
        std = math.sqrt(variance)
    else:
        std = 0

    return minimum, maximum, mean, std


def extract_flow_features(flow):

    packets = flow["packets"]
    forward = flow["forward_packets"]
    backward = flow["backward_packets"]

    if not packets:
        return None

    start = flow["start_time"]
    end = flow["last_time"]

    duration = max((end - start) * 1_000_000, 0.0)

    fwd_lengths = [packet_length(p) for p in forward]
    bwd_lengths = [packet_length(p) for p in backward]
    all_lengths = [packet_length(p) for p in packets]

    fwd_min, fwd_max, fwd_mean, fwd_std = calculate_stats(fwd_lengths)
    bwd_min, bwd_max, bwd_mean, bwd_std = calculate_stats(bwd_lengths)
    min_len, max_len, mean_len, std_len = calculate_stats(all_lengths)

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)

    duration_seconds = max(end - start, 0.000001)

    flow_bytes_per_sec = (
        (total_fwd_bytes + total_bwd_bytes)
        / duration_seconds
    )

    flow_packets_per_sec = (
        len(packets)
        / duration_seconds
    )

    fwd_packets_per_sec = (
        len(forward)
        / duration_seconds
    )

    bwd_packets_per_sec = (
        len(backward)
        / duration_seconds
    )

    iats = []

    for i in range(1, len(packets)):
        current = packets[i]
        previous = packets[i - 1]

        if hasattr(current, "time") and hasattr(previous, "time"):
            iats.append(float(current.time - previous.time))

    if iats:
        iat_mean = sum(iats) / len(iats)
        iat_std = math.sqrt(
            sum((x - iat_mean) ** 2 for x in iats) / len(iats)
        )
        iat_max = max(iats)
        iat_min = min(iats)
    else:
        iat_mean = 0
        iat_std = 0
        iat_max = 0
        iat_min = 0

    fwd_iats = []

    for i in range(1, len(forward)):
        if hasattr(forward[i], "time") and hasattr(forward[i - 1], "time"):
            fwd_iats.append(
                float(forward[i].time - forward[i - 1].time)
            )

    fwd_iat_total = sum(fwd_iats) * 1_000_000

    bwd_iats = []

    for i in range(1, len(backward)):
        if hasattr(backward[i], "time") and hasattr(backward[i - 1], "time"):
            bwd_iats.append(
                float(backward[i].time - backward[i - 1].time)
            )

    bwd_iat_total = sum(bwd_iats) * 1_000_000

    flags = {
        "FIN": 0,
        "SYN": 0,
        "RST": 0,
        "PSH": 0,
        "ACK": 0,
        "URG": 0
    }

    for packet in packets:
        packet_flags = get_tcp_flags(packet)

        for flag in flags:
            flags[flag] += packet_flags[flag]

    first_packet = packets[0]

    destination_port = 0
    protocol = 0

    if first_packet.haslayer("TCP"):
        destination_port = first_packet["TCP"].dport
        protocol = 6

    elif first_packet.haslayer("UDP"):
        destination_port = first_packet["UDP"].dport
        protocol = 17

    features = {
        "Destination Port": destination_port,
        "Protocol": protocol,
        "Flow Duration": duration,
        "Total Fwd Packets": len(forward),
        "Total Backward Packets": len(backward),
        "Total Length of Fwd Packets": total_fwd_bytes,
        "Total Length of Bwd Packets": total_bwd_bytes,
        "Fwd Packet Length Max": fwd_max,
        "Fwd Packet Length Min": fwd_min,
        "Fwd Packet Length Mean": fwd_mean,
        "Fwd Packet Length Std": fwd_std,
        "Bwd Packet Length Max": bwd_max,
        "Bwd Packet Length Min": bwd_min,
        "Bwd Packet Length Mean": bwd_mean,
        "Bwd Packet Length Std": bwd_std,
        "Flow Bytes/s": flow_bytes_per_sec,
        "Flow Packets/s": flow_packets_per_sec,
        "Flow IAT Mean": iat_mean,
        "Flow IAT Std": iat_std,
        "Flow IAT Max": iat_max,
        "Flow IAT Min": iat_min,
        "Fwd IAT Total": fwd_iat_total,
        "Bwd IAT Total": bwd_iat_total,
        "Fwd Packets/s": fwd_packets_per_sec,
        "Bwd Packets/s": bwd_packets_per_sec,
        "Min Packet Length": min_len,
        "Max Packet Length": max_len,
        "Packet Length Mean": mean_len,
        "Packet Length Std": std_len,
        "Packet Length Variance": std_len ** 2,
        "FIN Flag Count": flags["FIN"],
        "SYN Flag Count": flags["SYN"],
        "RST Flag Count": flags["RST"],
        "PSH Flag Count": flags["PSH"],
        "ACK Flag Count": flags["ACK"],
        "URG Flag Count": flags["URG"],
        "Subflow Fwd Packets": len(forward),
        "Subflow Fwd Bytes": total_fwd_bytes,
        "Subflow Bwd Packets": len(backward),
        "Subflow Bwd Bytes": total_bwd_bytes,
        "Init_Win_bytes_forward": 0,
        "Init_Win_bytes_backward": 0,
        "act_data_pkt_fwd": len(forward),
        "min_seg_size_forward": 0
    }

    return features