SIGNATURES = [
    {
        "name": "Telnet Traffic",
        "protocol": "TCP",
        "destination_port": 23,
        "attack_type": "Insecure Remote Access",
        "severity": "MEDIUM",
        "description": "Traffic detected on the Telnet service port"
    },
    {
        "name": "SMB Traffic",
        "protocol": "TCP",
        "destination_port": 445,
        "attack_type": "SMB Activity",
        "severity": "MEDIUM",
        "description": "Traffic detected on the SMB service port"
    },
    {
        "name": "RDP Traffic",
        "protocol": "TCP",
        "destination_port": 3389,
        "attack_type": "Remote Desktop Activity",
        "severity": "MEDIUM",
        "description": "Traffic detected on the RDP service port"
    },
    {
        "name": "FTP Traffic",
        "protocol": "TCP",
        "destination_port": 21,
        "attack_type": "FTP Activity",
        "severity": "LOW",
        "description": "Traffic detected on the FTP service port"
    },
    {
        "name": "VNC Traffic",
        "protocol": "TCP",
        "destination_port": 5900,
        "attack_type": "Remote Desktop Activity",
        "severity": "MEDIUM",
        "description": "Traffic detected on the VNC service port"
    }
]


def match_signatures(features):
    matches = []

    protocol = features.get("protocol")
    destination_port = features.get("destination_port")

    for signature in SIGNATURES:
        if (
            protocol == signature["protocol"]
            and destination_port == signature["destination_port"]
        ):
            matches.append({
                "detected": True,
                "signature": signature["name"],
                "attack_type": signature["attack_type"],
                "severity": signature["severity"],
                "reason": signature["description"]
            })

    return matches