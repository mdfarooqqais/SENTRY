import sqlite3
import random
from datetime import datetime, timedelta

DATABASE = "database/sentry.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            detection_type TEXT,
            attack_type TEXT,
            severity TEXT,
            confidence REAL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            normal_packets INTEGER,
            suspicious_packets INTEGER,
            bandwidth_mbps REAL
        )
    """)

    connection.commit()
    
    # Check if empty and seed initial data
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]
    connection.close()

    if count == 0:
        seed_mock_data()


def save_alert(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    detection_type,
    attack_type,
    severity,
    confidence=0,
    timestamp=None
):
    connection = get_connection()

    ts = timestamp if timestamp else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    connection.execute("""
        INSERT INTO alerts (
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            detection_type,
            attack_type,
            severity,
            confidence
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    """, (
        ts,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol,
        detection_type,
        attack_type,
        severity,
        confidence
    ))

    connection.commit()
    connection.close()


def get_alerts(limit=100):
    connection = get_connection()

    alerts = connection.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()

    connection.close()

    return [dict(alert) for alert in alerts]


def clear_alerts():
    connection = get_connection()
    connection.execute("DELETE FROM alerts")
    connection.commit()
    connection.close()


def get_alert_stats():
    connection = get_connection()

    total_alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    high_count = connection.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]
    med_count = connection.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'").fetchone()[0]
    low_count = connection.execute("SELECT COUNT(*) FROM alerts WHERE severity='LOW'").fetchone()[0]
    attack_count = connection.execute("SELECT COUNT(*) FROM alerts WHERE attack_type != 'BENIGN'").fetchone()[0]

    # Attack types distribution
    attack_types_rows = connection.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM alerts 
        GROUP BY attack_type
    """).fetchall()
    attack_types = {row['attack_type']: row['count'] for row in attack_types_rows}

    # Detection types distribution
    detection_types_rows = connection.execute("""
        SELECT detection_type, COUNT(*) as count 
        FROM alerts 
        GROUP BY detection_type
    """).fetchall()
    detection_types = {row['detection_type']: row['count'] for row in detection_types_rows}

    # Protocols distribution
    protocol_rows = connection.execute("""
        SELECT protocol, COUNT(*) as count 
        FROM alerts 
        GROUP BY protocol
    """).fetchall()
    protocols = {row['protocol']: row['count'] for row in protocol_rows}

    connection.close()

    total_packets_row = get_connection().execute("SELECT SUM(normal_packets + suspicious_packets) FROM traffic_stats").fetchone()[0]
    total_packets = total_packets_row if total_packets_row else 0

    return {
        "total_alerts": total_alerts,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "attack_count": attack_count,
        "attack_types": attack_types,
        "detection_types": detection_types,
        "protocols": protocols,
        "total_packets": total_packets
    }


def seed_mock_data():
    mock_attacks = [
        ("192.168.1.105", "10.0.0.1", 49152, 80, "TCP", "Rule-Based", "Possible Port Scan", "HIGH", 0.95),
        ("10.0.0.45", "10.0.0.1", 54321, 23, "TCP", "Rule-Based", "Suspicious Port (Telnet)", "MEDIUM", 0.88),
        ("172.16.0.12", "10.0.0.1", 33890, 443, "UDP", "ML Anomaly", "DoS Flood Anomaly", "HIGH", 0.92),
        ("192.168.1.110", "10.0.0.1", 40012, 21, "TCP", "Signature-Based", "FTP Brute Force Signature", "HIGH", 0.99),
        ("192.168.1.50", "10.0.0.1", 50123, 8080, "HTTP", "Rule-Based", "Large Packet Anomaly", "LOW", 0.75),
        ("10.0.0.88", "10.0.0.1", 42311, 445, "TCP", "Signature-Based", "SMB Exec Pattern", "HIGH", 0.97),
        ("192.168.1.115", "10.0.0.1", 39120, 80, "TCP", "ML Anomaly", "Unusual Flow Rate", "MEDIUM", 0.84),
        ("192.168.1.200", "10.0.0.1", 51234, 53, "UDP", "Rule-Based", "DNS Tunneling Suspect", "MEDIUM", 0.81),
        ("10.0.0.12", "10.0.0.1", 44332, 3389, "TCP", "Signature-Based", "RDP Attack Pattern", "HIGH", 0.94),
        ("192.168.1.15", "10.0.0.1", 12345, 80, "TCP", "ML Anomaly", "CICIDS Anomaly Detected", "HIGH", 0.90),
    ]

    now = datetime.now()
    for i, attack in enumerate(mock_attacks):
        ts = (now - timedelta(minutes=(len(mock_attacks) - i) * 3)).strftime("%Y-%m-%d %H:%M:%S")
        save_alert(
            source_ip=attack[0],
            destination_ip=attack[1],
            source_port=attack[2],
            destination_port=attack[3],
            protocol=attack[4],
            detection_type=attack[5],
            attack_type=attack[6],
            severity=attack[7],
            confidence=attack[8],
            timestamp=ts
        )

def log_traffic(normal_packets, suspicious_packets, bandwidth_mbps):
    connection = get_connection()
    ts = datetime.now().strftime("%H:%M:%S")
    connection.execute("""
        INSERT INTO traffic_stats (timestamp, normal_packets, suspicious_packets, bandwidth_mbps)
        VALUES (?, ?, ?, ?)
    """, (ts, normal_packets, suspicious_packets, bandwidth_mbps))
    connection.commit()
    connection.close()

def get_recent_traffic(limit=12):
    connection = get_connection()
    rows = connection.execute("""
        SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    connection.close()
    return [dict(row) for row in reversed(rows)]


if __name__ == "__main__":
    init_database()
    print("Database initialized & seeded successfully.")
