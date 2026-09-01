import random
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from database.database import (
    init_database,
    get_alerts,
    get_alert_stats,
    clear_alerts,
    save_alert
)

app = Flask(__name__)

# Global engine operational state
engine_state = {
    "status": "ONLINE",
    "monitoring": True,
    "total_packets": 14280,
    "rule_engine": "ONLINE",
    "signature_engine": "ONLINE",
    "ml_engine": "ONLINE",
    "start_time": time.time()
}


@app.route("/")
def home():
    init_database()
    alerts = get_alerts(100)
    stats = get_alert_stats()

    return render_template(
        "index.html",
        alerts=alerts,
        total_alerts=stats["total_alerts"],
        attack_count=stats["attack_count"],
        high_count=stats["high_count"],
        engine_state=engine_state
    )


@app.route("/api/stats")
def api_stats():
    stats = get_alert_stats()
    uptime_sec = int(time.time() - engine_state["start_time"])

    # Simulate packet count growth if monitoring is active
    if engine_state["monitoring"]:
        engine_state["total_packets"] += random.randint(5, 25)

    return jsonify({
        "status": "success",
        "total_packets": engine_state["total_packets"],
        "total_alerts": stats["total_alerts"],
        "attack_count": stats["attack_count"],
        "high_count": stats["high_count"],
        "medium_count": stats["medium_count"],
        "low_count": stats["low_count"],
        "uptime": uptime_sec,
        "engine_state": engine_state,
        "attack_types": stats["attack_types"],
        "detection_types": stats["detection_types"],
        "protocols": stats["protocols"]
    })


@app.route("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", 100, type=int)
    severity = request.args.get("severity", None)
    search = request.args.get("search", None)

    alerts = get_alerts(limit)

    if severity:
        alerts = [a for a in alerts if a["severity"].upper() == severity.upper()]

    if search:
        s = search.lower()
        alerts = [
            a for a in alerts
            if s in a["source_ip"].lower()
            or s in a["destination_ip"].lower()
            or s in a["attack_type"].lower()
            or s in a["detection_type"].lower()
            or s in a["protocol"].lower()
        ]

    return jsonify({
        "status": "success",
        "count": len(alerts),
        "alerts": alerts
    })


@app.route("/api/traffic")
def api_traffic():
    """Generates real-time packet throughput metrics for live line charts."""
    now = datetime.now()
    labels = [(now - timedelta(seconds=i*3)).strftime("%H:%M:%S") for i in range(12)][::-1]

    # Generate synthetic traffic rate curve with realistic spikes
    normal_rates = [random.randint(120, 240) for _ in range(12)]
    attack_rates = [random.randint(5, 45) for _ in range(12)]

    return jsonify({
        "status": "success",
        "timestamps": labels,
        "normal_packets": normal_rates,
        "suspicious_packets": attack_rates,
        "current_pps": random.randint(140, 280),
        "bandwidth_mbps": round(random.uniform(1.2, 4.8), 2)
    })


@app.route("/api/engine/status")
def api_engine_status():
    return jsonify({
        "status": "success",
        "engine": engine_state
    })


@app.route("/api/engine/toggle", methods=["POST"])
def api_engine_toggle():
    engine_state["monitoring"] = not engine_state["monitoring"]
    engine_state["status"] = "ONLINE" if engine_state["monitoring"] else "PAUSED"
    return jsonify({
        "status": "success",
        "monitoring": engine_state["monitoring"],
        "engine_status": engine_state["status"]
    })


@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    clear_alerts()
    return jsonify({
        "status": "success",
        "message": "All alerts cleared successfully"
    })


@app.route("/api/alerts/simulate", methods=["POST"])
def api_alerts_simulate():
    """Endpoint to trigger a simulated attack event for live testing."""
    attacks = [
        ("192.168.1.188", "10.0.0.1", 44321, 80, "TCP", "Rule-Based", "SYN Flood Attack", "HIGH", 0.96),
        ("10.0.0.99", "10.0.0.1", 55432, 22, "TCP", "Signature-Based", "SSH Brute Force Signature", "HIGH", 0.98),
        ("172.16.4.55", "10.0.0.1", 38921, 445, "TCP", "ML Anomaly", "SMB Vulnerability Anomaly", "MEDIUM", 0.89),
        ("192.168.1.72", "10.0.0.1", 51200, 53, "UDP", "Rule-Based", "DNS Amplification Spike", "HIGH", 0.93)
    ]
    atk = random.choice(attacks)
    save_alert(
        source_ip=atk[0],
        destination_ip=atk[1],
        source_port=atk[2],
        destination_port=atk[3],
        protocol=atk[4],
        detection_type=atk[5],
        attack_type=atk[6],
        severity=atk[7],
        confidence=atk[8]
    )
    return jsonify({
        "status": "success",
        "message": "Simulated threat injected into SENTRY alert queue"
    })


if __name__ == "__main__":
    init_database()
    app.run(debug=True)