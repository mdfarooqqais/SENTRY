from flask import Flask, render_template
from database.database import init_database, get_alerts

app = Flask(__name__)


@app.route("/")
def home():
    alerts = get_alerts(100)

    total_alerts = len(alerts)

    attack_count = sum(
        1 for alert in alerts
        if alert["attack_type"] != "BENIGN"
    )

    high_count = sum(
        1 for alert in alerts
        if alert["severity"] == "HIGH"
    )

    return render_template(
        "index.html",
        alerts=alerts,
        total_alerts=total_alerts,
        attack_count=attack_count,
        high_count=high_count
    )


if __name__ == "__main__":
    init_database()
    app.run(debug=True)