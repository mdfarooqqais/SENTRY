from flask import Flask, render_template
from database.database import get_alerts, init_database

app = Flask(__name__)

init_database()


@app.route("/")
def home():
    alerts = get_alerts()
    return render_template("index.html", alerts=alerts)


if __name__ == "__main__":
    app.run(debug=True)