import sqlite3

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

    connection.commit()
    connection.close()


def save_alert(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    detection_type,
    attack_type,
    severity,
    confidence=0
):
    connection = get_connection()

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
            datetime('now'),
            ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    """, (
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

    return alerts


if __name__ == "__main__":
    init_database()
    print("Database initialized successfully.")