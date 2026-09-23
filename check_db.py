import sqlite3
c = sqlite3.connect('database/sentry.db')
count = c.execute("SELECT COUNT(*) FROM alerts WHERE attack_type LIKE '%Tiny%'").fetchone()[0]
print(f"Remaining Tiny Packet Alerts: {count}")
c.close()

