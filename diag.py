import sqlite3
conn = sqlite3.connect('database/sentry.db')
conn.row_factory = sqlite3.Row

tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("Tables:", [t["name"] for t in tables])

try:
    count = conn.execute("SELECT COUNT(*) FROM packet_logs").fetchone()[0]
    print(f"packet_logs rows: {count}")
    if count > 0:
        rows = conn.execute("SELECT * FROM packet_logs ORDER BY id DESC LIMIT 5").fetchall()
        for r in rows:
            print(" ", dict(r))
    else:
        print("No data in packet_logs - capture engine may not be running.")
except Exception as e:
    print("ERROR:", e)

conn.close()

