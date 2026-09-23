import sqlite3
c = sqlite3.connect('database/sentry.db')
c.execute("DELETE FROM alerts WHERE attack_type LIKE '%Tiny Packet%'")
c.commit()
c.close()
print('Database cleaned.')
