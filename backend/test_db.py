from db import get_conn

conn = get_conn()
rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()

print("Connected OK")
for row in rows:
    print(row[0])