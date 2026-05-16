import sqlite3
from pathlib import Path

DB = Path(r"D:\VSAWA\data\vsawa.db")

print("DB exists:", DB.exists(), "path:", DB)

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row
cur = con.cursor()

cur.execute("PRAGMA foreign_keys=ON;")
print("foreign_keys =", con.execute("PRAGMA foreign_keys;").fetchone()[0])

tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;").fetchall()]
print("tables =", tables)

def table_info(name):
    rows = con.execute(f"PRAGMA table_info({name});").fetchall()
    return [(r["name"], r["type"], r["notnull"], r["dflt_value"], r["pk"]) for r in rows]

for t in ["users", "targets", "url_targets", "scans", "findings", "evidence", "remediations", "affected_endpoints", "reports", "report_items"]:
    if t in tables:
        print(f"\n== {t} ==")
        print(table_info(t))

print("\nforeign_key_check =", con.execute("PRAGMA foreign_key_check;").fetchall())
con.close()
