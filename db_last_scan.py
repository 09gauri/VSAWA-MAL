import sqlite3
DB = r"D:\VSAWA\data\vsawa.db"
con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

scan = con.execute("SELECT * FROM scans ORDER BY scan_id DESC LIMIT 1").fetchone()
print("last_scan:", dict(scan) if scan else None)

if scan:
    sid = scan["scan_id"]
    c = con.execute("SELECT COUNT(*) AS c FROM findings WHERE scan_id=?", (sid,)).fetchone()["c"]
    print("findings_count_for_last_scan:", c)

con.close()
