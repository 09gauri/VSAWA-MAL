import sqlite3, time

DB = r"D:\VSAWA\data\vsawa.db"

def row_to_dict(r):
    return dict(r) if r else None

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

last = con.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1").fetchone()
last_id = last["scan_id"] if last else None
print("starting from last scan_id:", last_id)

for _ in range(60):  # 60 checks (~60 sec)
    scan = con.execute("SELECT * FROM scans ORDER BY scan_id DESC LIMIT 1").fetchone()
    if not scan:
        print("no scans yet...")
        time.sleep(1)
        continue

    sid = scan["scan_id"]
    status = scan["status"]
    total = scan["total_findings"]
    print(f"scan_id={sid} status={status} total_findings={total}")

    # show findings count live
    fcount = con.execute("SELECT COUNT(*) AS c FROM findings WHERE scan_id=?", (sid,)).fetchone()["c"]
    print("  findings_count:", fcount)

    if status in ("COMPLETED", "FAILED"):
        if status == "COMPLETED":
            # show a sample finding + its children
            f = con.execute("""
                SELECT finding_id, finding_no, severity, title
                FROM findings WHERE scan_id=?
                ORDER BY finding_no LIMIT 1
            """, (sid,)).fetchone()
            print("  first_finding:", row_to_dict(f))

            if f:
                fid = f["finding_id"]
                ev = con.execute("SELECT COUNT(*) AS c FROM evidence WHERE finding_id=?", (fid,)).fetchone()["c"]
                rm = con.execute("SELECT COUNT(*) AS c FROM remediations WHERE finding_id=?", (fid,)).fetchone()["c"]
                ep = con.execute("SELECT COUNT(*) AS c FROM affected_endpoints WHERE finding_id=?", (fid,)).fetchone()["c"]
                print(f"  child counts for first finding: evidence={ev} remediations={rm} endpoints={ep}")
        else:
            print("  error_message:", scan["error_message"])
        break

    time.sleep(1)

con.close()
