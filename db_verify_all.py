import sqlite3
DB = r"D:\VSAWA\data\vsawa.db"
con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

scan = con.execute("SELECT * FROM scans ORDER BY scan_id DESC LIMIT 1").fetchone()
print("scan:", dict(scan) if scan else None)

if scan:
    sid = scan["scan_id"]
    findings = con.execute("""
        SELECT finding_id, finding_no, severity, title
        FROM findings
        WHERE scan_id=?
        ORDER BY finding_no
    """, (sid,)).fetchall()
    print("findings_count:", len(findings))
    print("first3_findings:", [dict(r) for r in findings[:3]])

    if findings:
        fid = findings[0]["finding_id"]
        ev = con.execute("SELECT evidence_type, url, content FROM evidence WHERE finding_id=? LIMIT 2", (fid,)).fetchall()
        rm = con.execute("SELECT source, text, reference_url FROM remediations WHERE finding_id=? LIMIT 2", (fid,)).fetchall()
        ep = con.execute("SELECT method, path, status_code FROM affected_endpoints WHERE finding_id=? LIMIT 2", (fid,)).fetchall()
        print("evidence_first_finding:", [dict(r) for r in ev])
        print("remediations_first_finding:", [dict(r) for r in rm])
        print("endpoints_first_finding:", [dict(r) for r in ep])

con.close()
