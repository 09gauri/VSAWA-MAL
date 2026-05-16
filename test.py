import sqlite3

# Database ka naam
DB_NAME = "vulnerability.db"

def execute_sql_file(cursor, filename):
    """
    SQL file read karke execute karta hai
    """
    with open(filename, 'r') as file:
        sql_script = file.read()
        cursor.executescript(sql_script)

def main():
    # Database connect (agar nahi hai toh create ho jayega)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 🔑 FOREIGN KEY ENABLE (ONLY ADDITION)
    cursor.execute("PRAGMA foreign_keys = ON;")

    print("Database connected successfully")

    # Schema create
    execute_sql_file(cursor, "schema.sql")
    print("Tables created successfully")

    # Sample data insert
    execute_sql_file(cursor, "sample.sql")
    print("Sample data inserted successfully")

    # FINDINGS TABLE TEST
    cursor.execute("SELECT * FROM findings")
    findings_rows = cursor.fetchall()

    print("\nData from findings table:")
    for row in findings_rows:
        print(row)

    # SCANS TABLE TEST
    cursor.execute("SELECT * FROM scans")
    scans_rows = cursor.fetchall()

    print("\nData from scans table:")
    for row in scans_rows:
        print(row)

    # URL TARGETS TABLE TEST
    cursor.execute("SELECT * FROM url_targets")
    url_rows = cursor.fetchall()

    print("\nData from url_targets table:")
    for row in url_rows:
        print(row)

    # USERS TABLE TEST  
    cursor.execute("SELECT * FROM users")
    user_rows = cursor.fetchall()

    print("\nData from users table:")
    for row in user_rows:
        print(row)

    # Save & close
    conn.commit()
    conn.close()
    print("\nDatabase connection closed")

if __name__ == "__main__":
    main()
