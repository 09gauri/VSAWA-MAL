# from db import get_conn

# def init_db():
#     with open("schema.sql", "r", encoding="utf-8") as f:
#         schema = f.read()
#     conn = get_conn()
#     conn.executescript(schema)
#     conn.commit()
#     conn.close()

# if __name__ == "__main__":
#     init_db()
#     print("DB initialized.")

import datetime
from db import get_conn


def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def table_exists(conn, table_name):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def column_names(conn, table_name):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}


def add_column_if_missing(conn, table_name, column_name, column_definition):
    if not table_exists(conn, table_name):
        return

    if column_name not in column_names(conn, table_name):
        conn.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )


def run_legacy_migrations(conn):
    """
    Keep existing SQLite databases compatible with newer schema.sql versions.

    CREATE TABLE IF NOT EXISTS does not update an old table. If an older
    notifications table already exists without the new read/unread columns,
    schema.sql fails while creating idx_notifications_user_read because is_read
    is missing.
    """
    add_column_if_missing(conn, "notifications", "title", "TEXT")
    add_column_if_missing(conn, "notifications", "message", "TEXT")
    add_column_if_missing(conn, "notifications", "level", "TEXT DEFAULT 'INFO'")
    add_column_if_missing(conn, "notifications", "is_read", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(conn, "notifications", "read_at", "TEXT")
    add_column_if_missing(conn, "notifications", "scan_id", "INTEGER")
    add_column_if_missing(conn, "notifications", "action_url", "TEXT")
    add_column_if_missing(conn, "notifications", "metadata_json", "TEXT")


def init_db():
    with open("schema.sql", "r", encoding="utf-8") as f:
        schema = f.read()

    conn = get_conn()
    run_legacy_migrations(conn)
    conn.executescript(schema)

    # demo user
    conn.execute("""
      INSERT OR IGNORE INTO users(user_id, name, email, password_hash, status, created_at)
      VALUES(1, 'Demo User', 'demo@vsawa.local', 'dev', 'ACTIVE', ?)
    """, (now_iso(),))

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("DB initialized + demo user inserted.")
