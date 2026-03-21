from services.investigation_api.database import get_connection
from shared.database_utils import rows_to_dicts


def ensure_watchlist_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS watchlist (
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by TEXT NOT NULL,
            PRIMARY KEY (type, value)
        )
        """
    )
    conn.commit()
    cur.close()
    conn.close()


def list_watchlist_entries():
    ensure_watchlist_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT type, value, created_at, created_by
        FROM watchlist
        ORDER BY created_at DESC, value ASC
        """
    )
    rows = rows_to_dicts(cur, cur.fetchall())
    cur.close()
    conn.close()
    return rows


def add_watchlist_entry(entry_type: str, value: str, created_by: str):
    ensure_watchlist_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO watchlist (type, value, created_by)
        VALUES (%s, %s, %s)
        ON CONFLICT (type, value) DO UPDATE SET
            created_by = EXCLUDED.created_by
        RETURNING type, value, created_at, created_by
        """,
        (entry_type, value, created_by),
    )
    row = rows_to_dicts(cur, cur.fetchall())[0]
    conn.commit()
    cur.close()
    conn.close()
    return row


def remove_watchlist_entry(entry_type: str, value: str) -> bool:
    ensure_watchlist_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM watchlist WHERE type=%s AND value=%s",
        (entry_type, value),
    )
    removed = cur.rowcount > 0
    conn.commit()
    cur.close()
    conn.close()
    return removed
