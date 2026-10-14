
import sqlite3
from pathlib import Path

# Store the database inside the backend folder.
DATABASE_PATH = Path(__file__).resolve().parent / "sentinel_x.db"


def get_connection():
    """Open a connection to the Sentinel-X database."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Create the security_events table if it doesn't exist."""
    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                details TEXT,
                received_at TEXT NOT NULL
            )
            """
        )
        connection.commit()
    finally:
        connection.close()
