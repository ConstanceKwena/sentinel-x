
import os
import sqlite3
from pathlib import Path

# Store the database inside the backend folder.
DATABASE_PATH = Path(
    os.getenv(
        "SENTINEL_DATABASE_PATH",
        str(Path(__file__).resolve().parent / "sentinel_x.db"),
    )
).resolve()


def get_connection():
    """Open a connection to the Sentinel-X database."""
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize_database():
    """Create or safely upgrade the event and incident tables."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
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
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_received_at
            ON security_events(received_at)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_identity_time
            ON security_events(username, source_ip, received_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (
                    severity IN ('Low', 'Medium', 'High', 'Critical')
                ),
                risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                evidence_event_ids TEXT NOT NULL,
                explanation TEXT NOT NULL,
                recommended_actions TEXT NOT NULL,
                attack_chain TEXT,
                status TEXT NOT NULL DEFAULT 'Open' CHECK (
                    status IN ('Open', 'Investigating', 'Resolved')
                ),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL REFERENCES incidents(incident_id)
                    ON DELETE CASCADE,
                previous_status TEXT,
                new_status TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                note TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_incidents_status_severity
            ON incidents(status, severity, updated_at)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_incident_history_incident
            ON incident_history(incident_id, changed_at)
            """
        )
        connection.commit()
    finally:
        connection.close()
