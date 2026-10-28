
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
    """Create or safely upgrade the event, incident, and response tables."""
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
                received_at TEXT NOT NULL,
                source_origin TEXT NOT NULL DEFAULT 'unknown',
                source_application TEXT
            )
            """
        )
        _ensure_columns(connection, "security_events", {
            "source_origin": "TEXT NOT NULL DEFAULT 'unknown'",
            "source_application": "TEXT",
        })
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
            CREATE INDEX IF NOT EXISTS idx_events_origin_application_time
            ON security_events(source_origin, source_application, received_at)
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
                source_origin TEXT NOT NULL DEFAULT 'unknown',
                source_application TEXT,
                source_ip TEXT,
                username TEXT,
                rule_id TEXT,
                status TEXT NOT NULL DEFAULT 'Open' CHECK (
                    status IN ('Open', 'Investigating', 'Resolved')
                ),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _ensure_columns(connection, "incidents", {
            "source_origin": "TEXT NOT NULL DEFAULT 'unknown'",
            "source_application": "TEXT",
            "source_ip": "TEXT",
            "username": "TEXT",
            "rule_id": "TEXT",
        })
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
            CREATE INDEX IF NOT EXISTS idx_incidents_provenance_rule
            ON incidents(source_origin, source_application, rule_id, status)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_incident_history_incident
            ON incident_history(incident_id, changed_at)
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS connected_applications (
                application_id TEXT PRIMARY KEY,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS response_blocks (
                source_ip TEXT PRIMARY KEY,
                blocked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                removed_at TEXT,
                rule_id TEXT,
                incident_id TEXT,
                source_origin TEXT NOT NULL DEFAULT 'unknown',
                source_application TEXT
            )
            """
        )
        _ensure_columns(connection, "response_blocks", {
            "rule_id": "TEXT",
            "incident_id": "TEXT",
            "source_origin": "TEXT NOT NULL DEFAULT 'unknown'",
            "source_application": "TEXT",
        })
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS response_actions (
                action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                action TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                expires_at TEXT,
                reason TEXT NOT NULL,
                actor TEXT NOT NULL,
                source_origin TEXT NOT NULL DEFAULT 'unknown',
                source_application TEXT
            )
            """
        )
        _ensure_columns(connection, "response_actions", {
            "source_origin": "TEXT NOT NULL DEFAULT 'unknown'",
            "source_application": "TEXT",
        })
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_response_actions_occurred
            ON response_actions(occurred_at)
            """
        )
        connection.commit()
    finally:
        connection.close()


def _ensure_columns(connection, table: str, columns: dict[str, str]) -> None:
    existing = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
    for column, definition in columns.items():
        if column not in existing:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
            )
