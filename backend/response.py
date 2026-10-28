"""Local, auditable response policies for the demo application."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from backend.database import get_connection


@dataclass(frozen=True)
class ResponsePolicy:
    enabled: bool = True
    failed_login_threshold: int = 5
    window_minutes: int = 10
    block_minutes: int = 15
    minimum_accounts: int = 2
    trusted_sources: frozenset[str] = frozenset()

    @classmethod
    def from_environment(cls) -> "ResponsePolicy":
        enabled_value = os.getenv("SENTINEL_AUTO_BLOCK_ENABLED", "true").strip().lower()
        if enabled_value not in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
            raise ValueError("SENTINEL_AUTO_BLOCK_ENABLED must be a boolean value")
        try:
            trusted_sources = frozenset(
                str(ip_address(value.strip()))
                for value in os.getenv("SENTINEL_RESPONSE_TRUSTED_IPS", "").split(",")
                if value.strip()
            )
            policy = cls(
                enabled=enabled_value in {"1", "true", "yes", "on"},
                failed_login_threshold=int(
                    os.getenv("SENTINEL_RESPONSE_FAILED_LOGIN_THRESHOLD", "5")
                ),
                window_minutes=int(os.getenv("SENTINEL_RESPONSE_WINDOW_MINUTES", "10")),
                block_minutes=int(os.getenv("SENTINEL_RESPONSE_BLOCK_MINUTES", "15")),
                minimum_accounts=int(os.getenv("SENTINEL_RESPONSE_MINIMUM_ACCOUNTS", "2")),
                trusted_sources=trusted_sources,
            )
        except ValueError as error:
            raise ValueError("Invalid automatic response policy configuration") from error
        if policy.failed_login_threshold < 2:
            raise ValueError("SENTINEL_RESPONSE_FAILED_LOGIN_THRESHOLD must be at least 2")
        if policy.window_minutes < 1:
            raise ValueError("SENTINEL_RESPONSE_WINDOW_MINUTES must be at least 1")
        if policy.block_minutes < 1:
            raise ValueError("SENTINEL_RESPONSE_BLOCK_MINUTES must be at least 1")
        if policy.minimum_accounts < 2:
            raise ValueError("SENTINEL_RESPONSE_MINIMUM_ACCOUNTS must be at least 2")
        return policy


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _record_expirations(connection: sqlite3.Connection, now: str) -> None:
    expired = connection.execute(
        """
        SELECT source_ip, expires_at, reason, source_origin, source_application
        FROM response_blocks
        WHERE removed_at IS NULL AND expires_at <= ?
        """,
        (now,),
    ).fetchall()
    for block in expired:
        connection.execute(
            "UPDATE response_blocks SET removed_at = ? WHERE source_ip = ?",
            (block["expires_at"], block["source_ip"]),
        )
        connection.execute(
            """
            INSERT INTO response_actions(
                source_ip, action, occurred_at, expires_at, reason, actor,
                source_origin, source_application
            ) VALUES (?, 'automatic_expiry', ?, ?, ?, 'policy', ?, ?)
            """,
            (
                block["source_ip"],
                block["expires_at"],
                block["expires_at"],
                block["reason"],
                block["source_origin"],
                block["source_application"],
            ),
        )
    if expired:
        connection.commit()


def record_application(application_id: str) -> None:
    now = _timestamp(utc_now())
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO connected_applications(application_id, first_seen_at, last_seen_at)
            VALUES (?, ?, ?)
            ON CONFLICT(application_id) DO UPDATE SET last_seen_at = excluded.last_seen_at
            """,
            (application_id, now, now),
        )
        connection.commit()
    finally:
        connection.close()


def list_applications() -> list[dict]:
    now = utc_now()
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT application_id, first_seen_at, last_seen_at
            FROM connected_applications ORDER BY application_id
            """
        ).fetchall()
        return [
            {
                **dict(row),
                "status": (
                    "connected"
                    if now - datetime.fromisoformat(row["last_seen_at"])
                    <= timedelta(minutes=5)
                    else "stale"
                ),
            }
            for row in rows
        ]
    finally:
        connection.close()


def active_blocks(
    source_origin: str | None = None,
    source_application: str | None = None,
) -> list[dict]:
    now = _timestamp(utc_now())
    connection = get_connection()
    try:
        _record_expirations(connection, now)
        rows = connection.execute(
            """
            SELECT source_ip, blocked_at, expires_at, reason, rule_id, incident_id,
                   source_origin, source_application
            FROM response_blocks
            WHERE removed_at IS NULL AND expires_at > ?
              AND (? IS NULL OR source_origin = ?)
              AND (? IS NULL OR source_application = ?)
            ORDER BY blocked_at DESC
            """,
            (now, source_origin, source_origin, source_application, source_application),
        ).fetchall()
        return [{**dict(row), "status": "active"} for row in rows]
    finally:
        connection.close()


def response_history(
    limit: int = 50,
    source_origin: str | None = None,
    source_application: str | None = None,
) -> list[dict]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT source_ip, action, occurred_at, expires_at, reason, actor,
                   source_origin, source_application
            FROM response_actions
            WHERE (? IS NULL OR source_origin = ?)
              AND (? IS NULL OR source_application = ?)
            ORDER BY action_id DESC LIMIT ?
            """,
            (
                source_origin,
                source_origin,
                source_application,
                source_application,
                limit,
            ),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def source_is_blocked(source_ip: str) -> bool:
    now = _timestamp(utc_now())
    connection = get_connection()
    try:
        _record_expirations(connection, now)
        row = connection.execute(
            """
            SELECT 1 FROM response_blocks
            WHERE source_ip = ? AND removed_at IS NULL AND expires_at > ?
              AND source_origin = 'connected_application'
            """,
            (source_ip, now),
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def evaluate_failed_login(
    source_ip: str,
    source_application: str | None = None,
) -> dict | None:
    policy = ResponsePolicy.from_environment()
    if not policy.enabled or source_ip in policy.trusted_sources:
        return None

    now = utc_now()
    since = _timestamp(now - timedelta(minutes=policy.window_minutes))
    connection = get_connection()
    try:
        _record_expirations(connection, _timestamp(now))
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            """
            SELECT DISTINCT event_id, username FROM security_events
            WHERE source_ip = ? AND event_type = 'login_failed'
              AND source_origin = 'connected_application'
              AND source_application = ? AND received_at >= ?
            ORDER BY received_at DESC
            """,
            (source_ip, source_application, since),
        ).fetchall()
        usernames = {row["username"] for row in rows}
        if (
            len(rows) < policy.failed_login_threshold
            or len(usernames) < policy.minimum_accounts
        ):
            return None

        blocked_at = _timestamp(now)
        expires_at = _timestamp(now + timedelta(minutes=policy.block_minutes))
        reason = (
            f"{len(rows)} failed logins across {len(usernames)} accounts within "
            f"{policy.window_minutes} minutes"
        )
        incident = connection.execute(
            """
            SELECT incident_id FROM incidents
            WHERE source_origin = 'connected_application'
              AND source_application = ? AND source_ip = ? AND rule_id = 'AUTH-002'
            ORDER BY created_at DESC LIMIT 1
            """,
            (source_application, source_ip),
        ).fetchone()
        incident_id = incident["incident_id"] if incident else None
        active = connection.execute(
            """
            SELECT 1 FROM response_blocks
            WHERE source_ip = ? AND removed_at IS NULL AND expires_at > ?
            """,
            (source_ip, blocked_at),
        ).fetchone()
        if active:
            return None

        connection.execute(
            """
            INSERT INTO response_blocks(
                source_ip, blocked_at, expires_at, reason, removed_at, rule_id,
                incident_id, source_origin, source_application
            )
            VALUES (?, ?, ?, ?, NULL, 'AUTH-002', ?, 'connected_application', ?)
            ON CONFLICT(source_ip) DO UPDATE SET
                blocked_at = excluded.blocked_at,
                expires_at = excluded.expires_at,
                reason = excluded.reason,
                removed_at = NULL,
                rule_id = excluded.rule_id,
                incident_id = excluded.incident_id,
                source_origin = excluded.source_origin,
                source_application = excluded.source_application
            """,
            (source_ip, blocked_at, expires_at, reason, incident_id, source_application),
        )
        connection.execute(
            """
            INSERT INTO response_actions(
                source_ip, action, occurred_at, expires_at, reason, actor,
                source_origin, source_application
            ) VALUES (?, 'automatic_block', ?, ?, ?, 'policy', 'connected_application', ?)
            """,
            (source_ip, blocked_at, expires_at, reason, source_application),
        )
        connection.commit()
        return {
            "source_ip": source_ip,
            "blocked_at": blocked_at,
            "expires_at": expires_at,
            "reason": reason,
            "rule_id": "AUTH-002",
            "incident_id": incident_id,
        }
    finally:
        connection.close()


def remove_block(source_ip: str, actor: str) -> bool:
    now = _timestamp(utc_now())
    connection = get_connection()
    try:
        _record_expirations(connection, now)
        row = connection.execute(
            """
            SELECT reason, source_origin, source_application FROM response_blocks
            WHERE source_ip = ? AND removed_at IS NULL AND expires_at > ?
              AND source_origin = 'connected_application'
            """,
            (source_ip, now),
        ).fetchone()
        if row is None:
            return False
        connection.execute(
            "UPDATE response_blocks SET removed_at = ? WHERE source_ip = ?",
            (now, source_ip),
        )
        connection.execute(
            """
            INSERT INTO response_actions(
                source_ip, action, occurred_at, expires_at, reason, actor,
                source_origin, source_application
            ) VALUES (?, 'manual_unblock', ?, NULL, ?, ?, ?, ?)
            """,
            (
                source_ip,
                now,
                row["reason"],
                actor,
                row["source_origin"],
                row["source_application"],
            ),
        )
        connection.commit()
        return True
    finally:
        connection.close()


def policy_status() -> dict:
    policy = ResponsePolicy.from_environment()
    return {
        "enabled": policy.enabled,
        "failed_login_threshold": policy.failed_login_threshold,
        "window_minutes": policy.window_minutes,
        "block_minutes": policy.block_minutes,
        "minimum_accounts": policy.minimum_accounts,
    }
