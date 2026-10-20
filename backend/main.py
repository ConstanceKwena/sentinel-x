
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, Query

from pydantic import BaseModel, Field, IPvAnyAddress

from backend.database import get_connection, initialize_database

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield

app = FastAPI(
    title="Sentinel-X",
    description="AI-powered attack-chain detection and security operations platform.",
    version="0.1.0",
    lifespan=lifespan,

)


class SecurityEvent(BaseModel):
    event_type: Literal[
        "login_failed",
        "login_success",
        "privilege_change",
        "internal_discovery",
        "outbound_transfer",
    ]
    username: str = Field(min_length=1, max_length=100)
    source_ip: IPvAnyAddress
    details: str | None = Field(default=None, max_length=500)


@app.get("/")
def root():
    return {
        "project": "Sentinel-X",
        "status": "online",
        "message": "Sentinel-X API is running.",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/events", status_code=201)
def ingest_event(event: SecurityEvent):
    event_id = str(uuid4())
    received_at = datetime.now(timezone.utc).isoformat()

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO security_events (
                event_id, event_type, username,
                source_ip, details, received_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event.event_type,
                event.username,
                str(event.source_ip),
                event.details,
                received_at,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return {
        "message": "Security event saved successfully.",
        "event_id": event_id,
        "received_at": received_at,
        "event": event,

    }


@app.get("/events")
def get_events(
    event_type: Literal[
        "login_failed",
        "login_success",
        "privilege_change",
        "internal_discovery",
        "outbound_transfer",
    ] | None = None,
    username: str | None = None,
    source_ip: IPvAnyAddress | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    connection = get_connection()

    filters = []
    parameters = []

    if event_type is not None:
        filters.append("event_type = ?")
        parameters.append(event_type)

    if username is not None:
        filters.append("username = ?")
        parameters.append(username)

    if source_ip is not None:
        filters.append("source_ip = ?")
        parameters.append(str(source_ip))

    where_clause = (
        f"WHERE {' AND '.join(filters)}"
        if filters
        else ""
    )

    try:
        rows = connection.execute(
            f"""
            SELECT event_id, event_type, username,
                   source_ip, details, received_at
            FROM security_events
            {where_clause}
            ORDER BY received_at DESC
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()

        return {
            "count": len(rows),
            "events": [dict(row) for row in rows],
        }
    finally:
        connection.close()
