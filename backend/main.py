from __future__ import annotations

import hashlib
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

from backend.database import get_connection, initialize_database
from backend.detection import correlate_attack_chains, detect_threats


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Sentinel-X",
    description="Rule-based threat detection and security incident response platform.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type"],
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

    @field_validator("username")
    @classmethod
    def username_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("username must not be blank")
        return value


class IncidentStatusUpdate(BaseModel):
    status: Literal["Open", "Investigating", "Resolved"]
    note: str | None = Field(default=None, max_length=500)


class SimulationRequest(BaseModel):
    scenario: Literal[
        "brute_force",
        "account_compromise",
        "privilege_escalation",
        "data_transfer",
        "full_attack_chain",
    ] = "full_attack_chain"


def _read_events() -> list[dict]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT event_id, event_type, username, source_ip, details, received_at
            FROM security_events
            ORDER BY received_at ASC, id ASC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def _risk_severity(value: str) -> str:
    return value.title()


def _serialize_incident(row) -> dict:
    incident = dict(row)
    for field in ("evidence_event_ids", "recommended_actions", "attack_chain"):
        raw = incident.pop(field)
        incident[field] = json.loads(raw) if raw is not None else None
    return incident


def _refresh_incidents(events: list[dict] | None = None) -> int:
    events = _read_events() if events is None else events
    detections = detect_threats(events)
    chains = {
        chain["chain_id"]: chain
        for chain in correlate_attack_chains(events)
    }
    connection = get_connection()
    created_count = 0
    try:
        now = datetime.now(timezone.utc).isoformat()
        for detection in detections:
            evidence_ids = detection["evidence_event_ids"]
            fingerprint = hashlib.sha256(
                (detection["rule_id"] + ":" + ":".join(evidence_ids)).encode("utf-8")
            ).hexdigest()
            incident_id = f"INC-{uuid4().hex.upper()}"
            chain = chains.get(detection.get("chain_id"))
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO incidents (
                    incident_id, fingerprint, title, description, severity, risk_score,
                    evidence_event_ids, explanation, recommended_actions, attack_chain,
                    status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
                """,
                (
                    incident_id,
                    fingerprint,
                    detection["description"],
                    detection["description"],
                    _risk_severity(detection["severity"]),
                    max(0, min(100, int(detection["risk_score"]))),
                    json.dumps(evidence_ids),
                    detection["explanation"],
                    json.dumps(detection["recommended_actions"]),
                    json.dumps(chain) if chain else None,
                    now,
                    now,
                ),
            )
            if cursor.rowcount:
                created_count += 1
                connection.execute(
                    """
                    INSERT INTO incident_history (
                        incident_id, previous_status, new_status, changed_at, note
                    ) VALUES (?, NULL, 'Open', ?, 'Incident created by rule-based detection.')
                    """,
                    (incident_id, now),
                )
        connection.commit()
    finally:
        connection.close()
    return created_count


def _insert_event(event: SecurityEvent) -> dict:
    event_id = str(uuid4())
    received_at = datetime.now(timezone.utc).isoformat()
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO security_events (
                event_id, event_type, username, source_ip, details, received_at
            ) VALUES (?, ?, ?, ?, ?, ?)
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
        "event_id": event_id,
        "event_type": event.event_type,
        "username": event.username,
        "source_ip": str(event.source_ip),
        "details": event.details,
        "received_at": received_at,
    }


@app.get("/")
def root():
    return {
        "project": "Sentinel-X",
        "status": "online",
        "message": "Sentinel-X API is running.",
        "dashboard": "/dashboard",
    }


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).resolve().parent.parent / "frontend" / "index.html")


@app.get("/styles.css", include_in_schema=False)
def dashboard_stylesheet():
    return FileResponse(Path(__file__).resolve().parent.parent / "frontend" / "styles.css")


@app.get("/app.js", include_in_schema=False)
def dashboard_script():
    return FileResponse(Path(__file__).resolve().parent.parent / "frontend" / "app.js")


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/events", status_code=201)
def ingest_event(event: SecurityEvent):
    saved_event = _insert_event(event)
    events = _read_events()
    _refresh_incidents(events)
    return {
        "message": "Security event saved successfully.",
        "event_id": saved_event["event_id"],
        "received_at": saved_event["received_at"],
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
    username: str | None = Query(default=None, min_length=1, max_length=100),
    source_ip: IPvAnyAddress | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    conditions = []
    parameters: list[object] = []
    if event_type is not None:
        conditions.append("event_type = ?")
        parameters.append(event_type)
    if username is not None:
        normalized_username = username.strip()
        if not normalized_username:
            raise HTTPException(status_code=422, detail="Username filter must not be blank.")
        conditions.append("username = ?")
        parameters.append(normalized_username)
    if source_ip is not None:
        conditions.append("source_ip = ?")
        parameters.append(str(source_ip))
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    connection = get_connection()
    try:
        rows = connection.execute(
            f"""
            SELECT event_id, event_type, username, source_ip, details, received_at
            FROM security_events
            {where_clause}
            ORDER BY received_at DESC, id DESC
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()
        return {"count": len(rows), "events": [dict(row) for row in rows]}
    finally:
        connection.close()


@app.get("/detections")
def get_detections():
    events = _read_events()
    _refresh_incidents(events)
    detections = detect_threats(events)
    return {"count": len(detections), "detections": detections}


@app.get("/attack-chains")
def get_attack_chains():
    return {"chains": correlate_attack_chains(_read_events())}


@app.get("/incidents")
def get_incidents(
    status: Literal["Open", "Investigating", "Resolved"] | None = None,
    severity: Literal["Low", "Medium", "High", "Critical"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    _refresh_incidents()
    filters = []
    parameters: list[object] = []
    if status is not None:
        filters.append("status = ?")
        parameters.append(status)
    if severity is not None:
        filters.append("severity = ?")
        parameters.append(severity)
    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    connection = get_connection()
    try:
        rows = connection.execute(
            f"""
            SELECT * FROM incidents
            {where_clause}
            ORDER BY
                CASE severity
                    WHEN 'Critical' THEN 0
                    WHEN 'High' THEN 1
                    WHEN 'Medium' THEN 2
                    ELSE 3
                END,
                updated_at DESC
            LIMIT ?
            """,
            (*parameters, limit),
        ).fetchall()
        return {"count": len(rows), "incidents": [_serialize_incident(row) for row in rows]}
    finally:
        connection.close()


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    _refresh_incidents()
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        incident = _serialize_incident(row)
        evidence_by_id = {}
        evidence_ids = incident["evidence_event_ids"]
        for offset in range(0, len(evidence_ids), 500):
            batch = evidence_ids[offset:offset + 500]
            placeholders = ",".join("?" for _ in batch)
            evidence_rows = connection.execute(
                f"""
                SELECT event_id, event_type, username, source_ip, details, received_at
                FROM security_events
                WHERE event_id IN ({placeholders})
                """,
                batch,
            ).fetchall()
            evidence_by_id.update(
                (event["event_id"], dict(event)) for event in evidence_rows
            )
        incident["evidence"] = [
            evidence_by_id[event_id]
            for event_id in evidence_ids
            if event_id in evidence_by_id
        ]
        history = connection.execute(
            """
            SELECT previous_status, new_status, changed_at, note
            FROM incident_history
            WHERE incident_id = ?
            ORDER BY changed_at ASC, history_id ASC
            """,
            (incident_id,),
        ).fetchall()
        incident["history"] = [dict(entry) for entry in history]
        return incident
    finally:
        connection.close()


@app.patch("/incidents/{incident_id}")
def update_incident_status(incident_id: str, update: IncidentStatusUpdate):
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT status FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        previous_status = row["status"]
        if previous_status != update.status:
            changed_at = datetime.now(timezone.utc).isoformat()
            connection.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
                (update.status, changed_at, incident_id),
            )
            connection.execute(
                """
                INSERT INTO incident_history (
                    incident_id, previous_status, new_status, changed_at, note
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (incident_id, previous_status, update.status, changed_at, update.note),
            )
            connection.commit()
    finally:
        connection.close()
    return get_incident(incident_id)


@app.get("/dashboard/summary")
def dashboard_summary():
    _refresh_incidents()
    connection = get_connection()
    try:
        total_events = connection.execute(
            "SELECT COUNT(*) AS count FROM security_events"
        ).fetchone()["count"]
        active_incidents = connection.execute(
            "SELECT COUNT(*) AS count FROM incidents WHERE status != 'Resolved'"
        ).fetchone()["count"]
        critical_threats = connection.execute(
            """
            SELECT COUNT(*) AS count FROM incidents
            WHERE severity = 'Critical' AND status != 'Resolved'
            """
        ).fetchone()["count"]
        distribution = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity"
        ).fetchall()
        recent_events = connection.execute(
            """
            SELECT event_id, event_type, username, source_ip, details, received_at
            FROM security_events ORDER BY received_at DESC, id DESC LIMIT 8
            """
        ).fetchall()
        return {
            "total_events": total_events,
            "active_incidents": active_incidents,
            "critical_threats": critical_threats,
            "severity_distribution": {
                severity: next((row["count"] for row in distribution if row["severity"] == severity), 0)
                for severity in ("Low", "Medium", "High", "Critical")
            },
            "recent_events": [dict(row) for row in recent_events],
        }
    finally:
        connection.close()


@app.post("/simulation/run", status_code=201)
def run_simulation(request: SimulationRequest):
    if os.getenv("SENTINEL_SIMULATION_ENABLED", "true").strip().lower() not in {
        "1", "true", "yes", "on",
    }:
        raise HTTPException(status_code=403, detail="The local attack simulation is disabled.")

    scenarios = {
        "brute_force": [
            ("login_failed", "Simulated failed login attempt 1"),
            ("login_failed", "Simulated failed login attempt 2"),
            ("login_failed", "Simulated failed login attempt 3"),
        ],
        "account_compromise": [
            ("login_failed", "Simulated failed login attempt 1"),
            ("login_failed", "Simulated failed login attempt 2"),
            ("login_failed", "Simulated failed login attempt 3"),
            ("login_success", "Simulated successful login after repeated failures"),
        ],
        "privilege_escalation": [
            ("privilege_change", "Simulated privilege escalation"),
        ],
        "data_transfer": [
            ("outbound_transfer", "Simulated suspicious outbound transfer: 250 MB"),
        ],
        "full_attack_chain": [
            ("login_failed", "Simulated failed login attempt 1"),
            ("login_failed", "Simulated failed login attempt 2"),
            ("login_failed", "Simulated failed login attempt 3"),
            ("login_success", "Simulated successful login after repeated failures"),
            ("privilege_change", "Simulated privilege escalation"),
            ("outbound_transfer", "Simulated suspicious outbound transfer: 250 MB"),
        ],
    }
    username = f"simulation_{request.scenario}"
    events = [
        _insert_event(SecurityEvent(
            event_type=event_type,
            username=username,
            source_ip="192.0.2.50",
            details=details,
        ))
        for event_type, details in scenarios[request.scenario]
    ]
    incidents_created = _refresh_incidents()
    event_ids = {event["event_id"] for event in events}
    matching = [
        chain for chain in correlate_attack_chains(_read_events())
        if chain["username"] == username
        and chain["source_ip"] == "192.0.2.50"
        and set(chain["evidence_event_ids"]) == event_ids
    ]
    detections = [
        detection for detection in detect_threats(events)
        if set(detection["evidence_event_ids"]) <= event_ids
    ]
    return {
        "message": "Synthetic local simulation completed.",
        "scenario": request.scenario,
        "event_count": len(events),
        "event_ids": [event["event_id"] for event in events],
        "detections": detections,
        "attack_chains": matching,
        "incidents_created": incidents_created,
    }


app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).resolve().parent.parent / "frontend"),
    name="static",
)
