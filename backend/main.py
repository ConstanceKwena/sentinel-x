from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

from backend.database import get_connection, initialize_database
from backend.detection import correlate_attack_chains, detect_threats
from backend.response import (
    active_blocks,
    evaluate_failed_login,
    list_applications,
    policy_status,
    record_application,
    remove_block,
    response_history,
    source_is_blocked,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    policy_status()
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


def _read_events(
    source_origin: str | None = None,
    source_application: str | None = None,
) -> list[dict]:
    connection = get_connection()
    try:
        conditions = []
        parameters: list[object] = []
        if source_origin is not None:
            conditions.append("source_origin = ?")
            parameters.append(source_origin)
        if source_application is not None:
            conditions.append("source_application = ?")
            parameters.append(source_application)
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = connection.execute(
            f"""
            SELECT event_id, event_type, username, source_ip, details, received_at,
                   source_origin, source_application
            FROM security_events
            {where_clause}
            ORDER BY received_at ASC, id ASC
            """,
            parameters,
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
    event_groups: dict[tuple[str, str | None], list[dict]] = {}
    for event in events:
        key = (event.get("source_origin", "unknown"), event.get("source_application"))
        event_groups.setdefault(key, []).append(event)

    connection = get_connection()
    created_count = 0
    try:
        now = datetime.now(timezone.utc).isoformat()
        for (source_origin, source_application), group in event_groups.items():
            chains = {
                chain["chain_id"]: chain
                for chain in correlate_attack_chains(group)
            }
            for detection in detect_threats(group):
                evidence_ids = detection["evidence_event_ids"]
                evidence_by_id = {
                    event["event_id"]: event for event in group
                }
                evidence = [
                    evidence_by_id[event_id]
                    for event_id in evidence_ids
                    if event_id in evidence_by_id
                ]
                detection["source_origin"] = source_origin
                detection["source_application"] = source_application
                fingerprint = hashlib.sha256(
                    (
                        source_origin + ":" + str(source_application) + ":"
                        + detection["rule_id"] + ":" + ":".join(evidence_ids)
                    ).encode("utf-8")
                ).hexdigest()
                chain = chains.get(detection.get("chain_id"))
                existing_rows = connection.execute(
                    """
                    SELECT incident_id, evidence_event_ids
                    FROM incidents
                    WHERE source_origin = ? AND source_application IS ?
                      AND rule_id = ? AND source_ip IS ? AND username IS ?
                      AND status != 'Resolved'
                    ORDER BY updated_at DESC
                    """,
                    (
                        source_origin,
                        source_application,
                        detection["rule_id"],
                        detection.get("source_ip"),
                        detection.get("username"),
                    ),
                ).fetchall()
                current_evidence = set(evidence_ids)
                existing_incident = next(
                    (
                        row for row in existing_rows
                        if current_evidence.intersection(
                            json.loads(row["evidence_event_ids"])
                        )
                    ),
                    None,
                )
                if existing_incident is not None:
                    old_evidence_ids = json.loads(
                        existing_incident["evidence_event_ids"]
                    )
                    merged_evidence_ids = list(dict.fromkeys(
                        old_evidence_ids + evidence_ids
                    ))
                    if merged_evidence_ids != old_evidence_ids:
                        connection.execute(
                            """
                            UPDATE incidents
                            SET title = ?, description = ?, severity = ?, risk_score = ?,
                                evidence_event_ids = ?, explanation = ?,
                                recommended_actions = ?, attack_chain = ?, updated_at = ?
                            WHERE incident_id = ?
                            """,
                            (
                                detection["description"],
                                detection["description"],
                                _risk_severity(detection["severity"]),
                                max(0, min(100, int(detection["risk_score"]))),
                                json.dumps(merged_evidence_ids),
                                detection["explanation"],
                                json.dumps(detection["recommended_actions"]),
                                json.dumps(chain) if chain else None,
                                now,
                                existing_incident["incident_id"],
                            ),
                        )
                    continue

                incident_id = f"INC-{uuid4().hex.upper()}"
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO incidents (
                        incident_id, fingerprint, title, description, severity, risk_score,
                        evidence_event_ids, explanation, recommended_actions, attack_chain,
                        source_origin, source_application, source_ip, username, rule_id,
                        status, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
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
                        source_origin,
                        source_application,
                        detection.get("source_ip"),
                        detection.get("username"),
                        detection["rule_id"],
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


def _insert_event(
    event: SecurityEvent,
    source_origin: str = "unknown",
    source_application: str | None = None,
) -> dict:
    event_id = str(uuid4())
    received_at = datetime.now(timezone.utc).isoformat()
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO security_events (
                event_id, event_type, username, source_ip, details, received_at,
                source_origin, source_application
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event.event_type,
                event.username,
                str(event.source_ip),
                event.details,
                received_at,
                source_origin,
                source_application,
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
        "source_origin": source_origin,
        "source_application": source_application,
    }


def _events_by_origin(
    source_origin: str | None,
    source_application: str | None = None,
) -> list[dict]:
    if source_origin == "all":
        source_origin = None
    return _read_events(source_origin, source_application)


def _event_description(event: dict) -> str:
    username = event["username"]
    source_ip = event["source_ip"]
    if event["event_type"] == "login_failed":
        return f"Failed login attempt for {username} from {source_ip}."
    if event["event_type"] == "login_success":
        return f"Successful login for {username} from {source_ip}."
    return f"{event['event_type'].replace('_', ' ').capitalize()} for {username} from {source_ip}."


def _event_annotations(events: list[dict], context: list[dict]) -> list[dict]:
    detections = detect_threats(context)
    detections_by_event: dict[str, list[dict]] = {}
    for detection in detections:
        evidence_ids = detection["evidence_event_ids"]
        for event_id in evidence_ids:
            detections_by_event.setdefault(event_id, []).append(detection)

    active_ip_set = {
        block["source_ip"]
        for block in active_blocks("connected_application")
    }
    connection = get_connection()
    try:
        incidents = connection.execute(
            """
            SELECT incident_id, source_origin, source_application, rule_id,
                   severity, risk_score, status, evidence_event_ids
            FROM incidents
            """
        ).fetchall()
        incident_by_event: dict[str, list[dict]] = {}
        for row in incidents:
            incident = dict(row)
            for event_id in json.loads(incident["evidence_event_ids"]):
                incident_by_event.setdefault(event_id, []).append({
                    key: value for key, value in incident.items()
                    if key != "evidence_event_ids"
                })

        actions_by_ip: dict[str, list[dict]] = {}
        for row in connection.execute(
            """
            SELECT source_ip, action, occurred_at, expires_at, reason,
                   source_origin, source_application
            FROM response_actions ORDER BY action_id DESC
            """
        ).fetchall():
            action = dict(row)
            action_key = (
                action["source_ip"],
                action["source_origin"],
                action["source_application"],
            )
            actions_by_ip.setdefault(action_key, []).append(action)

        annotated = []
        for event in events:
            event_detections = detections_by_event.get(event["event_id"], [])
            event_incidents = incident_by_event.get(event["event_id"], [])
            event_actions = actions_by_ip.get(
                (
                    event["source_ip"],
                    event.get("source_origin", "unknown"),
                    event.get("source_application"),
                ),
                [],
            )
            result = {
                **event,
                "description": _event_description(event),
                "outcome": (
                    "failed" if event["event_type"] == "login_failed"
                    else "successful" if event["event_type"] == "login_success"
                    else None
                ),
                "detections": [
                    {
                        "rule_id": detection["rule_id"],
                        "explanation": detection["explanation"],
                        "risk_score": detection["risk_score"],
                        "severity": detection["severity"],
                    }
                    for detection in event_detections
                ],
                "incidents": event_incidents,
                "response_actions": event_actions,
                "currently_blocked": event["source_ip"] in active_ip_set,
            }
            if event["event_type"] == "login_failed" and event["details"]:
                result["failure_reason"] = event["details"]
            annotated.append(result)
        return annotated
    finally:
        connection.close()


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
def ingest_event(
    event: SecurityEvent,
    sentinel_key: str | None = Header(default=None, alias="X-Sentinel-Key"),
    application_id: str | None = Header(default=None, alias="X-Sentinel-Application"),
):
    configured_key = os.getenv("SENTINEL_INGEST_API_KEY")
    if configured_key and (
        sentinel_key is None or not hmac.compare_digest(sentinel_key, configured_key)
    ):
        raise HTTPException(status_code=401, detail="A valid event-ingestion key is required.")
    if application_id is not None and not configured_key:
        raise HTTPException(
            status_code=503,
            detail="Connected-application provenance requires configured ingestion authentication.",
        )
    if application_id is not None and not re.fullmatch(
        r"[A-Za-z0-9._-]{1,64}", application_id
    ):
        raise HTTPException(
            status_code=422, detail="Invalid connected application identifier."
        )

    source_origin = "connected_application" if application_id else "unknown"
    saved_event = _insert_event(
        event,
        source_origin=source_origin,
        source_application=application_id,
    )
    if application_id is not None:
        record_application(application_id)
    events = _read_events(source_origin, application_id)
    _refresh_incidents(events)
    block = (
        evaluate_failed_login(
            saved_event["source_ip"],
            source_application=application_id,
        )
        if event.event_type == "login_failed" and application_id
        else None
    )
    return {
        "message": "Security event saved successfully.",
        "event_id": saved_event["event_id"],
        "received_at": saved_event["received_at"],
        "event": {key: value for key, value in saved_event.items() if key != "event_id"},
        "response": {"block": block},
    }


@app.get("/connected-applications")
def get_connected_applications():
    return {"applications": list_applications()}


@app.get("/response/blocks")
def get_response_blocks():
    blocks = active_blocks()
    return {"count": len(blocks), "blocks": blocks}


@app.get("/response/blocks/check")
def check_response_block(source_ip: IPvAnyAddress):
    return {"blocked": source_is_blocked(str(source_ip))}


@app.get("/response/history")
def get_response_history(limit: int = Query(default=50, ge=1, le=200)):
    actions = response_history(limit)
    return {"count": len(actions), "actions": actions}


@app.delete("/response/blocks/{source_ip}")
def manually_remove_response_block(
    source_ip: str,
    admin_key: str | None = Header(default=None, alias="X-Sentinel-Admin-Key"),
):
    configured_key = os.getenv("SENTINEL_ADMIN_API_KEY")
    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="Administrator block management is not configured.",
        )
    if admin_key is None or not hmac.compare_digest(admin_key, configured_key):
        raise HTTPException(status_code=401, detail="A valid administrator key is required.")
    try:
        normalized_ip = str(IPvAnyAddress(source_ip))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="Invalid source IP address.") from error
    if not remove_block(normalized_ip, actor="administrator"):
        raise HTTPException(status_code=404, detail="No active block exists for this source.")
    return {"message": "The active source block was removed.", "source_ip": normalized_ip}


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
    offset: int = Query(default=0, ge=0),
    source_origin: Literal[
        "connected_application", "simulation", "unknown", "all"
    ] | None = None,
    source_application: str | None = Query(default=None, min_length=1, max_length=64),
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
    if source_origin not in (None, "all"):
        conditions.append("source_origin = ?")
        parameters.append(source_origin)
    if source_application is not None:
        conditions.append("source_application = ?")
        parameters.append(source_application)
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    connection = get_connection()
    try:
        rows = connection.execute(
            f"""
            SELECT event_id, event_type, username, source_ip, details, received_at,
                   source_origin, source_application
            FROM security_events
            {where_clause}
            ORDER BY received_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (*parameters, limit, offset),
        ).fetchall()
        events = [dict(row) for row in rows]
    finally:
        connection.close()
    context = _events_by_origin(
        source_origin,
        source_application,
    )
    return {
        "count": len(events),
        "offset": offset,
        "events": _event_annotations(events, context),
    }


@app.get("/events/{event_id}")
def get_event_details(event_id: str):
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM security_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Security event not found.")
        event = dict(row)
    finally:
        connection.close()

    context = _read_events(event["source_origin"], event["source_application"])
    annotated = _event_annotations([event], context)[0]
    related = [
        item for item in context
        if item["source_ip"] == event["source_ip"]
        and item["event_type"] in {"login_failed", "login_success"}
    ]
    annotated["related_authentication_events"] = _event_annotations(related, context)
    return annotated


@app.get("/detections")
def get_detections(
    source_origin: Literal[
        "connected_application", "simulation", "unknown", "all"
    ] = "all",
    source_application: str | None = Query(default=None, min_length=1, max_length=64),
):
    events = _events_by_origin(source_origin, source_application)
    detections = []
    groups: dict[tuple[str, str | None], list[dict]] = {}
    for event in events:
        key = (event["source_origin"], event["source_application"])
        groups.setdefault(key, []).append(event)
    for (origin, application), group in groups.items():
        for detection in detect_threats(group):
            detection["source_origin"] = origin
            detection["source_application"] = application
            detections.append(detection)
    return {"count": len(detections), "detections": detections}


@app.get("/attack-chains")
def get_attack_chains(
    source_origin: Literal[
        "connected_application", "simulation", "unknown", "all"
    ] = "all",
    source_application: str | None = Query(default=None, min_length=1, max_length=64),
):
    events = _events_by_origin(source_origin, source_application)
    groups: dict[tuple[str, str | None], list[dict]] = {}
    for event in events:
        key = (event["source_origin"], event["source_application"])
        groups.setdefault(key, []).append(event)
    chains = [
        chain
        for group in groups.values()
        for chain in correlate_attack_chains(group)
    ]
    return {"chains": chains}


@app.get("/incidents")
def get_incidents(
    status: Literal["Open", "Investigating", "Resolved"] | None = None,
    severity: Literal["Low", "Medium", "High", "Critical"] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    source_origin: Literal[
        "connected_application", "simulation", "unknown", "all"
    ] = "all",
    source_application: str | None = Query(default=None, min_length=1, max_length=64),
):
    filters = []
    parameters: list[object] = []
    if source_origin != "all":
        filters.append("source_origin = ?")
        parameters.append(source_origin)
    if source_application is not None:
        filters.append("source_application = ?")
        parameters.append(source_application)
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
def dashboard_summary(
    source_origin: Literal[
        "connected_application", "simulation", "unknown", "all"
    ] = "all",
    source_application: str | None = Query(default=None, min_length=1, max_length=64),
):
    events = _events_by_origin(source_origin, source_application)
    event_ids = {event["event_id"] for event in events}
    event_source_origin = None if source_origin == "all" else source_origin
    recent_events = sorted(
        events, key=lambda event: event["received_at"], reverse=True
    )[:8]
    detection_groups: dict[tuple[str, str | None], list[dict]] = {}
    for event in events:
        detection_groups.setdefault(
            (event["source_origin"], event["source_application"]), []
        ).append(event)
    detections = [
        {**detection, "source_origin": origin, "source_application": application}
        for (origin, application), group in detection_groups.items()
        for detection in detect_threats(group)
    ]
    latest_detections = sorted(
        detections,
        key=lambda detection: detection["detected_at"],
        reverse=True,
    )[:8]
    connection = get_connection()
    try:
        incident_conditions = []
        incident_parameters: list[object] = []
        if event_source_origin is not None:
            incident_conditions.append("source_origin = ?")
            incident_parameters.append(event_source_origin)
        if source_application is not None:
            incident_conditions.append("source_application = ?")
            incident_parameters.append(source_application)
        incident_where = (
            f"WHERE {' AND '.join(incident_conditions)}"
            if incident_conditions
            else ""
        )
        incidents = connection.execute(
            f"""
            SELECT incident_id, severity, risk_score, status, evidence_event_ids,
                   source_origin, source_application, rule_id, source_ip, username
            FROM incidents {incident_where}
            """,
            incident_parameters,
        ).fetchall()
        visible_incidents = []
        for row in incidents:
            incident = dict(row)
            evidence_ids = set(json.loads(incident["evidence_event_ids"]))
            if evidence_ids & event_ids:
                visible_incidents.append(incident)
    finally:
        connection.close()

    severity_counts = {
        severity: sum(
            incident["severity"] == severity for incident in visible_incidents
        )
        for severity in ("Low", "Medium", "High", "Critical")
    }
    active_incidents = [
        incident for incident in visible_incidents
        if incident["status"] != "Resolved"
    ]
    critical_active = sum(
        incident["severity"] == "Critical" for incident in active_incidents
    )
    selected_origin = None if source_origin == "all" else source_origin
    return {
        "total_events": len(events),
        "failed_logins": sum(event["event_type"] == "login_failed" for event in events),
        "successful_logins": sum(event["event_type"] == "login_success" for event in events),
        "incident_count": len(visible_incidents),
        "active_incidents": len(active_incidents),
        "critical_threats": critical_active,
        "severity_distribution": severity_counts,
        "recent_events": _event_annotations(recent_events, events),
        "recent_detections": latest_detections,
        "detection_count": len(detections),
        "connected_applications": list_applications(),
        "active_blocks": active_blocks(selected_origin, source_application),
        "response_history": response_history(
            10, selected_origin, source_application
        ),
        "response_policy": policy_status(),
        "source_origin": source_origin,
        "source_application": source_application,
    }


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
        ), source_origin="simulation")
        for event_type, details in scenarios[request.scenario]
    ]
    incidents_created = _refresh_incidents(events)
    event_ids = {event["event_id"] for event in events}
    matching = [
        chain for chain in correlate_attack_chains(events)
        if chain["username"] == username
        and chain["source_ip"] == "192.0.2.50"
        and set(chain["evidence_event_ids"]) == event_ids
    ]
    detections = [
        {
            **detection,
            "source_origin": "simulation",
            "source_application": None,
        }
        for detection in detect_threats(events)
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
