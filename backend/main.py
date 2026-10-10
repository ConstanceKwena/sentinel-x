
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI
from pydantic import BaseModel, Field, IPvAnyAddress

app = FastAPI(
    title="Sentinel-X",
    description="AI-powered attack-chain detection and security operations platform.",
    version="0.1.0",
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
    return {
        "message": "Security event received successfully.",
        "event_id": str(uuid4()),
        "received_at": datetime.now(timezone.utc),
        "event": event,
    }
