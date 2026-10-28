"""Separate demo login app that reports activity to Sentinel-X."""

from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
from ipaddress import ip_address
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Request as IncomingRequest
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator


DEMO_ACCOUNTS = {"demo-user": "demo-password"}
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
app = FastAPI(title="Sentinel-X Demo Login", version="1.0.0")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("username must not be blank")
        return normalized


def _sentinel_request(path: str, method: str = "GET", payload: dict | None = None) -> dict:
    base_url = os.getenv("SENTINEL_API_URL", "http://127.0.0.1:8000").rstrip("/")
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    key = os.getenv("SENTINEL_INGEST_API_KEY")
    if key:
        headers["X-Sentinel-Key"] = key
    if method == "POST":
        headers["X-Sentinel-Application"] = "demo-login-app"
    request = Request(f"{base_url}{path}", data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise HTTPException(
            status_code=502,
            detail=f"Sentinel-X rejected the request (HTTP {error.code}).",
        ) from error
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=503,
            detail="Sentinel-X could not be reached; the demo login was not completed.",
        ) from error


@app.get("/", include_in_schema=False)
def demo_login_page():
    return FileResponse(FRONTEND / "demo_login.html")


@app.get("/demo.css", include_in_schema=False)
def demo_login_stylesheet():
    return FileResponse(FRONTEND / "demo.css")


@app.get("/demo.js", include_in_schema=False)
def demo_login_script():
    return FileResponse(FRONTEND / "demo.js")


@app.post("/login")
def login(credentials: LoginRequest, request: IncomingRequest):
    if request.client is None:
        raise HTTPException(status_code=400, detail="Client address is unavailable.")
    try:
        source_ip = str(ip_address(request.client.host))
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Client address is invalid.") from error
    try:
        query = urlencode({"source_ip": source_ip})
        block_status = _sentinel_request(
            f"/response/blocks/check?{query}"
        )
    except HTTPException:
        raise
    if block_status["blocked"]:
        raise HTTPException(status_code=429, detail="Login temporarily blocked for this source.")

    expected_password = DEMO_ACCOUNTS.get(credentials.username)
    authenticated = expected_password is not None and hmac.compare_digest(
        credentials.password, expected_password
    )
    event_type = "login_success" if authenticated else "login_failed"
    _sentinel_request(
        "/events",
        method="POST",
        payload={
            "event_type": event_type,
            "username": credentials.username,
            "source_ip": source_ip,
            "details": "Demo application login succeeded"
            if authenticated
            else "Invalid credentials",
        },
    )
    if not authenticated:
        return {"authenticated": False, "message": "Invalid username or password."}
    return {"authenticated": True, "message": "Demo login successful."}
