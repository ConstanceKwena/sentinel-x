import pytest
from fastapi.testclient import TestClient

import backend.database as database
from backend.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Keep test data separate from the real project database.
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test_sentinel_x.db",
    )

    database.initialize_database()

    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_ingest_valid_security_event(client):
    payload = {
        "event_type": "login_failed",
        "username": "test_user",
        "source_ip": "192.0.2.10",
        "details": "Test failed login",
    }

    response = client.post("/events", json=payload)

    assert response.status_code == 201

    result = response.json()
    assert result["event"]["event_type"] == "login_failed"
    assert result["event"]["username"] == "test_user"
    assert result["event"]["source_ip"] == "192.0.2.10"
    assert result["event_id"]


def test_ingest_rejects_invalid_event_type(client):
    payload = {
        "event_type": "unknown_event",
        "username": "test_user",
        "source_ip": "192.0.2.10",
    }

    response = client.post("/events", json=payload)

    assert response.status_code == 422


def test_ingest_rejects_invalid_ip(client):
    payload = {
        "event_type": "login_failed",
        "username": "test_user",
        "source_ip": "not-an-ip",
    }

    response = client.post("/events", json=payload)

    assert response.status_code == 422


def test_retrieved_events_include_saved_event(client):
    payload = {
        "event_type": "privilege_change",
        "username": "admin_test",
        "source_ip": "192.0.2.20",
        "details": "Test privilege change",
    }

    create_response = client.post("/events", json=payload)
    assert create_response.status_code == 201

    response = client.get("/events")

    assert response.status_code == 200
    result = response.json()
    assert result["count"] == 1
    assert result["events"][0]["event_type"] == "privilege_change"
    assert result["events"][0]["username"] == "admin_test"

def test_events_can_be_filtered_by_event_type(client):
    client.post(
        "/events",
        json={
            "event_type": "login_failed",
            "username": "alice",
            "source_ip": "192.0.2.10",
        },
    )

    client.post(
        "/events",
        json={
            "event_type": "login_success",
            "username": "bob",
            "source_ip": "192.0.2.20",
        },
    )

    response = client.get("/events?event_type=login_failed")

    assert response.status_code == 200

    result = response.json()
    assert result["count"] == 1
    assert result["events"][0]["event_type"] == "login_failed"
def test_events_can_be_filtered_by_username(client):
    client.post(
        "/events",
        json={
            "event_type": "login_failed",
            "username": "alice",
            "source_ip": "192.0.2.10",
        },
    )

    client.post(
        "/events",
        json={
            "event_type": "login_success",
            "username": "bob",
            "source_ip": "192.0.2.20",
        },
    )

    response = client.get("/events?username=alice")

    assert response.status_code == 200
    result = response.json()
    assert result["count"] == 1
    assert result["events"][0]["username"] == "alice"


def test_events_can_be_filtered_by_source_ip(client):
    client.post(
        "/events",
        json={
            "event_type": "login_failed",
            "username": "alice",
            "source_ip": "192.0.2.10",
        },
    )

    client.post(
        "/events",
        json={
            "event_type": "login_success",
            "username": "bob",
            "source_ip": "192.0.2.20",
        },
    )

    response = client.get("/events?source_ip=192.0.2.10")

    assert response.status_code == 200
    result = response.json()
    assert result["count"] == 1
    assert result["events"][0]["source_ip"] == "192.0.2.10"


def test_events_can_be_limited(client):
    for username, ip in [
        ("alice", "192.0.2.10"),
        ("bob", "192.0.2.20"),
        ("charlie", "192.0.2.30"),
    ]:
        client.post(
            "/events",
            json={
                "event_type": "login_failed",
                "username": username,
                "source_ip": ip,
            },
        )

    response = client.get("/events?limit=2")

    assert response.status_code == 200
    result = response.json()
    assert result["count"] == 2
    assert len(result["events"]) == 2
