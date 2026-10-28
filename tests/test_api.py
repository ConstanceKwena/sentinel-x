from datetime import datetime, timedelta, timezone
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

import backend.database as database
import backend.demo_login as demo_login
import backend.response as response_policy
from backend.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Keep test data separate from the real project database.
    monkeypatch.delenv("SENTINEL_INGEST_API_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_ADMIN_API_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_AUTO_BLOCK_ENABLED", raising=False)
    monkeypatch.delenv("SENTINEL_RESPONSE_FAILED_LOGIN_THRESHOLD", raising=False)
    monkeypatch.delenv("SENTINEL_RESPONSE_BLOCK_MINUTES", raising=False)
    monkeypatch.delenv("SENTINEL_RESPONSE_WINDOW_MINUTES", raising=False)
    monkeypatch.delenv("SENTINEL_RESPONSE_MINIMUM_ACCOUNTS", raising=False)
    monkeypatch.delenv("SENTINEL_RESPONSE_TRUSTED_IPS", raising=False)
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test_sentinel_x.db",
    )

    database.initialize_database()

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def demo_client(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_INGEST_API_KEY", "demo-app-test-key")

    def send_to_sentinel(path, method="GET", payload=None):
        if path.startswith("/response/blocks/check?"):
            source_ip = path.split("source_ip=", 1)[1]
            return client.get("/response/blocks/check", params={"source_ip": source_ip}).json()
        headers = {"X-Sentinel-Application": "demo-login-app"}
        key = os.getenv("SENTINEL_INGEST_API_KEY")
        if key:
            headers["X-Sentinel-Key"] = key
        return client.request(method, path, json=payload, headers=headers).json()

    monkeypatch.setattr(demo_login, "_sentinel_request", send_to_sentinel)
    with TestClient(demo_login.app, client=("192.0.2.77", 43123)) as test_client:
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


def test_connected_application_events_use_existing_event_pipeline(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_INGEST_API_KEY", "connected-app-test-key")
    response = client.post(
        "/events",
        headers={
            "X-Sentinel-Application": "external-login",
            "X-Sentinel-Key": "connected-app-test-key",
        },
        json={
            "event_type": "login_success",
            "username": "external_user",
            "source_ip": "192.0.2.33",
            "details": "External login succeeded",
        },
    )

    assert response.status_code == 201
    event = response.json()["event"]
    received_at = datetime.fromisoformat(event["received_at"])
    assert received_at.tzinfo is not None
    assert received_at.utcoffset() == timezone.utc.utcoffset(received_at)
    assert response.json()["received_at"] == event["received_at"]
    assert event["source_ip"] == "192.0.2.33"
    assert client.get("/events?username=external_user").json()["events"][0]["event_id"] == response.json()["event_id"]
    application = client.get("/connected-applications").json()["applications"][0]
    assert application["application_id"] == "external-login"
    assert application["status"] == "connected"


def test_empty_connected_application_dashboard_is_zero_and_read_only(client):
    summary = client.get(
        "/dashboard/summary?source_origin=connected_application"
    ).json()

    assert summary["total_events"] == 0
    assert summary["failed_logins"] == 0
    assert summary["successful_logins"] == 0
    assert summary["active_incidents"] == 0
    assert summary["critical_threats"] == 0
    assert summary["detection_count"] == 0
    assert summary["active_blocks"] == []
    assert client.get("/incidents?source_origin=connected_application").json()["count"] == 0


def test_demo_success_and_failed_logins_are_saved_with_provenance(
    client, demo_client
):
    success = demo_client.post(
        "/login", json={"username": "demo-user", "password": "demo-password"}
    )
    failure = demo_client.post(
        "/login", json={"username": "demo-user", "password": "incorrect"}
    )

    assert success.json()["authenticated"] is True
    assert failure.json()["authenticated"] is False
    events = client.get(
        "/events?source_origin=connected_application&source_application=demo-login-app"
    ).json()["events"]
    assert [event["event_type"] for event in events] == [
        "login_failed",
        "login_success",
    ]
    assert all(event["received_at"] for event in events)
    assert all(event["source_ip"] == "192.0.2.77" for event in events)
    assert all(event["source_origin"] == "connected_application" for event in events)
    assert all(event["source_application"] == "demo-login-app" for event in events)
    failed_event = events[0]
    assert failed_event["failure_reason"] == "Invalid credentials"
    assert "demo-password" not in repr(events)
    assert "SENTINEL_INGEST_API_KEY" not in repr(events)


def test_simulation_events_and_incidents_are_separate_from_connected_activity(client):
    simulation = client.post(
        "/simulation/run", json={"scenario": "account_compromise"}
    )

    assert simulation.status_code == 201
    simulation_events = client.get(
        "/events?source_origin=simulation"
    ).json()["events"]
    assert len(simulation_events) == 4
    assert all(event["source_origin"] == "simulation" for event in simulation_events)
    connected = client.get(
        "/dashboard/summary?source_origin=connected_application"
    ).json()
    assert connected["total_events"] == 0
    assert connected["active_incidents"] == 0
    assert connected["active_blocks"] == []
    simulated = client.get(
        "/dashboard/summary?source_origin=simulation"
    ).json()
    assert simulated["total_events"] == 4
    assert simulated["active_incidents"] > 0
    assert simulated["active_blocks"] == []


def test_dashboard_reads_do_not_create_incidents(client):
    connection = database.get_connection()
    try:
        connection.execute(
            """
            INSERT INTO security_events(
                event_id, event_type, username, source_ip, details, received_at,
                source_origin, source_application
            ) VALUES (?, 'login_failed', ?, ?, NULL, ?, 'connected_application', ?)
            """,
            (
                "read-only-dashboard-event",
                "dashboard-user",
                "192.0.2.84",
                datetime.now(timezone.utc).isoformat(),
                "dashboard-test-app",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    assert client.get(
        "/dashboard/summary?source_origin=connected_application"
    ).json()["total_events"] == 1
    assert client.get(
        "/incidents?source_origin=connected_application"
    ).json()["incidents"] == []


def test_unverified_events_keep_unknown_origin(client):
    response = client.post(
        "/events",
        json={
            "event_type": "login_success",
            "username": "legacy-like-user",
            "source_ip": "192.0.2.85",
        },
    )

    assert response.status_code == 201
    assert response.json()["event"]["source_origin"] == "unknown"
    assert client.get(
        "/dashboard/summary?source_origin=connected_application"
    ).json()["total_events"] == 0
    assert client.get(
        "/dashboard/summary?source_origin=unknown"
    ).json()["total_events"] == 1


def test_database_upgrade_preserves_legacy_events_as_unknown(tmp_path, monkeypatch):
    legacy_database = tmp_path / "legacy_sentinel.db"
    connection = sqlite3.connect(legacy_database)
    try:
        connection.execute(
            """
            CREATE TABLE security_events (
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
            INSERT INTO security_events(
                event_id, event_type, username, source_ip, details, received_at
            ) VALUES ('legacy-event', 'login_success', 'legacy-user',
                      '192.0.2.86', NULL, '2026-10-28T08:00:00+00:00')
            """
        )
        connection.commit()
    finally:
        connection.close()

    monkeypatch.setattr(database, "DATABASE_PATH", legacy_database)
    database.initialize_database()
    migrated = database.get_connection()
    try:
        event = migrated.execute(
            "SELECT event_id, source_origin, source_application FROM security_events"
        ).fetchone()
    finally:
        migrated.close()

    assert dict(event) == {
        "event_id": "legacy-event",
        "source_origin": "unknown",
        "source_application": None,
    }


def test_event_ingestion_requires_configured_application_key(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_INGEST_API_KEY", "integration-key")
    payload = {
        "event_type": "login_failed",
        "username": "external_user",
        "source_ip": "192.0.2.34",
    }

    assert client.post("/events", json=payload).status_code == 401
    rejected = client.post("/events", json=payload, headers={"X-Sentinel-Key": "wrong"})
    assert rejected.status_code == 401
    accepted = client.post("/events", json=payload, headers={"X-Sentinel-Key": "integration-key"})
    assert accepted.status_code == 201
    assert client.get("/events?username=external_user").json()["count"] == 1


def test_connected_provenance_requires_configured_ingestion_authentication(
    client, monkeypatch
):
    payload = {
        "event_type": "login_success",
        "username": "claimed_connected_user",
        "source_ip": "192.0.2.35",
    }

    rejected = client.post(
        "/events",
        headers={"X-Sentinel-Application": "unverified-client"},
        json=payload,
    )
    assert rejected.status_code == 503
    assert client.get("/events?username=claimed_connected_user").json()["count"] == 0

def test_demo_application_failed_logins_trigger_and_enforce_temporary_block(
    client, demo_client, monkeypatch
):
    monkeypatch.setenv("SENTINEL_RESPONSE_FAILED_LOGIN_THRESHOLD", "4")
    usernames = ["demo-user", "another-user", "demo-user", "another-user"]
    for username in usernames:
        response = demo_client.post(
            "/login", json={"username": username, "password": "incorrect"}
        )
        assert response.status_code == 200
        assert response.json()["authenticated"] is False

    assert client.get("/events?source_ip=192.0.2.77").json()["count"] == 4
    incidents = client.get(
        "/incidents?source_origin=connected_application"
    ).json()["incidents"]
    assert sum(incident["rule_id"] == "AUTH-002" for incident in incidents) == 1
    blocks = client.get("/response/blocks").json()["blocks"]
    assert len(blocks) == 1
    assert blocks[0]["source_ip"] == "192.0.2.77"
    assert blocks[0]["expires_at"]

    blocked_login = demo_client.post(
        "/login", json={"username": "demo-user", "password": "demo-password"}
    )
    assert blocked_login.status_code == 429
    assert client.get("/events?source_ip=192.0.2.77").json()["count"] == 4
    assert client.get("/dashboard/summary").json()["active_blocks"] == blocks
    history = client.get("/response/history").json()["actions"]
    assert history[0]["action"] == "automatic_block"


def test_response_block_expires_and_login_is_allowed_again(client, demo_client, monkeypatch):
    from datetime import datetime, timezone

    current_time = datetime.now(timezone.utc)
    monkeypatch.setattr(response_policy, "utc_now", lambda: current_time)
    monkeypatch.setenv("SENTINEL_RESPONSE_FAILED_LOGIN_THRESHOLD", "4")
    for username in ["demo-user", "other-user", "demo-user", "other-user"]:
        demo_client.post("/login", json={"username": username, "password": "bad"})

    assert client.get("/response/blocks/check?source_ip=192.0.2.77").json()["blocked"]
    monkeypatch.setattr(
        response_policy,
        "utc_now",
        lambda: current_time + timedelta(minutes=16),
    )
    assert not client.get("/response/blocks/check?source_ip=192.0.2.77").json()["blocked"]
    success = demo_client.post(
        "/login", json={"username": "demo-user", "password": "demo-password"}
    )
    assert success.status_code == 200
    assert success.json()["authenticated"] is True
    actions = client.get("/response/history").json()["actions"]
    assert actions[0]["action"] == "automatic_expiry"


def test_administrator_can_remove_a_block_and_action_is_audited(
    client, demo_client, monkeypatch
):
    monkeypatch.setenv("SENTINEL_RESPONSE_FAILED_LOGIN_THRESHOLD", "4")
    for username in ["demo-user", "other-user", "demo-user", "other-user"]:
        demo_client.post("/login", json={"username": username, "password": "bad"})
    monkeypatch.setenv("SENTINEL_ADMIN_API_KEY", "admin-secret")

    denied = client.delete("/response/blocks/192.0.2.77")
    assert denied.status_code == 401
    removed = client.delete(
        "/response/blocks/192.0.2.77",
        headers={"X-Sentinel-Admin-Key": "admin-secret"},
    )
    assert removed.status_code == 200
    assert client.get("/response/blocks").json()["blocks"] == []
    assert client.get("/response/blocks/check?source_ip=192.0.2.77").json()["blocked"] is False
    actions = client.get("/response/history").json()["actions"]
    assert [action["action"] for action in actions[:2]] == [
        "manual_unblock",
        "automatic_block",
    ]


def test_repeated_failures_for_one_account_do_not_block_legitimate_source(
    client, demo_client, monkeypatch
):
    monkeypatch.setenv("SENTINEL_RESPONSE_FAILED_LOGIN_THRESHOLD", "4")
    for _ in range(6):
        demo_client.post("/login", json={"username": "demo-user", "password": "bad"})

    assert client.get("/response/blocks").json()["blocks"] == []
    login = demo_client.post(
        "/login", json={"username": "demo-user", "password": "demo-password"}
    )
    assert login.status_code == 200
    assert login.json()["authenticated"] is True
    events = client.get("/events?source_ip=192.0.2.77").json()["events"]
    assert len(events) == 7
    assert events[0]["event_type"] == "login_success"


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


def test_ingest_rejects_blank_username(client):
    response = client.post(
        "/events",
        json={
            "event_type": "login_failed",
            "username": "   ",
            "source_ip": "192.0.2.10",
        },
    )

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



def test_detections_endpoint_returns_alert_for_suspicious_login(client):
    from datetime import datetime, timedelta, timezone

    start = datetime(2026, 10, 20, 10, 0, tzinfo=timezone.utc)

    events = [
        ("login_failed", 0),
        ("login_failed", 1),
        ("login_failed", 2),
        ("login_success", 3),
    ]

    for index, (event_type, minutes) in enumerate(events):
        payload = {
            "event_type": event_type,
            "username": "detection_test_user",
            "source_ip": "192.0.2.77",
            "details": "Automated detection test",
        }

        response = client.post("/events", json=payload)
        assert response.status_code == 201

        # The API assigns its own receive timestamp. The sequence is
        # submitted in order, so the detector can evaluate it.
    
    response = client.get("/detections")

    assert response.status_code == 200
    result = response.json()
    assert result["count"] >= 1

    matching_alerts = [
        alert for alert in result["detections"]
        if alert["username"] == "detection_test_user"
        and alert["source_ip"] == "192.0.2.77"
    ]

    assert matching_alerts
    assert matching_alerts[0]["rule_id"] == "AUTH-001"


def test_detections_endpoint_returns_empty_list_without_matching_events(client):
    response = client.get("/detections")

    assert response.status_code == 200
    assert response.json() == {
        "count": 0,
        "detections": [],
    }


def test_incident_creation_status_history_and_risk_score(client):
    result = client.post("/simulation/run", json={})
    assert result.status_code == 201
    assert result.json()["event_count"] == 6

    incidents_response = client.get("/incidents?severity=Critical")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()["incidents"]
    chain_incident = next(incident for incident in incidents if incident["attack_chain"])
    assert chain_incident["risk_score"] == 100
    assert chain_incident["status"] == "Open"
    assert len(chain_incident["evidence_event_ids"]) == 6

    update = client.patch(
        f"/incidents/{chain_incident['incident_id']}",
        json={"status": "Investigating", "note": "Analyst review started"},
    )
    assert update.status_code == 200
    updated = update.json()
    assert updated["status"] == "Investigating"
    assert len(updated["evidence"]) == 6
    assert [entry["new_status"] for entry in updated["history"]] == [
        "Open",
        "Investigating",
    ]
    assert updated["history"][-1]["note"] == "Analyst review started"

    resolved = client.patch(
        f"/incidents/{chain_incident['incident_id']}",
        json={"status": "Resolved"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "Resolved"
    assert client.get(
        f"/incidents/{chain_incident['incident_id']}?unused=true"
    ).json()["history"][-1]["new_status"] == "Resolved"


def test_simulation_generates_correlated_events_and_dashboard_metrics(client):
    response = client.post("/simulation/run", json={})

    assert response.status_code == 201
    result = response.json()
    assert result["event_count"] == 6
    assert result["incidents_created"] >= 1
    assert len(result["attack_chains"]) == 1
    assert len(result["event_ids"]) == 6
    assert result["attack_chains"][0]["stages"] == [
        "Repeated failed authentication",
        "Successful login",
        "Privilege change",
        "Outbound data transfer",
    ]
    assert len(result["attack_chains"][0]["timeline"]) == 6

    summary = client.get("/dashboard/summary")
    assert summary.status_code == 200
    assert summary.json()["total_events"] == 6
    assert summary.json()["critical_threats"] >= 1
    assert client.get("/dashboard").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/app.js").status_code == 200
    assert client.get("/styles.css").status_code == 200


def test_live_server_assets_and_cors_support_frontend_on_port_5500(client):
    response = client.options(
        "/dashboard/summary",
        headers={
            "Origin": "http://127.0.0.1:5500",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5500"
    assert response.headers["access-control-allow-methods"]

    document = client.get("/dashboard").text
    assert './styles.css' in document
    assert './app.js' in document

    script = client.get("/app.js").text
    assert 'pageUrl.port === "5500"' in script
    assert 'pageUrl.port = "8000"' in script


def test_incident_api_reports_missing_and_invalid_requests(client):
    assert client.get("/incidents/INC-not-found").status_code == 404
    assert client.patch(
        "/incidents/INC-not-found",
        json={"status": "Closed"},
    ).status_code == 422
    assert client.patch(
        "/incidents/INC-not-found",
        json={"status": "Resolved"},
    ).status_code == 404
    assert client.get("/events?event_type=made_up").status_code == 422


def test_simulation_can_be_disabled(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_SIMULATION_ENABLED", "false")

    response = client.post("/simulation/run", json={})

    assert response.status_code == 403
    assert response.json()["detail"] == "The local attack simulation is disabled."


@pytest.mark.parametrize(
    ("scenario", "expected_events", "expected_rule"),
    [
        ("brute_force", 3, "AUTH-004"),
        ("account_compromise", 4, "AUTH-001"),
        ("privilege_escalation", 1, "PRIV-001"),
        ("data_transfer", 1, "DATA-001"),
        ("full_attack_chain", 6, "CHAIN-001"),
    ],
)
def test_each_safe_simulation_scenario_creates_incidents_and_detections(
    client,
    scenario,
    expected_events,
    expected_rule,
):
    response = client.post("/simulation/run", json={"scenario": scenario})

    assert response.status_code == 201
    result = response.json()
    assert result["scenario"] == scenario
    assert result["event_count"] == expected_events
    assert result["incidents_created"] >= 1
    assert result["detections"]
    assert expected_rule in {detection["rule_id"] for detection in result["detections"]}

    persisted_events = client.get("/events?limit=10").json()["events"]
    assert len(persisted_events) == expected_events
    assert {event["event_id"] for event in persisted_events} == set(result["event_ids"])


def test_simulation_rejects_unknown_scenario(client):
    response = client.post("/simulation/run", json={"scenario": "real_attack"})

    assert response.status_code == 422
