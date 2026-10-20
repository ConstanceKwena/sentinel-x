
from datetime import datetime, timedelta, timezone

from backend.detection import detect_brute_force_followed_by_success


def make_event(event_id, event_type, minutes_after_start):
    start = datetime(2026, 10, 20, 10, 0, tzinfo=timezone.utc)

    return {
        "event_id": event_id,
        "event_type": event_type,
        "username": "simulation_user",
        "source_ip": "192.0.2.50",
        "received_at": (
            start + timedelta(minutes=minutes_after_start)
        ).isoformat(),
    }


def test_detects_failed_logins_followed_by_success():
    events = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_failed", 2),
        make_event("e4", "login_success", 3),
    ]

    alerts = detect_brute_force_followed_by_success(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-001"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["failed_attempts"] == 3
    assert alerts[0]["evidence_event_ids"] == ["e1", "e2", "e3"]


def test_does_not_alert_for_too_few_failures():
    events = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_success", 2),
    ]

    alerts = detect_brute_force_followed_by_success(events)

    assert alerts == []


def test_does_not_match_different_source_ips():
    events = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_failed", 2),
        {
            **make_event("e4", "login_success", 3),
            "source_ip": "192.0.2.99",
        },
    ]

    alerts = detect_brute_force_followed_by_success(events)

    assert alerts == []


def test_does_not_alert_when_failures_are_outside_window():
    events = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_failed", 2),
        make_event("e4", "login_success", 20),
    ]

    alerts = detect_brute_force_followed_by_success(events)

    assert alerts == []
