
from datetime import datetime, timedelta, timezone

from backend.detection import (
    DetectionConfig,
    correlate_attack_chains,
    detect_brute_force_followed_by_success,
    detect_threats,
)


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


def test_detects_brute_force_before_success():
    events = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_failed", 2),
    ]

    detections = detect_threats(events)

    brute_force = next(item for item in detections if item["rule_id"] == "AUTH-004")
    assert brute_force["evidence_event_ids"] == ["e1", "e2", "e3"]
    assert brute_force["severity"] == "medium"
    assert "threshold is 3" in brute_force["explanation"]


def test_detects_privilege_change_and_outbound_transfer():
    events = [
        {**make_event("e1", "privilege_change", 0), "details": "Role updated"},
        {**make_event("e2", "outbound_transfer", 1), "details": "Transferred 250 MB"},
    ]

    detections = detect_threats(events)

    assert {item["rule_id"] for item in detections} >= {"PRIV-001", "DATA-001"}
    transfer = next(item for item in detections if item["rule_id"] == "DATA-001")
    assert "250 MB" in transfer["explanation"]


def test_attack_chain_requires_same_account_and_ip_and_ordered_stages():
    events = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_failed", 2),
        make_event("e4", "login_success", 3),
        make_event("e5", "privilege_change", 4),
        make_event("e6", "outbound_transfer", 5),
    ]

    chains = correlate_attack_chains(events)

    assert len(chains) == 1
    assert chains[0]["evidence_event_ids"] == ["e1", "e2", "e3", "e4", "e5", "e6"]
    assert chains[0]["stages"] == [
        "Repeated failed authentication",
        "Successful login",
        "Privilege change",
        "Outbound data transfer",
    ]


def test_attack_chain_does_not_join_different_ips_or_reverse_order():
    unrelated = [
        make_event("e1", "login_failed", 0),
        {**make_event("e2", "login_success", 1), "source_ip": "192.0.2.99"},
        make_event("e3", "privilege_change", 2),
    ]
    reversed_sequence = [
        make_event("e1", "privilege_change", 0),
        make_event("e2", "login_success", 1),
        make_event("e3", "login_failed", 2),
    ]

    assert correlate_attack_chains(unrelated) == []
    assert correlate_attack_chains(reversed_sequence) == []


def test_detection_window_is_configurable():
    events = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_failed", 2),
        make_event("e4", "login_success", 3),
    ]

    detections = detect_threats(
        events,
        DetectionConfig(failed_login_threshold=3, window_minutes=2),
    )

    assert not any(item["rule_id"] == "AUTH-001" for item in detections)


def test_detects_failed_logins_sprayed_across_accounts():
    events = [
        {**make_event("e1", "login_failed", 0), "username": "alice"},
        {**make_event("e2", "login_failed", 1), "username": "bob"},
        {**make_event("e3", "login_failed", 2), "username": "carol"},
    ]

    detections = detect_threats(events)

    spraying = next(item for item in detections if item["rule_id"] == "AUTH-002")
    assert spraying["source_ip"] == "192.0.2.50"
    assert spraying["username"] is None
    assert spraying["evidence_event_ids"] == ["e1", "e2", "e3"]


def test_correlates_multiple_rules_only_inside_the_configured_window():
    related = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_failed", 2),
        make_event("e4", "privilege_change", 3),
    ]
    unrelated_in_time = [
        make_event("e1", "login_failed", 0),
        make_event("e2", "login_failed", 1),
        make_event("e3", "login_failed", 2),
        make_event("e4", "privilege_change", 20),
    ]

    related_detections = detect_threats(related)
    distant_detections = detect_threats(unrelated_in_time)

    aggregate = next(item for item in related_detections if item["rule_id"] == "CORR-001")
    assert aggregate["risk_score"] == 65
    assert aggregate["evidence_event_ids"] == ["e1", "e2", "e3", "e4"]
    assert not any(item["rule_id"] == "CORR-001" for item in distant_detections)
