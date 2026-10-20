
from datetime import datetime, timedelta, timezone


def detect_brute_force_followed_by_success(
    events: list[dict],
    threshold: int = 3,
    window_minutes: int = 10,
) -> list[dict]:
    """
    Detect three or more failed logins followed by a successful login
    for the same username and source IP within a time window.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    ordered_events = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event["received_at"]),
    )

    failed_logins: dict[tuple[str, str], list[dict]] = {}
    alerts = []
    window = timedelta(minutes=window_minutes)

    for event in ordered_events:
        key = (event["username"], event["source_ip"])
        timestamp = datetime.fromisoformat(event["received_at"])

        if event["event_type"] == "login_failed":
            failures = failed_logins.setdefault(key, [])
            failures.append(event)

            # Keep only failed logins within the detection window.
            failed_logins[key] = [
                failure
                for failure in failures
                if timestamp
                - datetime.fromisoformat(failure["received_at"])
                <= window
            ]

        elif event["event_type"] == "login_success":
            failures = [
                failure
                for failure in failed_logins.get(key, [])
                if timedelta(0)
                <= timestamp
                - datetime.fromisoformat(failure["received_at"])
                <= window
            ]

            if len(failures) >= threshold:
                alerts.append(
                    
                    {
                        "rule_id": "AUTH-001",
                        "alert_type": "brute_force_followed_by_success",
                        "severity": "high",
                        "username": event["username"],
                        "source_ip": event["source_ip"],
                        "failed_attempts": len(failures),
                        "successful_login_event_id": event["event_id"],
                        "evidence_event_ids": [
                            failure["event_id"] for failure in failures
                        ],
                        "description": (
                            f"{len(failures)} failed login attempts were "
                            f"followed by a successful login for "
                            f"{event['username']} from {event['source_ip']}."
                        ),
                        "detected_at": timestamp.isoformat(),
                    }
                )

            failed_logins[key] = []

    return alerts

