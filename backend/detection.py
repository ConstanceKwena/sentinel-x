"""Explainable rule-based threat detection and attack-chain correlation."""

from __future__ import annotations

import os
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True)
class DetectionConfig:
    """Detection thresholds can be overridden with environment variables."""

    failed_login_threshold: int = 3
    window_minutes: int = 10
    suspicious_transfer_mb: float = 100.0

    @classmethod
    def from_environment(cls) -> "DetectionConfig":
        config = cls(
            failed_login_threshold=int(os.getenv("SENTINEL_FAILED_LOGIN_THRESHOLD", "3")),
            window_minutes=int(os.getenv("SENTINEL_DETECTION_WINDOW_MINUTES", "10")),
            suspicious_transfer_mb=float(os.getenv("SENTINEL_SUSPICIOUS_TRANSFER_MB", "100")),
        )
        if config.failed_login_threshold < 2:
            raise ValueError("SENTINEL_FAILED_LOGIN_THRESHOLD must be at least 2")
        if config.window_minutes < 1:
            raise ValueError("SENTINEL_DETECTION_WINDOW_MINUTES must be at least 1")
        if config.suspicious_transfer_mb <= 0:
            raise ValueError("SENTINEL_SUSPICIOUS_TRANSFER_MB must be greater than 0")
        return config


DEFAULT_CONFIG = DetectionConfig.from_environment()
RULE_POINTS = {
    "AUTH-001": 50,
    "AUTH-002": 20,
    "AUTH-004": 25,
    "PRIV-001": 30,
    "DATA-001": 35,
    "CORR-001": 10,
    "CHAIN-001": 20,
}


def _timestamp(event: dict[str, Any]) -> datetime:
    value = datetime.fromisoformat(str(event["received_at"]).replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _risk_score(rule_ids: set[str]) -> int:
    return min(100, sum(RULE_POINTS[rule_id] for rule_id in rule_ids))


def _severity(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _detection(
    rule_id: str,
    alert_type: str,
    description: str,
    explanation: str,
    evidence: list[dict[str, Any]],
    username: str | None,
    source_ip: str | None,
    config: DetectionConfig,
) -> dict[str, Any]:
    score = _risk_score({rule_id})
    return {
        "rule_id": rule_id,
        "alert_type": alert_type,
        "severity": _severity(score),
        "risk_score": score,
        "username": username,
        "source_ip": source_ip,
        "description": description,
        "explanation": explanation,
        "evidence_event_ids": [event["event_id"] for event in evidence],
        "detected_at": max(_timestamp(event) for event in evidence).isoformat(),
        "recommended_actions": [
            "Review the supporting events and verify the activity with the account owner.",
            "Check authentication, endpoint, and network telemetry for related activity.",
        ],
        "criteria": {
            "failed_login_threshold": config.failed_login_threshold,
            "window_minutes": config.window_minutes,
            "suspicious_transfer_mb": config.suspicious_transfer_mb,
        },
    }


def correlate_attack_chains(
    events: list[dict[str, Any]],
    config: DetectionConfig = DEFAULT_CONFIG,
) -> list[dict[str, Any]]:
    """Correlate only ordered events sharing both account and source IP."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        groups[(str(event["username"]), str(event["source_ip"]))].append(event)

    chains: list[dict[str, Any]] = []
    window = timedelta(minutes=config.window_minutes)
    seen: set[tuple[str, ...]] = set()

    for (username, source_ip), group in groups.items():
        ordered = sorted(group, key=_timestamp)
        for start_index, start in enumerate(ordered):
            start_time = _timestamp(start)
            related = [
                event for event in ordered[start_index:]
                if _timestamp(event) - start_time <= window
            ]
            types = [event["event_type"] for event in related]
            success_indices = [
                index for index, event_type in enumerate(types)
                if event_type == "login_success"
            ]
            valid_success = [
                index for index in success_indices
                if sum(event_type == "login_failed" for event_type in types[:index])
                >= config.failed_login_threshold
            ]
            downstream = [
                index for index, event_type in enumerate(types)
                if event_type in {"privilege_change", "outbound_transfer"}
            ]
            valid_downstream = [
                index for index in downstream
                if any(success_index < index for success_index in valid_success)
            ]
            if not valid_success or not valid_downstream:
                continue

            end_index = valid_downstream[-1]
            evidence = related[:end_index + 1]
            event_ids = tuple(event["event_id"] for event in evidence)
            if event_ids in seen:
                continue
            seen.add(event_ids)

            stages = ["Repeated failed authentication", "Successful login"]
            if any(event["event_type"] == "privilege_change" for event in evidence):
                stages.append("Privilege change")
            if any(event["event_type"] == "outbound_transfer" for event in evidence):
                stages.append("Outbound data transfer")
            detected_at = max(_timestamp(event) for event in evidence).isoformat()
            chains.append({
                "chain_id": f"chain-{event_ids[0]}-{event_ids[-1]}",
                "username": username,
                "source_ip": source_ip,
                "stages": stages,
                "evidence_event_ids": list(event_ids),
                "timeline": [
                    {
                        "event_id": event["event_id"],
                        "event_type": event["event_type"],
                        "occurred_at": _timestamp(event).isoformat(),
                        "details": event.get("details"),
                    }
                    for event in evidence
                ],
                "started_at": min(_timestamp(event) for event in evidence).isoformat(),
                "detected_at": detected_at,
                "description": " → ".join(stages),
                "explanation": (
                    "These events share the same account and source IP and occurred "
                    f"in sequence within {config.window_minutes} minutes. "
                    "The ordered authentication and post-login activity is consistent "
                    "with account compromise followed by attempted impact."
                ),
            })

    return sorted(chains, key=lambda chain: chain["detected_at"], reverse=True)


def _transfer_size_mb(details: str | None) -> float | None:
    if not details:
        return None
    match = re.search(r"(\d+(?:\.\d+)?)\s*(bytes?|B|KB|MB|GB|TB)\b", details, re.IGNORECASE)
    if not match:
        return None
    amount = float(match.group(1))
    unit = match.group(2).upper()
    multipliers = {"BYTE": 1 / 1_000_000, "BYTES": 1 / 1_000_000, "B": 1 / 1_000_000,
                   "KB": 1 / 1_000, "MB": 1, "GB": 1_000, "TB": 1_000_000}
    return amount * multipliers[unit]


def detect_threats(
    events: list[dict[str, Any]],
    config: DetectionConfig = DEFAULT_CONFIG,
) -> list[dict[str, Any]]:
    """Run deterministic, explainable detection rules against normalized events."""
    window = timedelta(minutes=config.window_minutes)
    ordered = sorted(events, key=_timestamp)
    detections: list[dict[str, Any]] = []
    failed_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    failed_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in ordered:
        event_type = event["event_type"]
        username = str(event["username"])
        source_ip = str(event["source_ip"])
        timestamp = _timestamp(event)

        if event_type == "login_failed":
            identity_key = (username, source_ip)
            identity_failures = failed_by_identity[identity_key]
            identity_failures.append(event)
            identity_failures[:] = [
                failure for failure in identity_failures
                if timestamp - _timestamp(failure) <= window
            ]
            if len(identity_failures) == config.failed_login_threshold:
                detections.append(_detection(
                    "AUTH-004",
                    "brute_force_attempt",
                    f"{len(identity_failures)} failed logins targeted {username} from {source_ip}.",
                    "The same account received repeated authentication failures from one IP "
                    f"within {config.window_minutes} minutes. The configured threshold is "
                    f"{config.failed_login_threshold} attempts.",
                    identity_failures,
                    username,
                    source_ip,
                    config,
                ))

            ip_failures = failed_by_ip[source_ip]
            ip_failures.append(event)
            ip_failures[:] = [
                failure for failure in ip_failures
                if timestamp - _timestamp(failure) <= window
            ]
            accounts = {failure["username"] for failure in ip_failures}
            if len(ip_failures) >= config.failed_login_threshold and len(accounts) >= 2:
                if len(ip_failures) == config.failed_login_threshold or (
                    ip_failures[-1]["username"] not in {
                        failure["username"] for failure in ip_failures[:-1]
                    }
                ):
                    detections.append(_detection(
                        "AUTH-002",
                        "password_spraying",
                        f"{len(ip_failures)} failed logins from {source_ip} targeted "
                        f"{len(accounts)} accounts.",
                        "Repeated failures from one IP target multiple usernames, which "
                        "is consistent with password spraying rather than a single mistyped password.",
                        ip_failures,
                        None,
                        source_ip,
                        config,
                    ))

        elif event_type == "login_success":
            failures = [
                failure for failure in failed_by_identity.get((username, source_ip), [])
                if timedelta(0) <= timestamp - _timestamp(failure) <= window
            ]
            if len(failures) >= config.failed_login_threshold:
                evidence = failures + [event]
                detections.append(_detection(
                    "AUTH-001",
                    "suspicious_success_after_failures",
                    f"A successful login for {username} followed "
                    f"{len(failures)} failed attempts from {source_ip}.",
                    "The successful authentication followed repeated failures for the same "
                    "account from the same IP within the configured time window.",
                    evidence,
                    username,
                    source_ip,
                    config,
                ))
            failed_by_identity[(username, source_ip)] = []

        elif event_type == "privilege_change":
            detections.append(_detection(
                "PRIV-001",
                "privilege_escalation",
                f"A privilege change was recorded for {username} from {source_ip}.",
                "Privilege changes can grant access beyond an account's normal permissions. "
                "Verify the actor, requested role, and approved change record.",
                [event],
                username,
                source_ip,
                config,
            ))

        elif event_type == "outbound_transfer":
            size_mb = _transfer_size_mb(event.get("details"))
            size_context = (
                f" The event describes approximately {size_mb:g} MB, above the "
                f"{config.suspicious_transfer_mb:g} MB configured threshold."
                if size_mb is not None and size_mb >= config.suspicious_transfer_mb
                else " The event is explicitly classified as an outbound transfer; "
                "confirm its destination, volume, and business purpose."
            )
            detections.append(_detection(
                "DATA-001",
                "suspicious_outbound_transfer",
                f"An outbound data transfer was recorded for {username} from {source_ip}.",
                "Outbound transfer events are reviewed as potentially suspicious because "
                "they may represent data exfiltration." + size_context,
                [event],
                username,
                source_ip,
                config,
            ))

    # Correlate distinct rules for the same account or IP within one detection window.
    event_lookup = {event["event_id"]: event for event in ordered}
    rule_detections = list(detections)
    entity_matches: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for detection in rule_detections:
        if detection["username"]:
            entity_matches[("account", detection["username"])].append(detection)
        if detection["source_ip"]:
            entity_matches[("ip", detection["source_ip"])].append(detection)

    correlation_fingerprints: set[tuple[str, ...]] = set()
    for (entity_type, entity_value), related_detections in entity_matches.items():
        rule_ids = {detection["rule_id"] for detection in related_detections}
        if len(rule_ids) < 2:
            continue
        evidence_ids = list(dict.fromkeys(
            event_id
            for detection in related_detections
            for event_id in detection["evidence_event_ids"]
        ))
        evidence = [
            event_lookup[event_id] for event_id in evidence_ids if event_id in event_lookup
        ]
        if not evidence:
            continue
        evidence_times = [_timestamp(event) for event in evidence]
        if max(evidence_times) - min(evidence_times) > window:
            continue
        fingerprint = tuple(sorted(rule_ids)) + tuple(sorted(evidence_ids))
        if fingerprint in correlation_fingerprints:
            continue
        correlation_fingerprints.add(fingerprint)
        score = _risk_score(rule_ids | {"CORR-001"})
        username = entity_value if entity_type == "account" else None
        source_ip = entity_value if entity_type == "ip" else None
        detections.append({
            "rule_id": "CORR-001",
            "alert_type": "multiple_suspicious_events",
            "severity": _severity(score),
            "risk_score": score,
            "username": username,
            "source_ip": source_ip,
            "description": (
                f"{len(rule_ids)} suspicious detection rules were triggered for this "
                f"{entity_type} within {config.window_minutes} minutes."
            ),
            "explanation": (
                f"Multiple distinct detection rules ({', '.join(sorted(rule_ids))}) "
                f"support activity associated with {entity_type} {entity_value}. "
                "The evidence falls within the configured correlation window."
            ),
            "evidence_event_ids": [event["event_id"] for event in evidence],
            "detected_at": max(evidence_times).isoformat(),
            "recommended_actions": [
                "Review all supporting detection evidence together rather than in isolation.",
                "Verify whether the account or source IP is associated with approved activity.",
            ],
            "criteria": {
                "failed_login_threshold": config.failed_login_threshold,
                "window_minutes": config.window_minutes,
                "suspicious_transfer_mb": config.suspicious_transfer_mb,
            },
            "correlated_rule_ids": sorted(rule_ids),
        })

    # A sequence must be tied to a single account and IP to avoid joining unrelated users.
    chains = correlate_attack_chains(ordered, config)
    for chain in chains:
        evidence = [
            event for event in ordered
            if event["event_id"] in set(chain["evidence_event_ids"])
        ]
        chain_rules = {"AUTH-001", "AUTH-004", "CHAIN-001"}
        if any(event["event_type"] == "privilege_change" for event in evidence):
            chain_rules.add("PRIV-001")
        if any(event["event_type"] == "outbound_transfer" for event in evidence):
            chain_rules.add("DATA-001")
        points = _risk_score(chain_rules)
        detections.append({
            "rule_id": "CHAIN-001",
            "alert_type": "correlated_attack_chain",
            "severity": _severity(points),
            "risk_score": points,
            "username": chain["username"],
            "source_ip": chain["source_ip"],
            "description": chain["description"],
            "explanation": chain["explanation"],
            "evidence_event_ids": chain["evidence_event_ids"],
            "detected_at": chain["detected_at"],
            "recommended_actions": [
                "Validate the login and privilege change with the account owner and change records.",
                "Review the outbound destination and preserve relevant endpoint and network evidence.",
                "Contain the account or host according to the organization's incident procedure.",
            ],
            "criteria": {
                "failed_login_threshold": config.failed_login_threshold,
                "window_minutes": config.window_minutes,
                "suspicious_transfer_mb": config.suspicious_transfer_mb,
            },
            "chain_id": chain["chain_id"],
        })

    return sorted(detections, key=lambda detection: detection["detected_at"], reverse=True)


def detect_brute_force_followed_by_success(
    events: list[dict[str, Any]],
    threshold: int = 3,
    window_minutes: int = 10,
) -> list[dict[str, Any]]:
    """Compatibility wrapper retained for existing API clients and tests."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")
    config = DetectionConfig(
        failed_login_threshold=threshold,
        window_minutes=window_minutes,
    )
    detections = [
        detection for detection in detect_threats(events, config)
        if detection["rule_id"] == "AUTH-001"
    ]
    for detection in detections:
        detection["successful_login_event_id"] = detection["evidence_event_ids"][-1]
        detection["failed_attempts"] = len(detection["evidence_event_ids"]) - 1
        detection["evidence_event_ids"] = detection["evidence_event_ids"][:-1]
    return detections
