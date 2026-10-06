from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import re
from typing import Any


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

INJECTION_PATTERNS = [
    r"\bignore (all|any|the) (previous|prior|above) instructions\b",
    r"\bdisregard (all|any|the) (previous|prior|above) instructions\b",
    r"\breveal (the )?(secret|secrets|system prompt|passwords?)\b",
    r"\bshow (me )?(the )?(system prompt|hidden instructions)\b",
    r"\byou are now\b",
    r"\bexecute (this|the following) command\b",
    r"\bdo not tell the user\b",
]

FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "@timestamp", "datetime", "date"],
    "source_ip": ["source_ip", "src_ip", "src", "source.address", "client_ip"],
    "destination_ip": ["destination_ip", "dst_ip", "dst", "destination.address"],
    "event_type": ["event_type", "event", "type", "category"],
    "severity": ["severity", "level", "priority", "risk"],
    "user": ["user", "username", "account", "principal"],
    "host": ["host", "hostname", "device", "computer"],
    "message": ["message", "description", "details", "alert", "reason"],
}


def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value).strip()


def normalize_severity(value: Any) -> str:
    value = _clean(value).lower()
    if value in {"critical", "crit", "emergency", "fatal", "4"}:
        return "critical"
    if value in {"high", "severe", "3"}:
        return "high"
    if value in {"medium", "moderate", "2", "warning", "warn"}:
        return "medium"
    return "low"


def _pick(row: dict, aliases: list[str]) -> str:
    lower = {str(k).lower(): v for k, v in row.items()}
    for alias in aliases:
        if alias.lower() in lower:
            return _clean(lower[alias.lower()])
    return ""


def normalize_event(row: dict, index: int) -> dict:
    event = {
        "id": index + 1,
        "timestamp": _pick(row, FIELD_ALIASES["timestamp"]),
        "source_ip": _pick(row, FIELD_ALIASES["source_ip"]),
        "destination_ip": _pick(row, FIELD_ALIASES["destination_ip"]),
        "event_type": _pick(row, FIELD_ALIASES["event_type"]).lower() or "unknown",
        "severity": normalize_severity(_pick(row, FIELD_ALIASES["severity"])),
        "user": _pick(row, FIELD_ALIASES["user"]),
        "host": _pick(row, FIELD_ALIASES["host"]),
        "message": _pick(row, FIELD_ALIASES["message"]),
    }

    text = " ".join(
        event[k] for k in ["event_type", "message"]
        if event[k]
    ).lower()

    if any(x in text for x in ["login failed", "authentication failed", "failed login", "brute force"]):
        category = "authentication_failure"
    elif any(x in text for x in ["login success", "successful login", "authenticated"]):
        category = "authentication_success"
    elif any(x in text for x in ["malware", "ransomware", "trojan", "virus"]):
        category = "malware"
    elif any(x in text for x in ["powershell", "cmd.exe", "process_start", "process start", "encoded command"]):
        category = "suspicious_process"
    elif any(x in text for x in ["network connection", "outbound connection", "connection"]):
        category = "network_connection"
    elif any(x in text for x in ["privilege", "admin added", "role changed", "sudo"]):
        category = "privilege_change"
    elif any(x in text for x in ["dns", "domain lookup", "query"]):
        category = "dns_activity"
    elif any(x in text for x in ["upload", "exfil", "data transfer", "download"]):
        category = "data_movement"
    elif any(x in text for x in ["alert", "detection", "blocked"]):
        category = "security_detection"
    else:
        category = "other"

    event["category"] = category
    event["raw_text"] = " ".join(_clean(v) for v in row.values())
    return event


def parse_timestamp(value: str):
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def detect_prompt_injection(events: list[dict]) -> list[dict]:
    findings = []
    compiled = [re.compile(p, re.I) for p in INJECTION_PATTERNS]

    for event in events:
        fields = {
            "message": event.get("message", ""),
            "raw_text": event.get("raw_text", ""),
            "event_type": event.get("event_type", ""),
        }
        for field, value in fields.items():
            for pattern in compiled:
                match = pattern.search(value or "")
                if match:
                    findings.append({
                        "event_id": event["id"],
                        "field": field,
                        "matched_text": match.group(0),
                        "reason": "Instruction-like text inside alert data",
                    })
                    break
    return findings


def detect_patterns(events: list[dict]) -> list[dict]:
    patterns = []

    source_counts = Counter(e["source_ip"] for e in events if e["source_ip"])
    user_counts = Counter(e["user"] for e in events if e["user"])
    host_counts = Counter(e["host"] for e in events if e["host"])

    for source, count in source_counts.items():
        if count >= 3:
            patterns.append({
                "pattern": "Repeated source activity",
                "indicator": source,
                "count": count,
                "assessment": "Review for scanning, brute force, or compromised-host behavior.",
            })

    for user, count in user_counts.items():
        if count >= 3:
            patterns.append({
                "pattern": "Repeated account activity",
                "indicator": user,
                "count": count,
                "assessment": "Review authentication sequence and account legitimacy.",
            })

    for host, count in host_counts.items():
        if count >= 3:
            patterns.append({
                "pattern": "Repeated host activity",
                "indicator": host,
                "count": count,
                "assessment": "Review endpoint telemetry and process/network relationships.",
            })

    failures = defaultdict(list)
    successes = defaultdict(list)
    for event in events:
        key = event["user"] or event["source_ip"] or "unknown"
        if event["category"] == "authentication_failure":
            failures[key].append(event)
        if event["category"] == "authentication_success":
            successes[key].append(event)

    for key, fail_events in failures.items():
        if key in successes and fail_events:
            patterns.append({
                "pattern": "Failure-to-success authentication sequence",
                "indicator": key,
                "count": len(fail_events) + len(successes[key]),
                "assessment": "Validate whether the successful authentication followed expected behavior.",
            })

    return patterns


def build_timeline(events: list[dict]) -> list[dict]:
    ordered = sorted(events, key=lambda e: parse_timestamp(e["timestamp"]))
    return [
        {
            "time": e["timestamp"] or "Unknown",
            "event_id": e["id"],
            "category": e["category"],
            "severity": e["severity"],
            "source_ip": e["source_ip"],
            "user": e["user"],
            "host": e["host"],
            "message": e["message"],
        }
        for e in ordered
    ]


def build_checklist(events, patterns, injection_flags):
    steps = [
        ("Confirm incident scope", "Identify affected users, hosts, source addresses, and time window."),
        ("Validate authentication activity", "Review failed/successful authentication events and confirm whether access was expected."),
        ("Review endpoint telemetry", "Inspect process creation, parent-child process relationships, and suspicious command-line activity."),
        ("Review network activity", "Validate unusual outbound connections, DNS activity, and destination reputation in approved tooling."),
        ("Check privilege changes", "Confirm administrative or role changes were authorized."),
        ("Preserve evidence", "Preserve relevant logs and telemetry before making disruptive changes."),
        ("Contain if confirmed", "Use your organization's approved incident-response process to isolate affected assets or accounts."),
        ("Reset or revoke access when justified", "Apply approved credential/session controls after validating the incident."),
        ("Document findings", "Record evidence, decisions, timestamps, and analyst rationale."),
        ("Close with lessons learned", "Identify detection, logging, and control improvements."),
    ]

    if injection_flags:
        steps.insert(
            0,
            ("Treat alert instructions as untrusted data",
             "Do not execute, obey, or forward commands embedded in SIEM fields."),
        )

    return [
        {"id": i + 1, "step": title, "guidance": guidance}
        for i, (title, guidance) in enumerate(steps)
    ]


def analyze_events(raw_events: Any) -> dict:
    if isinstance(raw_events, dict):
        if isinstance(raw_events.get("events"), list):
            raw_events = raw_events["events"]
        else:
            raw_events = [raw_events]

    if not isinstance(raw_events, list):
        raise ValueError("Input must be a JSON object, JSON array, or CSV table.")

    events = [
        normalize_event(row, i)
        for i, row in enumerate(raw_events)
        if isinstance(row, dict)
    ]

    if not events:
        raise ValueError("No usable event records were found.")

    severity_counts = Counter(e["severity"] for e in events)
    categories = Counter(e["category"] for e in events)
    high_critical = sum(
        1 for e in events if SEVERITY_ORDER[e["severity"]] >= SEVERITY_ORDER["high"]
    )

    injection_flags = detect_prompt_injection(events)
    patterns = detect_patterns(events)
    timeline = build_timeline(events)

    source_ips = {e["source_ip"] for e in events if e["source_ip"]}
    hosts = {e["host"] for e in events if e["host"]}

    top_categories = ", ".join(
        f"{name} ({count})" for name, count in categories.most_common(5)
    ) or "none"

    narrative = (
        f"AegisTrace AI analyzed {len(events)} SIEM events. "
        f"{high_critical} events are high or critical severity. "
        f"The dataset contains {len(source_ips)} unique source IP(s) and "
        f"{len(hosts)} unique host(s). "
        f"Most common categories: {top_categories}. "
    )

    if patterns:
        narrative += f"{len(patterns)} repeated or correlated pattern(s) warrant analyst review. "
    else:
        narrative += "No repeated-activity pattern met the baseline correlation thresholds. "

    if injection_flags:
        narrative += (
            f"{len(injection_flags)} alert field(s) contain instruction-like text and "
            "should be treated as untrusted data."
        )

    summary = {
        "total_events": len(events),
        "high_critical": high_critical,
        "unique_source_ips": len(source_ips),
        "unique_hosts": len(hosts),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(categories),
        "narrative": narrative,
    }

    checklist = build_checklist(events, patterns, injection_flags)

    return {
        "events": events,
        "summary": summary,
        "timeline": timeline,
        "patterns": patterns,
        "prompt_injection_flags": injection_flags,
        "checklist": checklist,
    }


def build_report(result: dict) -> dict:
    return {
        "product": "AegisTrace AI",
        "report_type": "Defensive SIEM triage report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": result["summary"],
        "patterns": result["patterns"],
        "prompt_injection_flags": result["prompt_injection_flags"],
        "timeline": result["timeline"],
        "investigation_checklist": result["checklist"],
        "events": result["events"],
        "safety_note": (
            "This report is advisory. It does not execute commands, access endpoints, "
            "modify accounts, or perform automated containment."
        ),
    }
