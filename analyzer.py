"""
AegisTrace AI — Core SIEM Event Analyzer
Enhanced with MITRE ATT&CK mapping, composite risk scoring,
IOC extraction, and time-window pattern clustering.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import re
from typing import Any


# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHTS = {"low": 10, "medium": 30, "high": 60, "critical": 90}

# MITRE ATT&CK technique mapping per event category
MITRE_MAPPING: dict[str, dict[str, str]] = {
    "authentication_failure": {
        "tactic": "Credential Access",
        "technique": "T1110 — Brute Force",
        "reference": "https://attack.mitre.org/techniques/T1110/",
    },
    "authentication_success": {
        "tactic": "Initial Access",
        "technique": "T1078 — Valid Accounts",
        "reference": "https://attack.mitre.org/techniques/T1078/",
    },
    "malware": {
        "tactic": "Execution",
        "technique": "T1204 — User Execution",
        "reference": "https://attack.mitre.org/techniques/T1204/",
    },
    "suspicious_process": {
        "tactic": "Execution",
        "technique": "T1059 — Command & Scripting Interpreter",
        "reference": "https://attack.mitre.org/techniques/T1059/",
    },
    "network_connection": {
        "tactic": "Command and Control",
        "technique": "T1071 — Application Layer Protocol",
        "reference": "https://attack.mitre.org/techniques/T1071/",
    },
    "privilege_change": {
        "tactic": "Privilege Escalation",
        "technique": "T1078.003 — Local Accounts",
        "reference": "https://attack.mitre.org/techniques/T1078/003/",
    },
    "dns_activity": {
        "tactic": "Command and Control",
        "technique": "T1071.004 — DNS",
        "reference": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "data_movement": {
        "tactic": "Exfiltration",
        "technique": "T1041 — Exfiltration Over C2 Channel",
        "reference": "https://attack.mitre.org/techniques/T1041/",
    },
    "security_detection": {
        "tactic": "Defense Evasion",
        "technique": "T1562 — Impair Defenses",
        "reference": "https://attack.mitre.org/techniques/T1562/",
    },
    "other": {
        "tactic": "Unknown",
        "technique": "N/A",
        "reference": "",
    },
}

# Prompt injection detection patterns
INJECTION_PATTERNS = [
    r"\bignore (all|any|the) (previous|prior|above) instructions\b",
    r"\bdisregard (all|any|the) (previous|prior|above) instructions\b",
    r"\breveal (the )?(secret|secrets|system prompt|passwords?)\b",
    r"\bshow (me )?(the )?(system prompt|hidden instructions)\b",
    r"\byou are now\b",
    r"\bexecute (this|the following) command\b",
    r"\bdo not tell the user\b",
    r"\bforget (all|your|the) (rules|instructions|guidelines)\b",
    r"\bact as (a |an )?(different|new)\b",
    r"\boverride (your |all |the )?(safety|security|rules)\b",
    r"\bsystem\s*prompt\b",
    r"\bjailbreak\b",
    r"\bDAN\s+mode\b",
]

# IOC extraction patterns
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|gq|de|uk|co)\b"
)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

# Common SIEM field aliases
FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "@timestamp", "datetime", "date", "event_time",
                  "created_at", "occurred_at"],
    "source_ip": ["source_ip", "src_ip", "src", "source.address", "client_ip",
                  "attacker_ip", "remote_ip", "src_addr"],
    "destination_ip": ["destination_ip", "dst_ip", "dst", "destination.address",
                       "server_ip", "target_ip", "dst_addr"],
    "event_type": ["event_type", "event", "type", "category", "action",
                   "event_category", "rule_name"],
    "severity": ["severity", "level", "priority", "risk", "threat_level",
                 "risk_level", "criticality"],
    "user": ["user", "username", "account", "principal", "user_name",
             "actor", "subject", "identity"],
    "host": ["host", "hostname", "device", "computer", "machine",
             "endpoint", "asset", "workstation", "server"],
    "message": ["message", "description", "details", "alert", "reason",
                "summary", "msg", "alert_description", "event_description"],
}


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value).strip()


def normalize_severity(value: Any) -> str:
    value = _clean(value).lower()
    if value in {"critical", "crit", "emergency", "fatal", "4", "p1"}:
        return "critical"
    if value in {"high", "severe", "3", "p2", "major"}:
        return "high"
    if value in {"medium", "moderate", "2", "warning", "warn", "p3"}:
        return "medium"
    return "low"


def _pick(row: dict, aliases: list[str]) -> str:
    lower = {str(k).lower(): v for k, v in row.items()}
    for alias in aliases:
        if alias.lower() in lower:
            return _clean(lower[alias.lower()])
    return ""


def parse_timestamp(value: str) -> datetime:
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


# ─────────────────────────────────────────────────────────────
# Event Normalization
# ─────────────────────────────────────────────────────────────

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
        event[k] for k in ["event_type", "message"] if event[k]
    ).lower()

    if any(x in text for x in ["login failed", "authentication failed",
                                "failed login", "brute force",
                                "login_failed", "auth_fail"]):
        category = "authentication_failure"
    elif any(x in text for x in ["login success", "successful login",
                                  "authenticated", "login_success",
                                  "auth_success"]):
        category = "authentication_success"
    elif any(x in text for x in ["malware", "ransomware", "trojan",
                                  "virus", "worm", "rootkit",
                                  "backdoor", "keylogger"]):
        category = "malware"
    elif any(x in text for x in ["powershell", "cmd.exe", "process_start",
                                  "process start", "encoded command",
                                  "bash", "wscript", "cscript",
                                  "mshta", "regsvr32", "rundll32"]):
        category = "suspicious_process"
    elif any(x in text for x in ["network connection", "outbound connection",
                                  "connection", "c2", "beacon",
                                  "network_connection"]):
        category = "network_connection"
    elif any(x in text for x in ["privilege", "admin added", "role changed",
                                  "sudo", "elevation", "escalat"]):
        category = "privilege_change"
    elif any(x in text for x in ["dns", "domain lookup", "nslookup",
                                  "dns_query"]):
        category = "dns_activity"
    elif any(x in text for x in ["upload", "exfil", "data transfer",
                                  "download", "staging", "archive"]):
        category = "data_movement"
    elif any(x in text for x in ["alert", "detection", "blocked",
                                  "quarantine", "prevented"]):
        category = "security_detection"
    else:
        category = "other"

    event["category"] = category
    event["mitre"] = MITRE_MAPPING.get(category, MITRE_MAPPING["other"])
    event["raw_text"] = " ".join(_clean(v) for v in row.values())
    return event


# ─────────────────────────────────────────────────────────────
# Prompt Injection Detection
# ─────────────────────────────────────────────────────────────

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
                        "severity": "high",
                        "reason": "Instruction-like text inside alert data — "
                                  "potential prompt injection attempt",
                    })
                    break  # one finding per field
    return findings


# ─────────────────────────────────────────────────────────────
# IOC Extraction
# ─────────────────────────────────────────────────────────────

def extract_iocs(events: list[dict]) -> list[dict]:
    """Extract Indicators of Compromise from event messages and raw text."""
    iocs: dict[tuple[str, str], dict] = {}

    # Known internal/private ranges to exclude from IOC flagging
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.",
                        "172.24.", "172.25.", "172.26.", "172.27.",
                        "172.28.", "172.29.", "172.30.", "172.31.",
                        "192.168.", "127.", "0.")

    for event in events:
        corpus = f"{event.get('message', '')} {event.get('raw_text', '')}"

        # IPs (skip private for IOC purposes)
        for match in _IPV4.finditer(corpus):
            ip = match.group()
            if not ip.startswith(private_prefixes):
                key = ("ipv4", ip)
                if key not in iocs:
                    iocs[key] = {"type": "ipv4", "value": ip, "event_ids": []}
                iocs[key]["event_ids"].append(event["id"])

        # Domains
        for match in _DOMAIN.finditer(corpus):
            dom = match.group().lower()
            key = ("domain", dom)
            if key not in iocs:
                iocs[key] = {"type": "domain", "value": dom, "event_ids": []}
            iocs[key]["event_ids"].append(event["id"])

        # URLs
        for match in _URL.finditer(corpus):
            url = match.group()
            key = ("url", url)
            if key not in iocs:
                iocs[key] = {"type": "url", "value": url, "event_ids": []}
            iocs[key]["event_ids"].append(event["id"])

        # Hashes (check longest first to avoid partial matches)
        for match in _SHA256.finditer(corpus):
            h = match.group().lower()
            key = ("sha256", h)
            if key not in iocs:
                iocs[key] = {"type": "sha256", "value": h, "event_ids": []}
            iocs[key]["event_ids"].append(event["id"])

        for match in _SHA1.finditer(corpus):
            h = match.group().lower()
            # Skip if already captured as sha256 substring
            if ("sha256", h) not in iocs:
                key = ("sha1", h)
                if key not in iocs:
                    iocs[key] = {"type": "sha1", "value": h, "event_ids": []}
                iocs[key]["event_ids"].append(event["id"])

        for match in _MD5.finditer(corpus):
            h = match.group().lower()
            if ("sha1", h) not in iocs and ("sha256", h) not in iocs:
                key = ("md5", h)
                if key not in iocs:
                    iocs[key] = {"type": "md5", "value": h, "event_ids": []}
                iocs[key]["event_ids"].append(event["id"])

        # Emails
        for match in _EMAIL.finditer(corpus):
            email = match.group().lower()
            key = ("email", email)
            if key not in iocs:
                iocs[key] = {"type": "email", "value": email, "event_ids": []}
            iocs[key]["event_ids"].append(event["id"])

    result = list(iocs.values())
    for item in result:
        item["event_ids"] = sorted(set(item["event_ids"]))
        item["count"] = len(item["event_ids"])
    return result


# ─────────────────────────────────────────────────────────────
# Pattern Detection (Enhanced)
# ─────────────────────────────────────────────────────────────

def detect_patterns(events: list[dict]) -> list[dict]:
    patterns = []

    source_counts = Counter(e["source_ip"] for e in events if e["source_ip"])
    user_counts = Counter(e["user"] for e in events if e["user"])
    host_counts = Counter(e["host"] for e in events if e["host"])
    category_counts = Counter(e["category"] for e in events)

    for source, count in source_counts.items():
        if count >= 3:
            patterns.append({
                "pattern": "Repeated source activity",
                "indicator": source,
                "count": count,
                "assessment": "Review for scanning, brute force, or compromised-host behavior.",
                "mitre": MITRE_MAPPING.get("authentication_failure"),
            })

    for user, count in user_counts.items():
        if count >= 3:
            patterns.append({
                "pattern": "Repeated account activity",
                "indicator": user,
                "count": count,
                "assessment": "Review authentication sequence and account legitimacy.",
                "mitre": MITRE_MAPPING.get("authentication_success"),
            })

    for host, count in host_counts.items():
        if count >= 3:
            patterns.append({
                "pattern": "Repeated host activity",
                "indicator": host,
                "count": count,
                "assessment": "Review endpoint telemetry and process/network relationships.",
                "mitre": MITRE_MAPPING.get("suspicious_process"),
            })

    # Failure-to-success auth correlation
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
                "assessment": "Validate whether the successful authentication "
                              "followed expected behavior. Possible credential "
                              "stuffing or brute force success.",
                "mitre": MITRE_MAPPING.get("authentication_failure"),
            })

    # Time-window clustering: rapid events from same source within 5 min
    _detect_time_clusters(events, patterns)

    # Kill chain progression detection
    _detect_kill_chain(events, category_counts, patterns)

    return patterns


def _detect_time_clusters(events: list[dict], patterns: list[dict]):
    """Flag sources producing many events in a short window."""
    by_source: dict[str, list[datetime]] = defaultdict(list)
    for e in events:
        if e["source_ip"]:
            ts = parse_timestamp(e["timestamp"])
            if ts != datetime.min.replace(tzinfo=timezone.utc):
                by_source[e["source_ip"]].append(ts)

    for source, timestamps in by_source.items():
        timestamps.sort()
        if len(timestamps) < 4:
            continue
        window = timedelta(minutes=5)
        for i in range(len(timestamps) - 3):
            if timestamps[i + 3] - timestamps[i] <= window:
                patterns.append({
                    "pattern": "Rapid-fire activity cluster",
                    "indicator": source,
                    "count": len(timestamps),
                    "assessment": f"4+ events from {source} within a 5-minute "
                                  "window. Possible automated attack or scanning.",
                    "mitre": MITRE_MAPPING.get("authentication_failure"),
                })
                break


def _detect_kill_chain(events: list[dict],
                       category_counts: Counter,
                       patterns: list[dict]):
    """Detect multi-stage attack progression."""
    stages = [
        "authentication_failure",
        "authentication_success",
        "suspicious_process",
        "network_connection",
        "data_movement",
    ]
    present = [s for s in stages if category_counts.get(s, 0) > 0]

    if len(present) >= 3:
        chain = " → ".join(present)
        patterns.append({
            "pattern": "Multi-stage attack chain detected",
            "indicator": chain,
            "count": sum(category_counts[s] for s in present),
            "assessment": "Multiple kill chain stages observed in sequence. "
                          "This strongly suggests a coordinated intrusion attempt. "
                          "Immediate analyst review recommended.",
            "mitre": {
                "tactic": "Multiple",
                "technique": "Kill Chain Progression",
                "reference": "https://attack.mitre.org/",
            },
        })


# ─────────────────────────────────────────────────────────────
# Risk Score Calculation
# ─────────────────────────────────────────────────────────────

def calculate_risk_score(events: list[dict],
                         patterns: list[dict],
                         injection_flags: list[dict]) -> int:
    """Produce a composite risk score from 0–100."""
    if not events:
        return 0

    # Base: weighted average of severity
    severity_sum = sum(SEVERITY_WEIGHTS[e["severity"]] for e in events)
    base = severity_sum / len(events)  # 10–90 range

    # Pattern multiplier: each pattern adds 5 points, capped at +25
    pattern_bonus = min(len(patterns) * 5, 25)

    # Injection penalty: each flag adds 8 points, capped at +20
    injection_bonus = min(len(injection_flags) * 8, 20)

    # Kill chain bonus: if multi-stage attack detected, add 15
    kill_chain = any("kill chain" in p.get("pattern", "").lower()
                     for p in patterns)
    kc_bonus = 15 if kill_chain else 0

    # High-severity event density bonus
    high_crit = sum(1 for e in events
                    if SEVERITY_ORDER[e["severity"]] >= SEVERITY_ORDER["high"])
    density = high_crit / len(events) if events else 0
    density_bonus = int(density * 15)

    score = int(base + pattern_bonus + injection_bonus + kc_bonus + density_bonus)
    return max(0, min(100, score))


# ─────────────────────────────────────────────────────────────
# Timeline Builder
# ─────────────────────────────────────────────────────────────

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
            "mitre": e.get("mitre", {}).get("technique", "N/A"),
        }
        for e in ordered
    ]


# ─────────────────────────────────────────────────────────────
# Investigation Checklist Builder
# ─────────────────────────────────────────────────────────────

def build_checklist(events, patterns, injection_flags):
    steps = [
        ("Confirm incident scope",
         "Identify affected users, hosts, source addresses, and time window."),
        ("Validate authentication activity",
         "Review failed/successful authentication events and confirm whether "
         "access was expected."),
        ("Review endpoint telemetry",
         "Inspect process creation, parent-child process relationships, and "
         "suspicious command-line activity."),
        ("Review network activity",
         "Validate unusual outbound connections, DNS activity, and destination "
         "reputation in approved tooling."),
        ("Check privilege changes",
         "Confirm administrative or role changes were authorized."),
        ("Cross-reference IOCs",
         "Check extracted indicators (IPs, domains, hashes) against threat "
         "intelligence feeds and reputation services."),
        ("Validate MITRE ATT&CK mapping",
         "Confirm that observed techniques align with known threat actor TTPs."),
        ("Preserve evidence",
         "Preserve relevant logs and telemetry before making disruptive changes."),
        ("Contain if confirmed",
         "Use your organization's approved incident-response process to isolate "
         "affected assets or accounts."),
        ("Reset or revoke access when justified",
         "Apply approved credential/session controls after validating the incident."),
        ("Document findings",
         "Record evidence, decisions, timestamps, and analyst rationale."),
        ("Close with lessons learned",
         "Identify detection, logging, and control improvements."),
    ]

    if injection_flags:
        steps.insert(
            0,
            ("Treat alert instructions as untrusted data",
             "Do not execute, obey, or forward commands embedded in SIEM fields. "
             "Flag for security team review."),
        )

    return [
        {"id": i + 1, "step": title, "guidance": guidance}
        for i, (title, guidance) in enumerate(steps)
    ]


# ─────────────────────────────────────────────────────────────
# Main Analysis Pipeline
# ─────────────────────────────────────────────────────────────

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
    iocs = extract_iocs(events)
    risk_score = calculate_risk_score(events, patterns, injection_flags)

    source_ips = {e["source_ip"] for e in events if e["source_ip"]}
    hosts = {e["host"] for e in events if e["host"]}

    top_categories = ", ".join(
        f"{name} ({count})" for name, count in categories.most_common(5)
    ) or "none"

    # Collect unique MITRE techniques
    mitre_techniques = list({
        e["mitre"]["technique"]
        for e in events
        if e.get("mitre", {}).get("technique") != "N/A"
    })

    narrative = (
        f"AegisTrace AI analyzed {len(events)} SIEM events. "
        f"{high_critical} events are high or critical severity. "
        f"The dataset contains {len(source_ips)} unique source IP(s) and "
        f"{len(hosts)} unique host(s). "
        f"Most common categories: {top_categories}. "
    )

    if patterns:
        narrative += (
            f"{len(patterns)} correlated pattern(s) warrant analyst review. "
        )
    else:
        narrative += (
            "No repeated-activity pattern met the baseline correlation thresholds. "
        )

    if mitre_techniques:
        narrative += (
            f"MITRE ATT&CK techniques observed: "
            f"{', '.join(mitre_techniques)}. "
        )

    if injection_flags:
        narrative += (
            f"{len(injection_flags)} alert field(s) contain instruction-like text "
            "and should be treated as untrusted data."
        )

    summary = {
        "total_events": len(events),
        "high_critical": high_critical,
        "unique_source_ips": len(source_ips),
        "unique_hosts": len(hosts),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(categories),
        "mitre_techniques": mitre_techniques,
        "risk_score": risk_score,
        "narrative": narrative,
    }

    checklist = build_checklist(events, patterns, injection_flags)

    return {
        "events": events,
        "summary": summary,
        "timeline": timeline,
        "patterns": patterns,
        "prompt_injection_flags": injection_flags,
        "iocs": iocs,
        "checklist": checklist,
    }


# ─────────────────────────────────────────────────────────────
# Report Builder
# ─────────────────────────────────────────────────────────────

def build_report(result: dict) -> dict:
    return {
        "product": "AegisTrace AI",
        "version": "2.0.0",
        "report_type": "Defensive SIEM Triage Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": result["summary"]["risk_score"],
        "summary": result["summary"],
        "mitre_techniques": result["summary"].get("mitre_techniques", []),
        "patterns": result["patterns"],
        "iocs": result.get("iocs", []),
        "prompt_injection_flags": result["prompt_injection_flags"],
        "timeline": result["timeline"],
        "investigation_checklist": result["checklist"],
        "events": result["events"],
        "safety_note": (
            "This report is advisory. It does not execute commands, access "
            "endpoints, modify accounts, or perform automated containment."
        ),
    }
