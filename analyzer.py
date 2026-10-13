"""
AegisTrace AI - core SIEM event analyzer.

Normalisation, MITRE ATT&CK mapping, order-aware kill-chain and correlation
detection, IOC extraction, prompt-injection detection and composite risk scoring.
"""
from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from utils.sanitizer import defang, strip_controls

VERSION = "2.1.0"
MAX_EVENTS = 50_000
MAX_FIELD_LEN = 2_000

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHTS = {"low": 10, "medium": 30, "high": 60, "critical": 90}

MITRE_MAPPING: dict[str, dict[str, str]] = {
    "authentication_failure": {"tactic": "Credential Access", "technique": "T1110 — Brute Force",
                               "reference": "https://attack.mitre.org/techniques/T1110/"},
    "authentication_success": {"tactic": "Initial Access", "technique": "T1078 — Valid Accounts",
                               "reference": "https://attack.mitre.org/techniques/T1078/"},
    "malware": {"tactic": "Execution", "technique": "T1204 — User Execution",
                "reference": "https://attack.mitre.org/techniques/T1204/"},
    "suspicious_process": {"tactic": "Execution", "technique": "T1059 — Command & Scripting Interpreter",
                           "reference": "https://attack.mitre.org/techniques/T1059/"},
    "network_connection": {"tactic": "Command and Control", "technique": "T1071 — Application Layer Protocol",
                           "reference": "https://attack.mitre.org/techniques/T1071/"},
    "privilege_change": {"tactic": "Privilege Escalation", "technique": "T1078.003 — Local Accounts",
                         "reference": "https://attack.mitre.org/techniques/T1078/003/"},
    "dns_activity": {"tactic": "Command and Control", "technique": "T1071.004 — DNS",
                     "reference": "https://attack.mitre.org/techniques/T1071/004/"},
    "data_movement": {"tactic": "Exfiltration", "technique": "T1041 — Exfiltration Over C2 Channel",
                      "reference": "https://attack.mitre.org/techniques/T1041/"},
    "security_detection": {"tactic": "Defense Evasion", "technique": "T1562 — Impair Defenses",
                           "reference": "https://attack.mitre.org/techniques/T1562/"},
    "other": {"tactic": "Unknown", "technique": "N/A", "reference": ""},
}

# Kill-chain progression (ATT&CK-ish ordering). Equal rank = same stage.
KILL_CHAIN_RANK = {
    "authentication_failure": 0, "authentication_success": 1, "privilege_change": 2,
    "suspicious_process": 3, "dns_activity": 4, "network_connection": 4, "data_movement": 5,
}
KILL_CHAIN_MIN_STAGES = 3
AUTH_FAILURE_THRESHOLD = 3
CLUSTER_WINDOW = timedelta(minutes=5)
CLUSTER_MIN_EVENTS = 4

# ── Prompt-injection patterns (matched on normalised text) ──────────────────
INJECTION_PATTERNS = [
    r"\b(ignore|disregard|forget|override)\b.{0,25}\b(previous|prior|above|earlier|all|any|your|the)\b.{0,25}\b(instructions?|rules?|guidelines?|prompts?|polic(?:y|ies))\b",
    r"\b(reveal|show|print|output|repeat|leak|expose|dump)\b.{0,30}\b(system prompt|hidden instructions?|secrets?|passwords?|api keys?|credentials?)\b",
    r"\byou are now\b",
    r"\bfrom now on,? you\b",
    r"\bpretend (to be|you are)\b",
    r"\bact as (a |an )?(different|new|unrestricted|root|admin)\b",
    r"\bexecute\s+(?:all\s+|any\s+|these\s+|this\s+|the\s+following\s+)?commands?\b",
    r"\brun\s+(?:the\s+following|this)\s+(?:command|script)\b",
    r"\bdo not tell the (user|analyst)\b",
    r"\boverride\b.{0,20}\b(safety|security|rules|restrictions)\b",
    r"\bsystem\s*prompt\b",
    r"\bjailbreak\w*\b",
    r"\bdeveloper mode\b|\bdo anything now\b|\bdan mode\b",
    r"\bnew instructions?\s*:",
    r"(?:<\|?\s*(?:system|im_start)\s*\|?>|\[/?inst\])",
]
_INJECTION_RE = [re.compile(p, re.I | re.S) for p in INJECTION_PATTERNS]

# ── IOC patterns ─────────────────────────────────────────────────────────────
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?![\d.]*\d)")
_TLDS = (
    "com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|gq|de|uk|co|me|cc|site|online|club|shop|app|dev|pw|su|ws|to|"
    "in|us|fr|jp|br|nl|it|es|ch|se|no|fi|pl|ua|kr|vn|ir|tr|tv|onion|cloud|live|link|click|zip|icu|work|support|download"
)
_DOMAIN = re.compile(rf"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_TLDS})(?![\w-])", re.I)
_URL = re.compile(r"\bhttps?://[^\s<>\"']+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
)]

# ── Field aliases (compared case-insensitively after flattening) ─────────────
FIELD_ALIASES = {
    "timestamp": ["timestamp", "@timestamp", "time", "datetime", "date", "event_time", "created_at",
                  "occurred_at", "_time", "event.created", "event.start"],
    "source_ip": ["source_ip", "src_ip", "src", "source.address", "source.ip", "client_ip", "attacker_ip",
                  "remote_ip", "src_addr", "sourceaddress", "id.orig_h"],
    "destination_ip": ["destination_ip", "dst_ip", "dst", "destination.address", "destination.ip", "server_ip",
                       "target_ip", "dst_addr", "destinationaddress", "id.resp_h"],
    "event_type": ["event_type", "event", "type", "category", "action", "event_category", "rule_name",
                   "event.action", "event.category", "rule.name", "signature", "eventname"],
    "severity": ["severity", "level", "priority", "risk", "threat_level", "risk_level", "criticality",
                 "event.severity", "severity_label"],
    "user": ["user", "username", "account", "principal", "user_name", "actor", "subject", "identity",
             "user.name", "targetusername"],
    "host": ["host", "hostname", "device", "computer", "machine", "endpoint", "asset", "workstation",
             "server", "host.name", "computername"],
    "message": ["message", "description", "details", "alert", "reason", "summary", "msg",
                "alert_description", "event_description", "event.original", "log"],
}
_WRAPPER_KEYS = ("events", "alerts", "results", "records", "items", "logs", "data", "value")

# ── Categorisation rules: first match wins ──────────────────────────────────
_CATEGORY_RULES: list[tuple[str, re.Pattern]] = [(c, re.compile(p, re.I)) for c, p in [
    ("authentication_failure",
     r"\b(?:login|logon|sign ?in|auth\w*)\W+(?:fail\w*|denied|invalid|reject\w*)|\bfailed (?:login|logon|sign ?in|auth\w*|password)|\bbrute ?force|\binvalid (?:credentials|password)|\baccount lockout"),
    ("authentication_success",
     r"\b(?:login|logon|sign ?in|auth\w*)\W+(?:success\w*|succeeded)|\bsuccessful (?:login|logon|sign ?in|auth\w*)|\bauthenticated\b"),
    ("malware",
     r"\b(?:malware|ransomware|trojan|virus|worm|rootkit|backdoor|keylogger|spyware|botnet|infostealer|cryptominer)\b"),
    ("privilege_change",
     r"\bprivilege\w*|\bescalat\w*|\bsudo\b|\badmin group|\brole chang\w*|\badded to (?:the )?admin\w*|\belevat\w*"),
    ("suspicious_process",
     r"\b(?:powershell|pwsh|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|encoded command|base64|bash|process (?:start\w*|creat\w*))\b|/bin/sh"),
    ("dns_activity", r"\bdns\b|\bnslookup\b|\bdomain lookup\b"),
    ("data_movement", r"\bexfil\w*|\bdata transfer\b|\bupload\w*|\bstaging\b|\barchiv\w*|\bdownload\w*"),
    ("network_connection",
     r"\b(?:network connection|outbound|inbound|beacon\w*|c2|command and control|connection)\b|\btor exit"),
    ("security_detection", r"\balert\b|\bdetect\w*|\bblocked\b|\bquarantin\w*|\bprevented\b"),
]]


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _clean(value: Any) -> str:
    """Stringify a field; None/NaN/'nan' become '' (pandas CSV safe)."""
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    if isinstance(value, (dict, list, tuple)):
        text = str(value)
    else:
        text = str(value).strip()
    if text.lower() in {"nan", "none", "null", "nat"}:
        return ""
    return strip_controls(text)[:MAX_FIELD_LEN]


def _flatten(row: dict, prefix: str = "", depth: int = 0) -> dict[str, Any]:
    """Flatten nested dicts (ECS / Elastic / Splunk style) into dotted keys."""
    flat: dict[str, Any] = {}
    for key, value in row.items():
        full = f"{prefix}{key}"
        if isinstance(value, dict) and depth < 4:
            flat.update(_flatten(value, f"{full}.", depth + 1))
        else:
            flat[full] = value
    return flat


def normalize_severity(value: Any) -> str:
    text = _clean(value).lower()
    if not text:
        return "low"
    try:  # numeric scales: 0-4, 5-10, 11-100
        num = float(text)
        if num <= 4:
            return {0: "low", 1: "low", 2: "medium", 3: "high"}.get(int(num), "critical" if num >= 4 else "low")
        if num <= 10:
            return "critical" if num >= 9 else "high" if num >= 7 else "medium" if num >= 4 else "low"
        return "critical" if num >= 90 else "high" if num >= 70 else "medium" if num >= 40 else "low"
    except ValueError:
        pass
    if re.search(r"crit|emerg|fatal|\bp1\b|alert", text):
        return "critical"
    if re.search(r"high|severe|major|error|\bp2\b", text):
        return "high"
    if re.search(r"med|moder|warn|\bp3\b", text):
        return "medium"
    return "low"


def _pick(flat_lower: dict[str, Any], aliases: list[str]) -> str:
    for alias in aliases:
        value = flat_lower.get(alias.lower())
        cleaned = _clean(value)
        if cleaned:
            return cleaned
    return ""


_FRACTION = re.compile(r"(\.\d+)")
_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z",
               "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d")


def parse_timestamp(value: Any) -> datetime | None:
    """Parse many timestamp styles into an aware UTC datetime, else ``None``."""
    text = _clean(value)
    if not text:
        return None
    try:  # epoch seconds / milliseconds
        num = float(text)
        if num > 1e11:
            num /= 1000.0
        if 0 < num < 4e9:
            return datetime.fromtimestamp(num, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    iso = text.replace("Z", "+00:00").replace("z", "+00:00")
    iso = _FRACTION.sub(lambda m: "." + (m.group(1)[1:] + "000000")[:6], iso, count=1)
    candidates = [iso]
    for fmt in _TS_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            candidates = [parsed]
            break
        except ValueError:
            continue
    for cand in candidates:
        try:
            parsed = cand if isinstance(cand, datetime) else datetime.fromisoformat(cand)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


_FAR_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


def _sort_key(event: dict) -> tuple[datetime, int]:
    return (parse_timestamp(event.get("timestamp")) or _FAR_FUTURE, event["id"])


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in _INTERNAL_NETS)


# ─────────────────────────────────────────────────────────────
# Event normalisation & categorisation
# ─────────────────────────────────────────────────────────────

_REDACT_FOR_CLASSIFY = re.compile(
    r"https?://\S+|[\w.+-]+@[\w-]+\.[\w.-]+|\b(?:[a-z0-9-]+\.)+(?:" + _TLDS + r")\b|\b[0-9a-f]{32,64}\b", re.I)


def categorize(event_type: str, message: str) -> str:
    """Classify on event_type first (reliable), then on the message text."""
    for text in (event_type, message):
        text = _REDACT_FOR_CLASSIFY.sub(" ", text.replace("_", " ").replace("-", " ")) if text else ""
        if not text.strip():
            continue
        for category, rule in _CATEGORY_RULES:
            if rule.search(text):
                return category
    return "other"


def normalize_event(row: dict, index: int) -> dict:
    flat = _flatten(row)
    lower = {str(k).lower(): v for k, v in flat.items()}
    event = {
        "id": index + 1,
        "timestamp": _pick(lower, FIELD_ALIASES["timestamp"]),
        "source_ip": _pick(lower, FIELD_ALIASES["source_ip"]),
        "destination_ip": _pick(lower, FIELD_ALIASES["destination_ip"]),
        "event_type": _pick(lower, FIELD_ALIASES["event_type"]).lower() or "unknown",
        "severity": normalize_severity(_pick(lower, FIELD_ALIASES["severity"])),
        "user": _pick(lower, FIELD_ALIASES["user"]),
        "host": _pick(lower, FIELD_ALIASES["host"]),
        "message": _pick(lower, FIELD_ALIASES["message"]),
    }
    event["category"] = categorize(event["event_type"], event["message"])
    event["mitre"] = MITRE_MAPPING[event["category"]]
    event["raw_text"] = " ".join(_clean(v) for v in flat.values() if _clean(v))[:MAX_FIELD_LEN * 2]
    return event


# ─────────────────────────────────────────────────────────────
# Prompt-injection detection
# ─────────────────────────────────────────────────────────────

def _normalise_for_scan(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", text)
    text = text.translate(str.maketrans("0134@$", "oleass"))  # light leetspeak folding
    return re.sub(r"\s+", " ", text)


def detect_prompt_injection(events: list[dict]) -> list[dict]:
    """One finding per (event, field). ``other_fields`` is only scanned when the
    primary fields are clean, so the same text is never reported twice."""
    findings: list[dict] = []
    for event in events:
        hit_event = False
        for field in ("message", "event_type", "user", "host"):
            raw = event.get(field, "") or ""
            for variant in {raw, _normalise_for_scan(raw)}:
                match = next((m for r in _INJECTION_RE if (m := r.search(variant))), None)
                if match:
                    findings.append({
                        "event_id": event["id"], "field": field,
                        "matched_text": match.group(0)[:120], "severity": "high",
                        "reason": "Instruction-like text inside alert data — potential prompt injection attempt",
                    })
                    hit_event = True
                    break
            else:
                continue
        if not hit_event:
            raw = event.get("raw_text", "")
            match = next((m for r in _INJECTION_RE if (m := r.search(_normalise_for_scan(raw)))), None)
            if match:
                findings.append({
                    "event_id": event["id"], "field": "other_fields",
                    "matched_text": match.group(0)[:120], "severity": "high",
                    "reason": "Instruction-like text inside alert data — potential prompt injection attempt",
                })
    return findings


# ─────────────────────────────────────────────────────────────
# IOC extraction
# ─────────────────────────────────────────────────────────────

def extract_iocs(events: list[dict]) -> list[dict]:
    """Extract external IPs, domains, URLs, hashes and e-mails."""
    iocs: dict[tuple[str, str], dict] = {}

    def add(kind: str, value: str, event: dict) -> None:
        item = iocs.setdefault((kind, value), {
            "type": kind, "value": value, "defanged": defang(value), "event_ids": set(), "max_severity": "low"})
        item["event_ids"].add(event["id"])
        if SEVERITY_ORDER[event["severity"]] > SEVERITY_ORDER[item["max_severity"]]:
            item["max_severity"] = event["severity"]

    for event in events:
        corpus = event.get("raw_text") or event.get("message", "")

        for url in _URL.findall(corpus):
            url = url.rstrip(".,;)")
            add("url", url, event)
            host = urlparse(url).hostname or ""
            if host and not _IPV4.fullmatch(host):
                add("domain", host.lower(), event)
        remainder = _URL.sub(" ", corpus)

        for email in _EMAIL.findall(remainder):
            add("email", email.lower(), event)
        remainder = _EMAIL.sub(" ", remainder)

        for ip in _IPV4.findall(remainder):
            if not _is_internal(ip):
                add("ipv4", ip, event)
        for dom in _DOMAIN.findall(remainder):
            add("domain", dom.lower(), event)
        for h in _HEX.findall(remainder):
            if h.isdigit():
                continue
            add(_HASH_TYPES[len(h)], h.lower(), event)

    result = []
    for item in iocs.values():
        item["event_ids"] = sorted(item["event_ids"])
        item["count"] = len(item["event_ids"])
        result.append(item)
    result.sort(key=lambda i: (-SEVERITY_ORDER[i["max_severity"]], i["type"], i["value"]))
    return result


# ─────────────────────────────────────────────────────────────
# Pattern detection
# ─────────────────────────────────────────────────────────────

def _dominant_mitre(evs: list[dict]) -> dict[str, str]:
    cats = Counter(e["category"] for e in evs if e["category"] != "other")
    return MITRE_MAPPING[cats.most_common(1)[0][0]] if cats else MITRE_MAPPING["other"]


def _max_sev(evs: list[dict]) -> str:
    return max((e["severity"] for e in evs), key=lambda s: SEVERITY_ORDER[s], default="low")


def _pattern(kind, title, indicator, evs, assessment, mitre=None) -> dict:
    return {
        "type": kind, "pattern": title, "indicator": indicator, "count": len(evs),
        "severity": _max_sev(evs), "event_ids": sorted(e["id"] for e in evs),
        "assessment": assessment, "mitre": mitre or _dominant_mitre(evs),
    }


def detect_patterns(events: list[dict]) -> list[dict]:
    patterns: list[dict] = []
    ordered = sorted(events, key=_sort_key)

    for field, kind, title, advice in (
        ("source_ip", "repeated_source", "Repeated source activity",
         "Review for scanning, brute force, or compromised-host behavior."),
        ("user", "repeated_account", "Repeated account activity",
         "Review authentication sequence and account legitimacy."),
        ("host", "repeated_host", "Repeated host activity",
         "Review endpoint telemetry and process/network relationships."),
    ):
        groups: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            if e[field]:
                groups[e[field]].append(e)
        for value, evs in groups.items():
            if len(evs) >= 3:
                patterns.append(_pattern(kind, title, value, evs, advice))

    # Failures followed (chronologically) by a success for the same account/source
    groups = defaultdict(list)
    for e in ordered:
        groups[e["user"] or e["source_ip"] or "unknown"].append(e)
    for key, evs in groups.items():
        fails = 0
        fail_evs: list[dict] = []
        for e in evs:
            if e["category"] == "authentication_failure":
                fails += 1
                fail_evs.append(e)
            elif e["category"] == "authentication_success" and fails >= AUTH_FAILURE_THRESHOLD:
                patterns.append(_pattern(
                    "auth_failure_to_success", "Failure-to-success authentication sequence", key,
                    fail_evs + [e],
                    f"{fails} failed authentications were followed by a success. Validate whether the "
                    "login was expected; possible credential stuffing or brute-force success.",
                    MITRE_MAPPING["authentication_failure"]))
                break

    # Rapid-fire clusters: densest 5-minute window per source
    by_source: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    for e in ordered:
        ts = parse_timestamp(e["timestamp"])
        if e["source_ip"] and ts:
            by_source[e["source_ip"]].append((ts, e))
    for source, items in by_source.items():
        best: list[dict] = []
        lo = 0
        for hi in range(len(items)):
            while items[hi][0] - items[lo][0] > CLUSTER_WINDOW:
                lo += 1
            if hi - lo + 1 > len(best):
                best = [it[1] for it in items[lo:hi + 1]]
        if len(best) >= CLUSTER_MIN_EVENTS:
            patterns.append(_pattern(
                "rapid_cluster", "Rapid-fire activity cluster", source, best,
                f"{len(best)} events from {source} within a 5-minute window. "
                "Possible automated attack or scanning."))

    chain = _detect_kill_chain(ordered)
    if chain:
        patterns.append(chain)
    return patterns


def _detect_kill_chain(ordered: list[dict]) -> dict | None:
    """Longest strictly increasing run of kill-chain stages in time order."""
    seq = [e for e in ordered if e["category"] in KILL_CHAIN_RANK]
    if not seq:
        return None
    ranks = [KILL_CHAIN_RANK[e["category"]] for e in seq]
    best_len = [1] * len(seq)
    prev = [-1] * len(seq)
    for i in range(len(seq)):
        for j in range(i):
            if ranks[j] < ranks[i] and best_len[j] + 1 > best_len[i]:
                best_len[i], prev[i] = best_len[j] + 1, j
    end = max(range(len(seq)), key=lambda i: best_len[i])
    if best_len[end] < KILL_CHAIN_MIN_STAGES:
        return None
    idx = []
    while end != -1:
        idx.append(end)
        end = prev[end]
    idx.reverse()
    chain_evs = [seq[i] for i in idx]
    names = " → ".join(e["category"] for e in chain_evs)
    return {
        "type": "kill_chain", "pattern": "Multi-stage attack chain detected", "indicator": names,
        "count": len(chain_evs), "severity": "critical", "event_ids": [e["id"] for e in chain_evs],
        "assessment": "Attack stages were observed in chronological order. This strongly suggests "
                      "a coordinated intrusion; immediate analyst review is recommended.",
        "mitre": {"tactic": "Multiple", "technique": "Kill Chain Progression", "reference": "https://attack.mitre.org/"},
    }


# ─────────────────────────────────────────────────────────────
# Risk score
# ─────────────────────────────────────────────────────────────

def calculate_risk_score(events: list[dict], patterns: list[dict], injection_flags: list[dict]) -> int:
    """Composite 0-100 score: severity average + correlation, injection and
    kill-chain bonuses + high/critical density."""
    if not events:
        return 0
    base = sum(SEVERITY_WEIGHTS[e["severity"]] for e in events) / len(events)
    pattern_bonus = min(len(patterns) * 5, 25)
    injection_bonus = min(len(injection_flags) * 8, 20)
    kc_bonus = 15 if any(p.get("type") == "kill_chain" for p in patterns) else 0
    high_crit = sum(1 for e in events if SEVERITY_ORDER[e["severity"]] >= SEVERITY_ORDER["high"])
    density_bonus = int(high_crit / len(events) * 15)
    return max(0, min(100, int(base + pattern_bonus + injection_bonus + kc_bonus + density_bonus)))


def risk_label(score: int) -> str:
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"


# ─────────────────────────────────────────────────────────────
# Timeline & checklist
# ─────────────────────────────────────────────────────────────

def build_timeline(events: list[dict]) -> list[dict]:
    return [{
        "time": e["timestamp"] or "Unknown", "event_id": e["id"], "category": e["category"],
        "severity": e["severity"], "source_ip": e["source_ip"], "user": e["user"], "host": e["host"],
        "message": e["message"], "mitre": e.get("mitre", {}).get("technique", "N/A"),
    } for e in sorted(events, key=_sort_key)]


def build_checklist(events, patterns, injection_flags):
    steps = [
        ("Confirm incident scope", "Identify affected users, hosts, source addresses, and time window."),
        ("Validate authentication activity", "Review failed/successful authentication events and confirm whether access was expected."),
        ("Review endpoint telemetry", "Inspect process creation, parent-child process relationships, and suspicious command-line activity."),
        ("Review network activity", "Validate unusual outbound connections, DNS activity, and destination reputation in approved tooling."),
        ("Check privilege changes", "Confirm administrative or role changes were authorized."),
        ("Cross-reference IOCs", "Check extracted indicators (IPs, domains, hashes) against threat intelligence feeds and reputation services."),
        ("Validate MITRE ATT&CK mapping", "Confirm that observed techniques align with known threat actor TTPs."),
        ("Preserve evidence", "Preserve relevant logs and telemetry before making disruptive changes."),
        ("Contain if confirmed", "Use your organization's approved incident-response process to isolate affected assets or accounts."),
        ("Reset or revoke access when justified", "Apply approved credential/session controls after validating the incident."),
        ("Document findings", "Record evidence, decisions, timestamps, and analyst rationale."),
        ("Close with lessons learned", "Identify detection, logging, and control improvements."),
    ]
    if injection_flags:
        steps.insert(0, ("Treat alert instructions as untrusted data",
                         "Do not execute, obey, or forward commands embedded in SIEM fields. Flag for security team review."))
    return [{"id": i + 1, "step": t, "guidance": g} for i, (t, g) in enumerate(steps)]


# ─────────────────────────────────────────────────────────────
# Main pipeline
# ─────────────────────────────────────────────────────────────

def _unwrap(raw: Any) -> list:
    """Accept arrays, {"events": [...]}, Elastic hits, Splunk results, single objects."""
    if isinstance(raw, dict):
        hits = raw.get("hits")
        if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
            return [h.get("_source", h) if isinstance(h, dict) else h for h in hits["hits"]]
        for key in _WRAPPER_KEYS:
            if isinstance(raw.get(key), list):
                return raw[key]
        return [raw]
    if isinstance(raw, list):
        return raw
    raise ValueError("Input must be a JSON object, JSON array, or CSV table.")


def analyze_events(raw_events: Any) -> dict:
    rows = _unwrap(raw_events)
    if len(rows) > MAX_EVENTS:
        raise ValueError(f"Too many events ({len(rows):,}). The limit is {MAX_EVENTS:,} per analysis.")

    events = [normalize_event(row, i) for i, row in enumerate(rows) if isinstance(row, dict)]
    if not events:
        raise ValueError("No usable event records were found.")

    severity_counts = Counter(e["severity"] for e in events)
    categories = Counter(e["category"] for e in events)
    high_critical = sum(1 for e in events if SEVERITY_ORDER[e["severity"]] >= SEVERITY_ORDER["high"])

    injection_flags = detect_prompt_injection(events)
    patterns = detect_patterns(events)
    timeline = build_timeline(events)
    iocs = extract_iocs(events)
    risk_score = calculate_risk_score(events, patterns, injection_flags)

    source_ips = {e["source_ip"] for e in events if e["source_ip"]}
    hosts = {e["host"] for e in events if e["host"]}
    stamps = sorted(t for t in (parse_timestamp(e["timestamp"]) for e in events) if t)
    mitre_techniques = sorted({e["mitre"]["technique"] for e in events if e["mitre"]["technique"] != "N/A"})
    top_categories = ", ".join(f"{n} ({c})" for n, c in categories.most_common(5)) or "none"

    narrative = (
        f"AegisTrace AI analyzed {len(events)} SIEM events. {high_critical} events are high or critical "
        f"severity. The dataset contains {len(source_ips)} unique source IP(s) and {len(hosts)} unique "
        f"host(s). Most common categories: {top_categories}. "
    )
    narrative += (f"{len(patterns)} correlated pattern(s) warrant analyst review. " if patterns
                  else "No repeated-activity pattern met the baseline correlation thresholds. ")
    if mitre_techniques:
        narrative += f"MITRE ATT&CK techniques observed: {', '.join(mitre_techniques)}. "
    if injection_flags:
        narrative += (f"{len(injection_flags)} alert field(s) contain instruction-like text "
                      "and should be treated as untrusted data.")

    summary = {
        "total_events": len(events), "high_critical": high_critical,
        "unique_source_ips": len(source_ips), "unique_hosts": len(hosts),
        "severity_counts": dict(severity_counts), "category_counts": dict(categories),
        "mitre_techniques": mitre_techniques, "risk_score": risk_score, "risk_label": risk_label(risk_score),
        "first_seen": stamps[0].isoformat() if stamps else None,
        "last_seen": stamps[-1].isoformat() if stamps else None,
        "duration_seconds": int((stamps[-1] - stamps[0]).total_seconds()) if len(stamps) > 1 else 0,
        "unparsed_timestamps": sum(1 for e in events if not parse_timestamp(e["timestamp"])),
        "narrative": narrative,
    }
    return {
        "events": events, "summary": summary, "timeline": timeline, "patterns": patterns,
        "prompt_injection_flags": injection_flags, "iocs": iocs,
        "checklist": build_checklist(events, patterns, injection_flags),
    }


def build_report(result: dict) -> dict:
    return {
        "product": "AegisTrace AI", "version": VERSION, "report_type": "Defensive SIEM Triage Report",
        "created_by": "RAJ ARYAN", "author_url": "https://rajaryan.neocities.org",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": result["summary"]["risk_score"], "summary": result["summary"],
        "mitre_techniques": result["summary"].get("mitre_techniques", []),
        "patterns": result["patterns"], "iocs": result.get("iocs", []),
        "prompt_injection_flags": result["prompt_injection_flags"], "timeline": result["timeline"],
        "investigation_checklist": result["checklist"], "events": result["events"],
        "safety_note": ("This report is advisory. It does not execute commands, access endpoints, "
                        "modify accounts, or perform automated containment."),
    }
