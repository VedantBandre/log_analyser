from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from parser import LogEntry


# Data Structure for Alert
@dataclass
class Alert:
    ip: str
    rule: str
    reason: str
    evidence: list[LogEntry]

    def __str__(self) -> str:
        return f"IP: {self.ip}\nRule: {self.rule}\nReason: {self.reason}"


# Rule 1: Brute Force
# >5 auth failures from the same IP within a rolling time window
# Applies to: CLF (401s on login endpoints) + SSH (AUTH_FAIL events)

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=10)

def _is_auth_failure(entry: LogEntry) -> bool:
    if entry.source == "ssh":
        return entry.method == "AUTH_FAIL"
    if entry.source == "clf":
        return entry.status == 401
    return False

def check_brute_force(entries: list[LogEntry]) -> list[Alert]:
    # Group Auth failures by IP addr
    failures: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        if e.ip and _is_auth_failure(e):
            failures[e.ip].append(e)
    
    alerts = []
    for ip, events in failures.items():
        events.sort(key=lambda e: e.timestamp)
        
        # Slide a window over the sorted failures
        for i, start_event in enumerate(events):
            window = [
                e for e in events[i:]
                if e.timestamp - start_event.timestamp <= BRUTE_FORCE_WINDOW
            ]
            if len(window) > BRUTE_FORCE_THRESHOLD:
                alerts.append(Alert(
                    ip=ip,
                    rule="Brute Force",
                    reason=(
                        f"{len(window)} failed auth attempts in "
                        f"{BRUTE_FORCE_WINDOW.seconds // 60} minutes "
                        f"(threshold: {BRUTE_FORCE_THRESHOLD})"
                    ),
                    evidence=window,
                ))
                break # Only alert once per IP

    return alerts


# Rule 2: Endpoint Scanning
# Many uniques paths hit by the same IP in a short time window
# Applies to CLF only

SCAN_THRESHOLD = 5
SCAN_WINDOW = timedelta(minutes=1)

def check_scanning(entries: list[LogEntry]) -> list[Alert]:
    clf = [e for e in entries if e.source == "clf" and e.ip]

    # Group requests by IP
    by_ip: dict[str, list[LogEntry]] = defaultdict(list)
    for e in clf:
        by_ip[e.ip].append(e)
    
    alerts = []
    for ip, events in by_ip.items():
        events.sort(key=lambda e: e.timestamp)

        for i, start_event in enumerate(events):
            window = [
                e for e in events[i:]
                if e.timestamp - start_event.timestamp <= SCAN_WINDOW
            ]
            unique_paths = {e.path for e in window}
            if len(unique_paths) >= SCAN_THRESHOLD:
                alerts.append(Alert(
                    ip=ip,
                    rule="Endpoint Scanning",
                    reason=(
                        f"{len(unique_paths)} unique endpoints in "
                        f"{SCAN_WINDOW.seconds} seconds "
                        f"(threshold: {SCAN_THRESHOLD})"
                    ),
                    evidence=window,
                ))
                break
    
    return alerts


# Rule 3: Suspicious Paths
# Requests to known sensitive/malicious paths
# Applies to CLF only

SUSPICIOUS_PATHS = {
    "/admin", "/admin/", "/administrator",
    "/wp-login", "/wp-login.php", "/wp-admin",
    "/.env", "/.git", "/.git/config",
    "/etc/passwd", "/etc/shadow",
    "/shell", "/cmd", "/exec",
    "/phpmyadmin", "/pma",
    "/config", "/config.php",
}

def check_suspicious_paths(entries: list[LogEntry]) -> list[Alert]:
    # Collect hits per IP
    hits: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        if e.source == "clf" and e.ip:
            # path normalisation
            normalised = e.path.strip("/").lower().split("?")[0]
            if normalised in SUSPICIOUS_PATHS:
                hits[e.ip].append(e)
    
    alerts = []
    for ip, events in hits.items():
        paths_hit = sorted({e.path for e in events})
        alerts.append(Alert(
            ip=ip,
            rule="Suspicious Paths",
            reason=f"Requested {len(events)} sensitive path(s): {', '.join(paths_hit)}",
            evidence=events,
        ))
    
    return alerts


# Public Rules API
# Runs all rules against a list of entries
RULES = [
    check_brute_force,
    check_scanning,
    check_suspicious_paths,
]

def run_all(entries: list[LogEntry]) -> list[Alert]:
    """Returns alerts from all rules, sorted by most frequent first."""
    alerts = []
    for rule_fn in RULES:
        alerts.extend(rule_fn(entries))
    
    alerts.sort(key=lambda a: len(a.evidence), reverse=True)
    return alerts