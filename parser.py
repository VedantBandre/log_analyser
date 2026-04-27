# extracts IP, timestamp, request, method, status code from log file

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# Data structure for Log Entries
@dataclass
class LogEntry:
    ip: str             
    timestamp: datetime 
    method: str         # HTTP Method (CLF) | SSH event
    path: str           # HTTP Request Path (CLF)
    status: int         # Status Code
    message: str        # Empty string (CLF) | Full event message (SSH)
    source: str         # "clf" | "ssh"
    raw: str            # Raw Log Line


# CLF Parser
# Common Log Format (CLF):
# IP - - [timestamp] "METHOD /path HTTP/x.x" status size
_CLF_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})' # IP Address
    r'.*?'
    r'\[(?P<timestamp>[^\]]+)\]'       # [timestamp]
    r'\s+"(?P<method>\w+)\s+'          # "METHOD
    r'(?P<path>\S+)\s+'                # /path
    r'HTTP/[\d.]+"'                    # HTTP/x.x"
    r'\s+(?P<status>\d{3})'            # status code
)

_CLF_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_clf(line: str) -> Optional[LogEntry]:
    m = _CLF_PATTERN.match(line)
    
    if not m:
        return None
    
    try:
        ts = datetime.strptime(m.group("timestamp"), _CLF_TIMESTAMP_FORMAT)
    except ValueError:
        return None
    
    return LogEntry(
        ip=m.group("ip"),
        timestamp=ts,
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        message="",
        source="clf",
        raw=line,
    )



# SSH parser
# loghub Linux format:
#   Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; ... rhost=1.2.3.4 user=root
#   Jun 15 02:04:59 combo sshd[20882]: Failed password for root from 1.2.3.4 port 22 ssh2
_SSH_HEADER = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'  # Jun 14 15:16:01
    r'\s+\S+'                                               # hostname
    r'\s+ssh[\w()]*\[\d+\]:\s*'                             # sshd(pam_unix)[pid]
    r'(?P<message>.+)$'
)

# Matches any valid auth log line (su, cron, sudo, etc.) — used to
# silently discard non-sshd lines rather than counting them as errors
_AUTH_LOG_LINE = re.compile(
    r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\[\d+\]:'
)

# IP can appear as bare-dotted or "from X.X.X.X"
_RHOST_PATTERN = re.compile(r'rhost=(\d{1,3}(?:\.\d{1,3}){3})')
_FROM_PATTERN  = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')

# Event to Keyword dictionary
_EVENT_KEYWORDS = {
    "authentication failure": "AUTH_FAIL",
    "failed password":        "AUTH_FAIL",
    "invalid user":           "INVALID_USER",
    "check pass":             "CHECK_PASS",
    "accepted password":      "AUTH_OK",
    "accepted publickey":     "AUTH_OK",
    "connection closed":      "CONN_CLOSED",
    "disconnect":             "DISCONNECT",
}

# SSH log year placeholder
_SSH_YEAR = 2005


def _classify_ssh(message: str) -> str:
    lower = message.lower()
    for keyword, label in _EVENT_KEYWORDS.items():
        if keyword in lower:
            return label
    return "SSH_EVENT"


def _parse_ssh(line: str) -> Optional[LogEntry]:
    m = _SSH_HEADER.match(line)
    if not m:
        return None
    
    raw_ts = m.group("timestamp")
    message = m.group("message").strip()

    try:
        ts = datetime.strptime(f"{raw_ts} {_SSH_YEAR}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    
    ip_match = _RHOST_PATTERN.search(message) or _FROM_PATTERN.search(message)
    ip = ip_match.group(1) if ip_match else ""

    return LogEntry(
        ip=ip,
        timestamp=ts,
        method=_classify_ssh(message),
        path="",
        status=0,
        message=message,
        source="ssh",
        raw=line,
    )


def _detect_format(filepath: str) -> str:
    """Returns 'clf' or 'ssh' based on 1st parseable line"""
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if _CLF_PATTERN.match(line):
                return "clf"
            if _SSH_HEADER.match(line) or _AUTH_LOG_LINE.match(line):
                return "ssh"
    return "unknown"


# Public Parser API
def parse_file(filepath: str) -> list[LogEntry]:
    """
    Detect Log Format and parse valid lines from log file.
    Returns a list of LogEntry objects while skipping unparseable lines.
    """
    fmt = _detect_format(filepath)
    if fmt == "unknown":
        print(f"[parser] WARNING: Could not detect log format for {filepath}")
        return []
    
    parser_fn = _parse_clf if fmt == "clf" else _parse_ssh
    print(f"[parser] detected format: {fmt.upper()} - {filepath}")
    
    entries = []
    skipped = 0
    ignored = 0

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = parser_fn(line)
            if entry:
                entries.append(entry)
            elif fmt == "ssh" and _AUTH_LOG_LINE.match(line):
                ignored += 1  # valid auth log line, just not sshd — discard silently
            else:
                skipped += 1
 
    if ignored:
        print(f"[parser] ignored {ignored} non-sshd line(s) (su, cron, sudo, etc.)")
    if skipped:
        print(f"[parser] skipped {skipped} unparseable line(s)")
 
    print(f"[parser] parsed {len(entries)} entries")
    return entries