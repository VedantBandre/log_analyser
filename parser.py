# extracts IP, timestamp, request, method, status code from log file

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Common Log Format (CLF):
# IP - - [timestamp] "METHOD /path HTTP/x.x" status size
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})' # IP Address
    r'.*?'
    r'\[(?P<timestamp>[^\]]+)\]'       # [timestamp]
    r'\s+"(?P<method>\w+)\s+'          # "METHOD
    r'(?P<path>\S+)\s+'                # /path
    r'HTTP/[\d.]+"'                    # HTTP/x.x"
    r'\s+(?P<status>\d{3})'            # status code
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    raw: str


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse a log line. Returns None for mismatch"""
    line = line.strip()
    if not line:
        return None
    
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    
    try:
        timestamp = datetime.strptime(match.group("timestamp"), TIMESTAMP_FORMAT)
    except ValueError:
        return None
    
    return LogEntry(
        ip=match.group("ip"),
        timestamp=timestamp,
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        raw=line,
    )


def parse_file(filepath: str) -> list[LogEntry]:
    """Parse valid lines from log file"""
    entries = []
    skipped = 0

    with open(filepath, 'r') as file:
        for line in file:
            entry = parse_line(line)
            if entry:
                entries.append(entry)
            elif line.strip():
                skipped += 1
    
    if skipped:
        print(f"[parser] skipped {skipped} unparseable line(s)")
    
    return entries

