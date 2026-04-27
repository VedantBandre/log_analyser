#!/usr/bin/env python3
"""
Log Analyser CLI

Usage:
    python analyser.py <logfile> [logfile2 ...]
    python analyser.py <logfile> --json
    python analyser.py <logfile> --json --out results.json
    python analyser.py <logfile> --quiet
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from parser import parse_file, LogEntry
from rules import run_all, Alert


SEVERITY = {
    "Brute Force":       "🔴 HIGH",
    "Endpoint Scanning": "🟡 MEDIUM",
    "Suspicious Paths":  "🟡 MEDIUM",
}
 
DIVIDER     = "─" * 52
BIG_DIVIDER = "═" * 52
 

def _severity(rule: str) -> str:
    return SEVERITY.get(rule, "⚪ INFO")

def format_alert(alert: Alert, index: int) -> str:
    lines = [
        DIVIDER,
        f"  Alert #{index}          {_severity(alert.rule)}",
        DIVIDER,
        f"  IP      : {alert.ip}",
        f"  Rule    : {alert.rule}",
        f"  Reason  : {alert.reason}",
        f"  Hits    : {len(alert.evidence)}",
    ]

    # Show upto 3 evidence lines, keeping output readable
    sample = alert.evidence[:3]
    if sample:
        lines.append("  Sample  :")
        for e in sample:
            ts = e.timestamp.strftime("%b %d %H:%M:%S")
            lines.append(f"    [{ts}] {e.raw[:72]}")
        if len(alert.evidence) > 3:
            lines.append(f"    ... and {len(alert.evidence) - 3} more")
 
    return "\n".join(lines)

def format_summary(alerts: list[Alert], files: list[str], elapsed_ms: float) -> str:
    high   = sum(1 for a in alerts if "HIGH"   in _severity(a.rule))
    medium = sum(1 for a in alerts if "MEDIUM" in _severity(a.rule))

    return "\n".join([
        BIG_DIVIDER,
        "  SUMMARY",
        BIG_DIVIDER,
        f"  Files analysed : {len(files)}",
        f"  Total alerts   : {len(alerts)}",
        f"  High severity  : {high}",
        f"  Medium severity: {medium}",
        f"  Elapsed        : {elapsed_ms:.1f}ms",
        BIG_DIVIDER,
    ])

# JSON Export
def _entry_to_dict(e: LogEntry) -> dict:
    return {
        "ip":        e.ip,
        "timestamp": e.timestamp.isoformat(),
        "method":    e.method,
        "path":      e.path,
        "status":    e.status,
        "source":    e.source,
    }

def alerts_to_json(alerts: list[Alert], files: list[str]) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "total_alerts": len(alerts),
        "alerts": [
            {
                "ip": a.ip,
                "rule": a.rule,
                "severity": _severity(a.rule).split()[-1], # HIGH | MEDIUM
                "reason": a.reason,
                "hits": len(a.evidence),
                "evidence": [_entry_to_dict(e) for e in a.evidence],
            }
            for a in alerts
        ],
    }


# Analyse function
def analyse(filepaths: list[str], quiet: bool = False) -> tuple[list[Alert], list[str]]:
    """Parse all files, run rules, return (alerts, successfully_parsed_files)."""
    all_entries = []
    parsed_files = []

    for fp in filepaths:
        path = Path(fp)
        if not path.exists():
            print(f"[analyser] ERROR: file not found — {fp}", file=sys.stderr)
            continue
        entries = parse_file(str(path))
        if entries:
            all_entries.extend(entries)
            parsed_files.append(fp)

    if not all_entries:
        return [], parsed_files

    alerts = run_all(all_entries)
    return alerts, parsed_files


# CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='analyser',
        description="Detect suspicious activity in Apache/SSH log files.",
    )
    p.add_argument(
        "logfiles",
        nargs="+",
        metavar="LOGFILE",
        help="One or more log files to analyse",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output analysis results as JSON",
    )
    p.add_argument(
        "--out",
        metavar="FILE",
        help="Write JSON output to a file (default: stdout)",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress parser info messages",
    )
    return p


def main():
    args = build_parser().parse_args()

    start = datetime.now(timezone.utc)
    alerts, parsed_files = analyse(args.logfiles, quiet=args.quiet)
    elapsed_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000

    # JSON mode
    if args.json:
        payload = alerts_to_json(alerts, parsed_files)
        output = json.dumps(payload, indent=2)
        if args.out:
            Path(args.out).write_text(output)
            print(f"[analyser] results written to {args.out}")
        else:
            print(output)
        return
    
    # Human-readable mode
    print()
    print(BIG_DIVIDER)
    print("  LOG ANALYSER")
    print(BIG_DIVIDER)
 
    if not alerts:
        print("\n  No suspicious activity detected.\n")
    else:
        print(f"\n  {len(alerts)} alert(s) found:\n")
        for i, alert in enumerate(alerts, 1):
            print(format_alert(alert, i))
        print(DIVIDER)
 
    print(format_summary(alerts, parsed_files, elapsed_ms))
    print()
 
if __name__ == "__main__":
    main()