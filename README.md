# log-analyser

Static log analysis tool for detecting common attack patterns in Apache access logs and SSH auth logs.  
No dependencies beyond the Python standard library.

---

## Problem

Production servers generate thousands of log lines per hour. Manually reviewing them for intrusion attempts is not practical, and most SIEM tools are either expensive, complex to operate, or both. This tool addresses a narrower problem: given a log file, identify IPs that are almost certainly doing something malicious — brute-forcing credentials, scanning for endpoints, or probing for known vulnerable paths.

---

## Usage

```bash
# Human-readable output
python3 analyser.py sample_logs/access.log
python3 analyser.py sample_logs/ssh.log
python3 analyser.py sample_logs/access.log sample_logs/ssh.log

# JSON output (stdout)
python3 analyser.py sample_logs/ssh.log --json

# JSON output (file)
python3 analyser.py sample_logs/ssh.log --json --out results.json
```

Format detection is automatic — CLF and SSH auth logs can be mixed freely.  
Multiple files can be passed in a single invocation.

### Sample output

```
[parser] detected format: CLF — sample_logs/access.log
[parser] parsed 17 entries
[parser] detected format: SSH — sample_logs/ssh.log
[parser] parsed 677 entries

====================================================
  LOG ANALYSER
====================================================

  5 alert(s) found:

----------------------------------------------------
  Alert #1          HIGH
----------------------------------------------------
  IP      : 220.135.151.1
  Rule    : Brute Force
  Reason  : 6 failed auth attempts in 10 minutes (threshold: 5)
  Hits    : 6
  Sample  :
    [Jun 15 02:04:59] authentication failure; rhost=220.135.151.1 user=root
    [Jun 15 02:04:59] authentication failure; rhost=220.135.151.1 user=root
    [Jun 15 02:05:00] authentication failure; rhost=220.135.151.1 user=root
    ... and 3 more

----------------------------------------------------
  Alert #5          MEDIUM
----------------------------------------------------
  IP      : 172.16.0.99
  Rule    : Suspicious Paths
  Reason  : Requested 3 sensitive path(s): /.env, /admin, /wp-login.php
  Hits    : 3

====================================================
  SUMMARY
====================================================
  Files analysed : 2
  Total alerts   : 5
  High severity  : 3
  Medium severity: 2
  Elapsed        : 6.2ms
====================================================
```

---

## Structure

```
log-analyser/
├── analyser.py       # CLI entry point, output formatting
├── parser.py         # Log parsing and format detection
├── rules.py          # Detection rule implementations
└── sample_logs/
    ├── access.log    # Apache CLF sample
    └── ssh.log       # Linux auth log sample (loghub format)
```

---

## Approach

### Parsing

Format is detected by inspecting the first non-empty line of each file.  
Two formats are supported:

**1. CLF (Common Log Format)** — standard Apache access log. Extracts IP, timestamp, HTTP method, path, and status code via regex.

**2. SSH / auth log** — Linux auth log as produced by `rsyslog` and used in the [loghub dataset](https://github.com/logpai/loghub). Only `sshd` lines are parsed; `su`, `sudo`, `cron`, and other PAM daemons are discarded silently. IPs are extracted from both `rhost=` key-value pairs and `from X.X.X.X` patterns to cover both `pam_unix` and direct `sshd` line formats. Events are normalised to typed labels (`AUTH_FAIL`, `AUTH_OK`, `INVALID_USER`, etc.).

All formats produce the same `LogEntry` dataclass, so rules have no awareness of the source format.

### Detection rules

**1. Brute Force** (`rules.py: check_brute_force`)
Triggers when more than 5 authentication failures originate from the same IP within a 10-minute rolling window. Uses a sliding window rather than fixed time buckets, so attempts that straddle a bucket boundary are still caught. Applies to HTTP 401 responses (CLF) and `AUTH_FAIL` events (SSH).

**2. Endpoint Scanning** (`rules.py: check_scanning`)
Triggers when a single IP hits 5 or more distinct paths within 60 seconds. Counts unique paths, not total requests — an IP hammering one endpoint repeatedly does not trigger this rule. CLF only.

**3. Suspicious Paths** (`rules.py: check_suspicious_paths`)
Triggers on any request to a known sensitive path: `/admin`, `/.env`, `/.git/config`, `/wp-login.php`, `/phpmyadmin`, `/etc/passwd`, and similar. Paths are normalised before matching (trailing slashes stripped, query strings removed, lowercased), so `/Admin/?debug=1` is treated the same as `/admin`. One hit is sufficient to generate an alert. CLF only.

Alerts are sorted by evidence count before output, so the noisiest offenders appear first.

### JSON output

The `--json` flag outputs a structured report suitable for ingestion into other tools:

```json
{
  "generated_at": "2026-04-28T10:00:00+00:00",
  "files": ["sample_logs/ssh.log"],
  "total_alerts": 2,
  "alerts": [
    {
      "ip": "220.135.151.1",
      "rule": "Brute Force",
      "severity": "HIGH",
      "reason": "6 failed auth attempts in 10 minutes (threshold: 5)",
      "hits": 6,
      "evidence": [...]
    }
  ]
}
```

---

## Limitations

**No DNS resolution.** The SSH auth log from loghub stores some IPs as hostnames (`rhost=220-135-151-1.hinet-ip.hinet.net`). Only bare dotted-quad IPs are extracted; hostname-only entries produce an empty IP field and are excluded from all rules. Resolving hostnames at parse time would add latency and external network dependency.

**SSH auth log year is hardcoded.** The Linux auth log format (`Jun 14 15:16:01`) does not include a year. The parser defaults to 2005 to match the loghub dataset. For current system logs this should be changed to the current year, or derived from the file modification time.

**Scanning rule is CLF-only.** SSH logs have no path concept, so endpoint scanning cannot be detected from auth logs. An IP conducting a slow scan across many days would also evade the 60-second window.

**No stateful tracking across runs.** Each invocation is independent. An attacker who sends 3 attempts per run across multiple log rotation periods will never trigger the brute force threshold.

**Thresholds are not tuned per environment.** The defaults (5 failures / 10 minutes for brute force, 5 paths / 60 seconds for scanning) are reasonable starting points but will produce false positives or false negatives depending on traffic patterns. A busy CI system legitimately hits many endpoints quickly; a low-traffic admin panel might warrant a threshold of 2.

---

## Future improvements

**Persistent state across log rotations:** Storing per-IP counters in a local SQLite database would allow detection of slow, distributed attacks that stay below the per-file threshold.

**CIDR / ASN grouping:** Brute force campaigns frequently distribute attempts across a /24 or across IPs registered to the same ASN. Grouping by network block rather than individual IP would catch coordinated attacks that rotate source addresses.

**Rate-based severity:** A fixed threshold treats 6 failures the same as 600. Scaling severity by the rate of failures (attempts per second) would produce more actionable prioritisation.

**Allowlist support:** Internal monitoring systems, load balancer health checks, and known scanners (e.g. Shodan, security researchers) generate noise that is difficult to suppress without per-IP or per-CIDR exclusions.

**Hostname resolution with caching:** Resolving hostnames asynchronously with a TTL-based cache would recover the ~30% of loghub SSH entries that carry only a hostname in `rhost=`.

**Additional log formats:** nginx, HAProxy, and `journald` JSON output are natural next targets. The parser's strategy pattern makes adding a new format a self-contained change.
