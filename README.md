# ThreatLens

### 10-Day SOC Detection & Incident Investigation Learning Journey

Welcome to the **ThreatLens Learning Journey** repository. This repository documents a hands-on, step-by-step educational pathway to understanding the foundational architecture and engineering principles behind a modern Security Operations Center (SOC) platform.

> **Note**: This repository is an educational build-along project focused on learning fundamentals from scratch. It is **not** the full ThreatLens production application. Each day implements one core concept using clean, beginner-friendly Python without complex frameworks, abstractions, or external dependencies.

---

## 🗺️ 10-Day Learning Roadmap

- [x] **Day 1 — Firewall Log Parsing**
- [x] **Day 2 — Log Normalization**
- [x] **Day 3 — Security Event Analysis**
- [x] **Day 4 — Attack Detection**
- [ ] **Day 5 — Risk Scoring**
- [ ] **Day 6 — Threat Intelligence**
- [ ] **Day 7 — MITRE ATT&CK**
- [ ] **Day 8 — Alert Correlation**
- [ ] **Day 9 — Incident Investigation**
- [ ] **Day 10 — SOC Dashboard**

---

## 🛡️ Day 1 — Firewall Log Parsing

### Learning Objectives
- **Understand firewall logs**: Learn what firewalls record when inspecting incoming and outgoing network packets.
- **Source & Destination IPs (`src_ip`, `dst_ip`)**: Identify who is initiating the connection and what system is being targeted.
- **Source & Destination Ports (`src_port`, `dst_port`)**: Understand how ephemeral client ports connect to standard service ports (e.g., port 22 for SSH, port 80 for HTTP, port 53 for DNS).
- **Protocols (`protocol`)**: Distinguish between connection-oriented transport (TCP) and stateless communication (UDP).
- **Actions (`action`)**: Differentiate between dropped/blocked traffic (`BLOCK`) and permitted connections (`ALLOW`).
- **Regular Expressions (Regex)**: Use Python's built-in `re` module to locate key-value patterns in unstructured text.
- **Convert raw logs into structured events**: Transform flat log strings into clean Python dictionaries.
- **Error handling & malformed logs**: Safely handle corrupt or non-standard log entries without crashing the parser.

---

### Ingestion Pipeline

```
Raw Firewall Log
       ↓
Read log line
       ↓
Regex parsing
       ↓
Extract security fields
       ↓
Validate required fields
       ↓
Python dictionary
       ↓
Structured security event
```

---

### Extracted Security Fields

| Field | Meaning | Example Value |
|---|---|---|
| `timestamp` | Time of the firewall event | `"Jan 24 10:15:30"` |
| `action` | Firewall decision (`BLOCK` or `ALLOW`) | `"BLOCK"` |
| `src_ip` | Source IP address initiating the connection | `"192.168.1.10"` |
| `dst_ip` | Destination IP address receiving traffic | `"192.168.1.1"` |
| `protocol` | Network transport protocol (`TCP`, `UDP`, etc.) | `"TCP"` |
| `src_port` | Ephemeral client port on the source machine | `54321` (integer) |
| `dst_port` | Target service port on the destination server | `22` (integer) |

---

### Example: Raw Log to Structured Event

#### RAW LOG
```text
Jan 24 10:15:30 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
```

↓

#### PARSED EVENT
```json
{
    "timestamp": "Jan 24 10:15:30",
    "action": "BLOCK",
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.1",
    "protocol": "TCP",
    "src_port": 54321,
    "dst_port": 22
}
```

---

## 🔄 Day 2 — Log Normalization

### The Real-World Problem
A real-world Security Operations Center (SOC) receives telemetry and logs from dozens of different technologies and vendors.

For example, observe how three different systems log activity involving the same IP address (`10.0.0.5`):

1. **Firewall Log (UFW / iptables):**
   ```text
   Jan 24 10:15:30 kernel: [UFW BLOCK] SRC=10.0.0.5 DST=192.168.1.10 PROTO=TCP SPT=54321 DPT=22
   ```
2. **Linux Authentication Log (Syslog / SSH):**
   ```text
   Jan 24 10:20:01 server sshd[1234]: Failed password for user admin from 10.0.0.5 port 45123 ssh2
   ```
3. **Web Server Log (Nginx / Apache):**
   ```text
   10.0.0.5 - - [24/Jan/2026:10:20:10] "GET /login HTTP/1.1" 401 432
   ```

These logs use completely different formats, delimiters, and field names (`SRC` vs. `from` vs. position-based client IP). If an analyst wants to detect an adversary pivoting from scanning a port to brute-forcing SSH, a detection engine cannot easily query across different raw schemas.

### The Solution: Log Normalization
**Log Normalization** is the process of translating disparate parsed event dictionaries into a single, canonical schema with consistent field names and types. Once normalized, downstream detection rules (Day 4), risk scoring (Day 5), and correlation engines (Day 8) only need to interact with one unified data model.

---

### Day 2 Pipeline

```
RAW LOG (Firewall / Auth / Web)
       ↓
DAY 1 PARSER (Source-specific regex & syntax extraction)
       ↓
PARSED EVENT (Source-specific dictionary)
       ↓
DAY 2 NORMALIZER (Schema mapping & validation)
       ↓
CANONICAL NORMALIZED SECURITY EVENT
```

---

### Canonical Normalized Schema

Every normalized event in ThreatLens adheres to this structure:

| Field | Type | Description | Present in Firewall? | Present in Auth? |
|---|---|---|---|---|
| `timestamp` | `str` | Event timestamp | Yes | Yes |
| `event_type` | `str` | High-level category (`"network"`, `"authentication"`) | Yes (`"network"`) | Yes (`"authentication"`) |
| `source` | `str` | Sensor/technology identifier (`"ufw"`, `"linux_auth"`) | Yes (`"ufw"`) | Yes (`"linux_auth"`) |
| `src_ip` | `str` or `None` | Initiating source IP address | Yes | Yes |
| `dst_ip` | `str` or `None` | Target destination IP address | Yes | `None` |
| `src_port` | `int` or `None` | Source port integer | Yes | `None` |
| `dst_port` | `int` or `None` | Destination port integer | Yes | `None` |
| `protocol` | `str` or `None` | Network transport protocol (`"TCP"`, `"UDP"`) | Yes | `None` |
| `action` | `str` | Outcome/decision (`"BLOCK"`, `"FAILED_LOGIN"`, etc.) | Yes | Yes |
| `username` | `str` or `None` | User identity involved in the event | `None` | Yes |
| `raw_log` | `str` or `None` | Preserved original raw log line for forensics | Yes | Yes |

> **Important Rule**: We do **not** force every log source to contain every field. If a field does not exist for a given log source (e.g., firewall logs do not have usernames, authentication logs do not have destination ports), it is represented consistently as `None`.

---

### Multi-Source Normalization Examples

#### 1. Firewall Log Normalization

- **Raw Log**:
  ```text
  Jan 24 10:15:30 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
  ```
- **Parsed Event (Day 1)**:
  ```json
  {
      "timestamp": "Jan 24 10:15:30",
      "action": "BLOCK",
      "src_ip": "192.168.1.10",
      "dst_ip": "192.168.1.1",
      "protocol": "TCP",
      "src_port": 54321,
      "dst_port": 22
  }
  ```
- **Normalized Event (Day 2)**:
  ```json
  {
      "timestamp": "Jan 24 10:15:30",
      "event_type": "network",
      "source": "ufw",
      "src_ip": "192.168.1.10",
      "dst_ip": "192.168.1.1",
      "src_port": 54321,
      "dst_port": 22,
      "protocol": "TCP",
      "action": "BLOCK",
      "username": null,
      "raw_log": "Jan 24 10:15:30 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22"
  }
  ```

#### 2. Linux Authentication Log Normalization

- **Raw Log**:
  ```text
  Jan 24 10:20:01 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 45123 ssh2
  ```
- **Parsed Event (Auth)**:
  ```json
  {
      "timestamp": "Jan 24 10:20:01",
      "action": "FAILED_LOGIN",
      "username": "admin",
      "src_ip": "10.0.0.5"
  }
  ```
- **Normalized Event (Day 2)**:
  ```json
  {
      "timestamp": "Jan 24 10:20:01",
      "event_type": "authentication",
      "source": "linux_auth",
      "src_ip": "10.0.0.5",
      "dst_ip": null,
      "src_port": null,
      "dst_port": null,
      "protocol": null,
      "action": "FAILED_LOGIN",
      "username": "admin",
      "raw_log": "Jan 24 10:20:01 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 45123 ssh2"
  }
  ```

---

## 📊 Day 3 — Security Event Analysis

### The Concept
Once logs are parsed into structured data (Day 1) and normalized into a unified schema (Day 2), a SOC receives a continuous stream of canonical events.

Before jumping into writing attack detection rules, an analyst or automated pipeline needs to perform **Security Event Analysis**. Analysis computes aggregate statistics, baseline metrics, and operational summaries across events to answer the question:

> *"What is happening across our environment right now?"*

### Critical SOC Principle: Analysis ≠ Detection

Understanding the distinction between these two stages is essential for cybersecurity engineers:

```
+-------------------------------------------------------------------------+
|                               PARSING (Day 1)                           |
|                  "Extract information from a raw log."                  |
+-------------------------------------------------------------------------+
                                    ↓
+-------------------------------------------------------------------------+
|                            NORMALIZATION (Day 2)                        |
|       "Convert different log formats into a common structure."         |
+-------------------------------------------------------------------------+
                                    ↓
+-------------------------------------------------------------------------+
|                              ANALYSIS (Day 3)                           |
|       "Calculate statistics and summarize what is happening."          |
|                                                                         |
|  Asks: "What is happening?"                                             |
|  Example: "10.0.0.5 generated 10 events across ports 22, 80, and 8080."|
+-------------------------------------------------------------------------+
                                    ↓
+-------------------------------------------------------------------------+
|                             DETECTION (Day 4)                           |
|                     "Identify suspicious behavior."                     |
|                                                                         |
|  Asks: "Does this behavior match a known suspicious pattern?"           |
|  Example: "10.0.0.5 attempted 30 SSH logins in 2 minutes (Brute Force)" |
+-------------------------------------------------------------------------+
```

- **Analysis** observes and quantifies reality without passing judgment.
- **Detection** applies security logic, signatures, and thresholds to decide if an observation constitutes an attack.

---

### Key Questions Answered by Security Event Analysis

1. **Top Source IPs**: Which IP address generates the most events?
2. **Top Destination Ports**: Which services (SSH=22, HTTP=80, HTTPS=443, DNS=53) are receiving the highest volume of traffic?
3. **Protocol Distribution**: What is the ratio between TCP and UDP traffic?
4. **Action Breakdown**: How many events resulted in `BLOCK` vs `ALLOW` vs `FAILED_LOGIN`?
5. **Unique Entities**: How many distinct source IPs are communicating on our network?
6. **Port Diversity per Host**: Which source IPs are contacting many distinct destination ports?

---

### Functions Implemented in `backend/analyzer.py`

| Function | Purpose | Example Return Value |
|---|---|---|
| `get_top_source_ips(events, top_n=None)` | Ranks source IPs by activity count | `[("10.0.0.5", 10), ("10.0.0.8", 4)]` |
| `get_top_destination_ports(events, top_n=None)` | Ranks target ports by connection attempts | `[(22, 6), (80, 5), (443, 3)]` |
| `get_protocol_stats(events)` | Computes protocol distribution | `{"TCP": 15, "UDP": 3}` |
| `get_action_stats(events)` | Tallies firewall & auth decisions | `{"BLOCK": 10, "ALLOW": 8, "FAILED_LOGIN": 6}` |
| `get_unique_source_ips(events)` | Returns set of all unique source IPs | `{"10.0.0.5", "10.0.0.8", ...}` |
| `get_unique_source_ip_count(events)` | Returns integer count of unique IPs | `8` |
| `get_event_type_stats(events)` | Categorizes events by type | `{"network": 18, "authentication": 9}` |
| `get_ports_per_source_ip(events)` | Maps source IP to contacted ports | `{"10.0.0.5": {22, 80, 8080}}` |
| `analyze_events(events)` | Consolidates all stats into one summary dict | `{ "total_events": 27, ... }` |
| `format_analysis_report(events)` | Formats clean human-readable text report | Formatted string for SOC analysts |

---

### Example Analysis Output

When `backend/main.py` processes normalized events, it generates this live summary:

```text
=============================
THREATLENS DAY 3 ANALYSIS
=============================

Top Source IPs:
10.0.0.5 -> 10 events
10.0.0.8 -> 4 events
192.168.1.50 -> 4 events
192.168.1.10 -> 3 events
185.34.22.10 -> 2 events
45.33.32.156 -> 1 events
10.0.0.12 -> 1 events
172.16.0.40 -> 1 events

Top Destination Ports:
22 -> 6
80 -> 5
443 -> 3
53 -> 2
8080 -> 1
123 -> 1

Protocol Statistics:
TCP -> 15
UDP -> 3

Action Statistics:
BLOCK -> 10
ALLOW -> 8
FAILED_LOGIN -> 6
SUCCESSFUL_LOGIN -> 2
SUDO_COMMAND -> 1

Unique Source IPs:
8

Event Types:
network -> 18
authentication -> 9
```

---

## 🎯 Day 4 — Attack Detection

### The Concept
After parsing raw logs (Day 1), normalizing disparate formats into a canonical schema (Day 2), and calculating baseline statistics (Day 3), the security pipeline performs **Attack Detection**.

While Day 3 Security Event Analysis asks:
> *"What is happening across our environment?"*

Day 4 Attack Detection asks:
> *"Does the observed behavior match a suspicious or malicious pattern?"*

### Pipeline Distinction: Parsing vs. Normalization vs. Analysis vs. Detection

Understanding where Detection sits in the security lifecycle is fundamental for security operations:

| Pipeline Stage | Question Asked | What It Does | Example |
|---|---|---|---|
| **Parsing (Day 1)** | *"What information is inside this log?"* | Uses regex to extract attributes from raw unstructured text | Extracts `src_ip=10.0.0.50`, `dst_port=22` |
| **Normalization (Day 2)** | *"How do we represent different logs consistently?"* | Maps diverse vendor fields into a standardized schema | Standardizes firewall and auth logs into common keys |
| **Analysis (Day 3)** | *"What is happening in the collected events?"* | Aggregates and summarizes event metrics without judgment | `10.0.0.50` contacted 7 destination ports |
| **Detection (Day 4)** | *"Does the behavior match a suspicious pattern?"* | Compares events against attack signatures and thresholds | `10.0.0.50` contacted 7 ports (>= threshold 5) → **ALERT** |

> **Critical SOC Principle**: A detection alert is **NOT** automatic proof of an attack or compromise. In a production SOC, an alert is a high-confidence signal indicating suspicious behavior that warrants investigation by a security analyst. We use investigative language (*"Possible port scanning detected"*, *"Possible SSH brute-force activity detected"*) rather than definitive conclusions.
>
> *Note: Risk scoring belongs to Day 5 and is not implemented here.*

---

### Detection Rules Implemented in `backend/detector.py`

#### 1. Port Scanning Detection (`detect_port_scan`)
- **Adversary Behavior**: During network reconnaissance, an attacker probes multiple ports on a server to discover active services, open doors, and vulnerable listening daemons.
- **Detection Logic**:
  1. Inspect normalized `network` events.
  2. Group destination ports by `src_ip`.
  3. Count the number of **unique** destination ports contacted by each source IP.
  4. If unique destination ports $\ge$ `PORT_SCAN_THRESHOLD` (default: `5`), generate a `PORT_SCAN` alert.
- **Why Unique Ports?**: Normal legitimate clients (e.g. web browsers) may send hundreds of packets, but only to 1 or 2 distinct destination ports (80 or 443). Contacting 5+ distinct service ports (21, 22, 23, 25, 80, 110, 443) in a short span strongly indicates reconnaissance.

#### 2. SSH Brute-Force Detection (`detect_ssh_bruteforce`)
- **Adversary Behavior**: An attacker uses automated tools (e.g., Hydra) to guess passwords across common or administrative accounts (`root`, `admin`, `guest`, `test`).
- **Detection Logic**:
  1. Inspect normalized `authentication` events.
  2. Identify events where `action == "FAILED_LOGIN"`.
  3. Group failure occurrences by `src_ip`.
  4. If total failed login attempts $\ge$ `SSH_BRUTE_FORCE_THRESHOLD` (default: `5`), generate an `SSH_BRUTE_FORCE` alert.

#### 3. Modular Detection Engine (`detect_events`)
A dispatcher function that runs all registered detection rules against the normalized event stream and aggregates the resulting alerts into a clean list:
```python
alerts = detect_events(events)
```

---

### Canonical Alert Schema

In a SOC, analysts must quickly understand **why** an alert was raised. A simple `{"attack": true}` flag is useless. ThreatLens generates structured alerts containing actionable evidence:

```json
{
    "alert_type": "PORT_SCAN",
    "severity": "HIGH",
    "source_ip": "10.0.0.50",
    "description": "Possible port scanning detected",
    "evidence": {
        "unique_destination_ports": 7,
        "threshold": 5
    }
}
```

And for brute-force attacks:

```json
{
    "alert_type": "SSH_BRUTE_FORCE",
    "severity": "HIGH",
    "source_ip": "10.0.0.60",
    "description": "Possible SSH brute-force activity detected",
    "evidence": {
        "failed_attempts": 8,
        "threshold": 5
    }
}
```

---

### False Positive Prevention & Safe Handling
The detection engine is engineered to prevent false positives and safely handle malformed telemetry:
- **Missing Fields**: Safely skips events missing `src_ip`, `dst_port`, `username`, or `action` without throwing exceptions.
- **Malformed Telemetry**: Handles non-dictionary items, `None`, strings, or corrupted values gracefully.
- **Event Type Isolation**: Port scanning rules ignore authentication events; brute-force rules ignore network firewall blocks.
- **Threshold Safeguards**: Normal traffic (e.g., `10.0.0.5` contacting 4 ports, or `192.168.1.10` with 2 failed logins) remains below thresholds and produces **0** false alerts.

---

### Example Detection Output

When `backend/main.py` runs, it executes the full pipeline from raw log to detection alert:

```text
========================================
THREATLENS DAY 4 — ATTACK DETECTION
========================================

Running detection rules...

[ALERT]
Type: PORT_SCAN
Severity: HIGH
Source IP: 10.0.0.50
Description: Possible port scanning detected

Evidence:
Unique destination ports: 7
Threshold: 5

----------------------------------------

[ALERT]
Type: SSH_BRUTE_FORCE
Severity: HIGH
Source IP: 10.0.0.60
Description: Possible SSH brute-force activity detected

Evidence:
Failed attempts: 8
Threshold: 5

----------------------------------------
```

---

## 📂 Project Structure

```
threatlens-learning/
│
├── README.md                   # 10-day roadmap, Day 1, 2, 3 & 4 documentation
├── .gitignore                  # Python bytecode and cache ignores
│
├── backend/
│   ├── __init__.py             # Module exports (Days 1 - 4)
│   ├── log_parser.py           # Day 1 regex parsing (firewall & auth)
│   ├── normalizer.py           # Day 2 canonical schema mapping & validation
│   ├── analyzer.py             # Day 3 security event statistical analysis
│   ├── detector.py             # Day 4 attack detection engine & rules
│   └── main.py                 # Multi-source pipeline demo (Parse -> Normalize -> Analyze -> Detect)
│
├── logs/
│   ├── sample_auth.log         # Realistic synthetic Linux authentication logs
│   └── sample_firewall.log     # Realistic synthetic UFW firewall logs
│
└── tests/
    ├── __init__.py             # Test package marker
    ├── test_day1_parser.py     # Day 1 parser unit tests
    ├── test_day2_normalizer.py # Day 2 normalization unit tests
    ├── test_day3_analyzer.py   # Day 3 event analysis unit tests
    └── test_day4_detector.py   # Day 4 attack detection unit tests
```

---

## 🚀 How to Run

Make sure you have Python 3 installed. No external libraries or third-party packages are needed.

### 1. Run the Full Security Pipeline Demo
```bash
python3 backend/main.py
```
This executes the 4-stage pipeline:
1. Ingests raw lines from `logs/sample_firewall.log` and `logs/sample_auth.log`.
2. Parses each line into intermediate dictionaries and validates them (Day 1).
3. Normalizes each event into the canonical security event format (Day 2).
4. Analyzes all normalized events and outputs the **ThreatLens Day 3 Analysis** statistics report (Day 3).
5. Evaluates normalized events against detection rules and outputs **ThreatLens Day 4 Attack Detection** alerts with evidence (Day 4).

### 2. Run All Automated Unit Tests
```bash
python3 -m unittest discover -s tests -v
```
Runs all 34 unit tests across Day 1 (parsing), Day 2 (normalization), Day 3 (analysis), and Day 4 (attack detection).

