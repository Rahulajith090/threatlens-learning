# ThreatLens

### 10-Day SOC Detection & Incident Investigation Learning Journey

Welcome to the **ThreatLens Learning Journey** repository. This repository documents a hands-on, step-by-step educational pathway to understanding the foundational architecture and engineering principles behind a modern Security Operations Center (SOC) platform.

> **Note**: This repository is an educational build-along project focused on learning fundamentals from scratch. It is **not** the full ThreatLens production application. Each day implements one core concept using clean, beginner-friendly Python without complex frameworks, abstractions, or external dependencies.

---

## 🗺️ 10-Day Learning Roadmap

- [x] **Day 1 — Firewall Log Parsing**
- [x] **Day 2 — Log Normalization**
- [ ] **Day 3 — Security Event Analysis**
- [ ] **Day 4 — Attack Detection**
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
| `protocol` | `str` or `None` | Network protocol (`"TCP"`, `"UDP"`) | Yes | `None` |
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

## 📂 Project Structure

```
threatlens-learning/
│
├── README.md                   # 10-day roadmap, Day 1 & Day 2 explanations
├── .gitignore                  # Python bytecode and cache ignores
│
├── backend/
│   ├── __init__.py             # Module exports
│   ├── log_parser.py           # Day 1 & Auth log regex extraction functions
│   ├── normalizer.py           # Day 2 normalization schema, mapping & validation
│   └── main.py                 # Multi-source ingestion & normalization pipeline demo
│
├── logs/
│   ├── sample_auth.log         # Realistic synthetic Linux authentication logs
│   └── sample_firewall.log     # Realistic UFW sample logs (valid + malformed)
│
└── tests/
    ├── __init__.py             # Test package marker
    ├── test_day1_parser.py     # Day 1 parser unit tests
    └── test_day2_normalizer.py # Day 2 normalization unit tests
```

---

## 🚀 How to Run

Make sure you have Python 3 installed. No external libraries or third-party packages are needed.

### 1. Run the Ingestion & Normalization Pipeline Demo
```bash
python3 backend/main.py
```
This executes the end-to-end pipeline:
- Ingests `logs/sample_firewall.log` and `logs/sample_auth.log`.
- Shows each raw log line, its parsed intermediate dictionary, and the finalized canonical normalized event.
- Displays summary statistics for valid vs. invalid lines.

### 2. Run the Automated Unit Tests
```bash
python3 -m unittest discover -s tests -v
```
All unit tests for both Day 1 (parsing) and Day 2 (normalization) execute automatically.
