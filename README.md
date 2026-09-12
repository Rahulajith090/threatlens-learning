# ThreatLens

### 10-Day SOC Detection & Incident Investigation Learning Journey

Welcome to the **ThreatLens Learning Journey** repository. This repository documents a hands-on, step-by-step educational pathway to understanding the foundational architecture and engineering principles behind a modern Security Operations Center (SOC) platform.

> **Note**: This repository is an educational build-along project focused on learning fundamentals from scratch. It is **not** the full ThreatLens production application. Each day implements one core concept using clean, beginner-friendly Python without complex frameworks, abstractions, or external dependencies.

---

## 🗺️ 10-Day Learning Roadmap

- [x] **Day 1 — Firewall Log Parsing**
- [ ] **Day 2 — Log Normalization**
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

## 📂 Project Structure

```
threatlens-learning/
│
├── README.md                 # 10-day roadmap and Day 1 explanation
├── .gitignore                # Python and environment ignores
│
├── logs/
│   └── sample_firewall.log   # Realistic UFW sample logs (valid + malformed)
│
└── backend/
    ├── __init__.py           # Package marker
    ├── log_parser.py         # Regex parsing function (parse_log)
    └── main.py               # Line-by-line runner and terminal reporter
```

---

## 🚀 How to Run Day 1

Make sure you have Python 3 installed. No external libraries are needed.

```bash
# Navigate to the repository root
cd /home/rahul/projects/threatlens-learning

# Execute the Day 1 ingestion script
python3 backend/main.py
```

### Expected Output
The script reads `logs/sample_firewall.log`, outputs each valid parsed event in JSON format, warns on invalid lines, and displays a summary table.
