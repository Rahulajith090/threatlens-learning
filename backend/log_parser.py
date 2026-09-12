"""
ThreatLens Learning Journey - Day 1: Firewall Log Parsing
=========================================================

This module demonstrates how a Security Operations Center (SOC)
platform parses raw, unstructured firewall logs into clean,
structured security events.

Pipeline:
Raw Firewall Log -> Regex Parsing -> Field Validation -> Python Dictionary
"""

import re


def parse_log(line):
    """
    Parses a single raw UFW-style firewall log line.

    Example input:
    'Jan 24 10:15:30 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22'

    Returns:
        dict: A structured dictionary with extracted security fields if valid.
        None: If the line is malformed or missing any required field.
    """
    # 1. Clean whitespace and ignore empty lines
    cleaned_line = line.strip()
    if not cleaned_line:
        return None

    # 2. Extract timestamp from the beginning of the syslog entry
    # Format: Month Day HH:MM:SS (e.g., 'Jan 24 10:15:30')
    timestamp_match = re.search(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", cleaned_line)
    if not timestamp_match:
        return None
    timestamp = timestamp_match.group(1)

    # 3. Extract the firewall action: [UFW BLOCK] or [UFW ALLOW]
    action_match = re.search(r"\[UFW\s+(BLOCK|ALLOW|AUDIT)\]", cleaned_line)
    if not action_match:
        return None
    action = action_match.group(1)

    # 4. Extract Source IP (SRC=...)
    src_ip_match = re.search(r"\bSRC=([0-9.]+)", cleaned_line)
    if not src_ip_match:
        return None
    src_ip = src_ip_match.group(1)

    # 5. Extract Destination IP (DST=...)
    dst_ip_match = re.search(r"\bDST=([0-9.]+)", cleaned_line)
    if not dst_ip_match:
        return None
    dst_ip = dst_ip_match.group(1)

    # 6. Extract Protocol (PROTO=...)
    proto_match = re.search(r"\bPROTO=([A-Za-z0-9]+)", cleaned_line)
    if not proto_match:
        return None
    protocol = proto_match.group(1)

    # 7. Extract Source Port (SPT=...)
    spt_match = re.search(r"\bSPT=(\d+)", cleaned_line)
    if not spt_match:
        return None
    try:
        src_port = int(spt_match.group(1))
    except ValueError:
        return None

    # 8. Extract Destination Port (DPT=...)
    dpt_match = re.search(r"\bDPT=(\d+)", cleaned_line)
    if not dpt_match:
        return None
    try:
        dst_port = int(dpt_match.group(1))
    except ValueError:
        return None

    # 9. Return structured security event dictionary
    return {
        "timestamp": timestamp,
        "action": action,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
    }
