"""
ThreatLens Learning Journey - Day 2: Log Normalization
======================================================

Concept:
In a Security Operations Center (SOC), logs are collected from dozens of
different technologies (firewalls, operating system authentication, web
servers, DNS servers, endpoint detection agents). Each vendor formats logs
differently, using different field names for the same underlying concepts:

  - Firewall:   SRC=10.0.0.5 DST=192.168.1.10 PROTO=TCP SPT=54321 DPT=22
  - Linux Auth: Failed password for user admin from 10.0.0.5
  - Web Server: 10.0.0.5 - - [24/Jan/2026:10:20:10] "GET /login HTTP/1.1" 401

If an analyst or detection rule wants to search for all activity involving
IP '10.0.0.5', they would need to write separate rules for 'SRC', 'from',
and client IP tokens.

LOG NORMALIZATION solves this by mapping diverse parsed events into a single,
standardized security event schema with predictable field names.

Canonical Normalized Security Event Schema:
------------------------------------------
{
    "timestamp":  "...",   # Time of the event
    "event_type": "...",   # "network", "authentication", etc.
    "source":     "...",   # "ufw", "linux_auth", etc.
    "src_ip":     "...",   # Initiating IP (or None if unavailable)
    "dst_ip":     "...",   # Target IP (or None if unavailable)
    "src_port":   ...,     # Source port integer (or None)
    "dst_port":   ...,     # Destination port integer (or None)
    "protocol":   "...",   # Transport protocol (or None)
    "action":     "...",   # Decision/outcome: BLOCK, ALLOW, FAILED_LOGIN, etc.
    "username":   "...",   # Targeted account (or None)
    "raw_log":    "..."    # Original raw text for forensic auditing
}
"""


# List of canonical keys guaranteed to be present in every normalized event.
NORMALIZED_FIELDS = [
    "timestamp",
    "event_type",
    "source",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "action",
    "username",
    "raw_log",
]

# Required fields that must be present and non-empty for an event to be valid.
REQUIRED_NORMALIZED_FIELDS = ["timestamp", "event_type", "action"]


def validate_normalized_event(event):
    """
    Validates that a normalized event contains all standard keys and that
    essential core fields (timestamp, event_type, action) are non-empty.

    Args:
        event (dict): The candidate normalized event.

    Returns:
        bool: True if the event satisfies the schema, False otherwise.
    """
    if not isinstance(event, dict):
        return False

    for field in REQUIRED_NORMALIZED_FIELDS:
        val = event.get(field)
        if val is None or (isinstance(val, str) and not val.strip()):
            return False

    return True


def normalize_firewall_event(parsed_event, raw_log=None):
    """
    Normalizes a parsed firewall event (such as from Day 1 parse_log()) into
    the canonical ThreatLens security event structure.

    Args:
        parsed_event (dict): Parsed dictionary containing firewall attributes:
                             timestamp, action, src_ip, dst_ip, protocol,
                             src_port, dst_port.
        raw_log (str, optional): The original raw log string for forensic retention.

    Returns:
        dict: The canonical normalized event dictionary.
        None: If parsed_event is invalid, missing required fields, or not a dict.
    """
    # 1. Reject invalid input types
    if not isinstance(parsed_event, dict):
        return None

    # 2. Extract and validate required attributes
    timestamp = parsed_event.get("timestamp")
    action = parsed_event.get("action")

    if not timestamp or not action:
        return None

    # 3. Resolve raw_log (prefer explicit parameter, fallback to dict entry if present)
    preserved_raw_log = raw_log if raw_log is not None else parsed_event.get("raw_log")

    # 4. Construct normalized event
    # Optional fields default to None if not present in the parsed event
    normalized = {
        "timestamp": str(timestamp).strip(),
        "event_type": "network",
        "source": parsed_event.get("source", "ufw"),
        "src_ip": parsed_event.get("src_ip"),
        "dst_ip": parsed_event.get("dst_ip"),
        "src_port": parsed_event.get("src_port"),
        "dst_port": parsed_event.get("dst_port"),
        "protocol": parsed_event.get("protocol"),
        "action": str(action).strip(),
        "username": parsed_event.get("username", None),
        "raw_log": preserved_raw_log,
    }

    # 5. Validate that all required normalized fields exist and are non-empty
    if not validate_normalized_event(normalized):
        return None

    return normalized


def normalize_auth_event(parsed_event, raw_log=None):
    """
    Normalizes a parsed Linux authentication event into the canonical
    ThreatLens security event structure.

    Args:
        parsed_event (dict): Parsed dictionary containing authentication attributes:
                             timestamp, action, username, src_ip.
        raw_log (str, optional): The original raw log string for forensic retention.

    Returns:
        dict: The canonical normalized event dictionary.
        None: If parsed_event is invalid, missing required fields, or not a dict.
    """
    # 1. Reject invalid input types
    if not isinstance(parsed_event, dict):
        return None

    # 2. Extract and validate required attributes
    timestamp = parsed_event.get("timestamp")
    action = parsed_event.get("action")

    if not timestamp or not action:
        return None

    # 3. Resolve raw_log
    preserved_raw_log = raw_log if raw_log is not None else parsed_event.get("raw_log")

    # 4. Construct normalized event
    # Authentication logs lack dst_ip, src_port, dst_port, protocol; these remain None.
    normalized = {
        "timestamp": str(timestamp).strip(),
        "event_type": "authentication",
        "source": parsed_event.get("source", "linux_auth"),
        "src_ip": parsed_event.get("src_ip"),
        "dst_ip": parsed_event.get("dst_ip", None),
        "src_port": parsed_event.get("src_port", None),
        "dst_port": parsed_event.get("dst_port", None),
        "protocol": parsed_event.get("protocol", None),
        "action": str(action).strip(),
        "username": parsed_event.get("username"),
        "raw_log": preserved_raw_log,
    }

    # 5. Validate schema
    if not validate_normalized_event(normalized):
        return None

    return normalized


def normalize_event(parsed_event, event_type="network", raw_log=None):
    """
    General dispatcher function that normalizes a parsed event based on
    its event_type.

    Args:
        parsed_event (dict): Structured parsed event dictionary.
        event_type (str): "network" (default) or "authentication".
        raw_log (str, optional): Original raw log string.

    Returns:
        dict: Normalized event dictionary, or None if invalid.
    """
    if event_type == "authentication":
        return normalize_auth_event(parsed_event, raw_log=raw_log)
    elif event_type == "network":
        return normalize_firewall_event(parsed_event, raw_log=raw_log)
    else:
        return None
