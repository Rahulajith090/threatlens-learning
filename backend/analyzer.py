"""
ThreatLens Learning Journey - Day 3: Security Event Analysis
============================================================

Concept:
In a Security Operations Center (SOC), after logs are parsed (Day 1) and
normalized into a canonical schema (Day 2), analysts perform Security Event
Analysis.

The goal of analysis is to calculate statistics, aggregate activity, and
summarize what is happening across the monitored infrastructure.

================================================================================
CRITICAL SOC CONCEPT: ANALYSIS ≠ DETECTION
================================================================================

It is vital to understand the difference between Analysis and Detection:

  - ANALYSIS asks: "What is happening?"
    It aggregates, counts, and observes reality without making a threat judgment.
    Example:
      "10.0.0.5 generated 15 events."
      "Port 22 is the most accessed destination port."
      "75% of connections were BLOCKED."

  - DETECTION asks: "Does this behavior match a known suspicious or malicious pattern?"
    It evaluates events against attack signatures, threshold rules, or anomalies.
    Example:
      "10.0.0.5 attempted 30 failed SSH logins in 2 minutes (SSH Brute Force Attack)."
      "10.0.0.5 probed 20 different ports in 10 seconds (Port Scan Attack)."

Day 3 focuses STRICTLY on Security Event Analysis.
Attack detection belongs to Day 4.
================================================================================

This module provides simple, beginner-friendly analytics functions using
Python's standard library (Counter, dict, set, list).
"""

from collections import Counter


def get_top_source_ips(events, top_n=None):
    """
    Counts and returns the most frequent source IP addresses across normalized events.

    Args:
        events (list): List of normalized event dictionaries.
        top_n (int, optional): Number of top IPs to return. If None, returns all.

    Returns:
        list of tuple: List of (ip_address, count) tuples sorted descending by frequency.
                       Example: [("10.0.0.5", 15), ("10.0.0.8", 9)]

    Analysis Note:
        Helps an analyst identify the most active hosts on the network.
        A high event count is an observation, not necessarily malicious.
    """
    if not events or not isinstance(events, (list, tuple)):
        return []

    counts = Counter(
        event["src_ip"]
        for event in events
        if isinstance(event, dict) and event.get("src_ip")
    )

    return counts.most_common(top_n)


def get_top_destination_ports(events, top_n=None):
    """
    Counts and returns the most frequently targeted destination ports.

    Args:
        events (list): List of normalized event dictionaries.
        top_n (int, optional): Number of top ports to return. If None, returns all.

    Returns:
        list of tuple: List of (port_number, count) tuples sorted descending by frequency.
                       Example: [(22, 20), (80, 12), (443, 8)]

    Analysis Note:
        Helps identify popular services (e.g. port 22=SSH, 80=HTTP, 443=HTTPS, 53=DNS).
        Events without a destination port (such as auth logs) are safely omitted.
    """
    if not events or not isinstance(events, (list, tuple)):
        return []

    counts = Counter(
        event["dst_port"]
        for event in events
        if isinstance(event, dict) and event.get("dst_port") is not None
    )

    return counts.most_common(top_n)


def get_protocol_stats(events):
    """
    Calculates the distribution of transport protocols across events.

    Args:
        events (list): List of normalized event dictionaries.

    Returns:
        dict: Mapping of protocol names to occurrence counts.
              Example: {"TCP": 35, "UDP": 10, "ICMP": 5}

    Analysis Note:
        Shows network transport breakdown (e.g. ratio of TCP vs UDP traffic).
    """
    if not events or not isinstance(events, (list, tuple)):
        return {}

    counts = Counter(
        event["protocol"]
        for event in events
        if isinstance(event, dict) and event.get("protocol")
    )

    return dict(counts)


def get_action_stats(events):
    """
    Calculates the distribution of security actions and outcomes.

    Args:
        events (list): List of normalized event dictionaries.

    Returns:
        dict: Mapping of action types to counts.
              Example: {"BLOCK": 25, "ALLOW": 15, "FAILED_LOGIN": 10}

    Analysis Note:
        Gives a high-level view of system decisions (how much traffic was blocked,
        how many logins failed, how many connections were permitted).
    """
    if not events or not isinstance(events, (list, tuple)):
        return {}

    counts = Counter(
        event["action"]
        for event in events
        if isinstance(event, dict) and event.get("action")
    )

    return dict(counts)


def get_unique_source_ips(events):
    """
    Extracts the collection of all unique source IP addresses.

    Args:
        events (list): List of normalized event dictionaries.

    Returns:
        set: Set of distinct source IP strings.
             Example: {"10.0.0.5", "10.0.0.8", "192.168.1.10"}
    """
    if not events or not isinstance(events, (list, tuple)):
        return set()

    return {
        event["src_ip"]
        for event in events
        if isinstance(event, dict) and event.get("src_ip")
    }


def get_unique_source_ip_count(events):
    """
    Returns the total count of distinct source IP addresses.

    Args:
        events (list): List of normalized event dictionaries.

    Returns:
        int: Number of unique source IPs.
    """
    return len(get_unique_source_ips(events))


def get_event_type_stats(events):
    """
    Calculates the breakdown of high-level event types (e.g. network vs authentication).

    Args:
        events (list): List of normalized event dictionaries.

    Returns:
        dict: Mapping of event type to count.
              Example: {"network": 40, "authentication": 10}
    """
    if not events or not isinstance(events, (list, tuple)):
        return {}

    counts = Counter(
        event["event_type"]
        for event in events
        if isinstance(event, dict) and event.get("event_type")
    )

    return dict(counts)


def get_ports_per_source_ip(events):
    """
    Maps each source IP address to the set of destination ports it contacted.

    Args:
        events (list): List of normalized event dictionaries.

    Returns:
        dict: Mapping of source IP to set of destination port integers.
              Example: {"10.0.0.5": {22, 80, 443}, "10.0.0.8": {443}}

    Analysis Note:
        Helps analysts answer: "Which source IP contacted many different ports?"
        Observing that an IP contacted 20 ports is Analysis. Deciding that this
        constitutes a Port Scan attack is Detection (Day 4).
    """
    if not events or not isinstance(events, (list, tuple)):
        return {}

    ip_ports = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        src_ip = event.get("src_ip")
        dst_port = event.get("dst_port")

        if src_ip and dst_port is not None:
            if src_ip not in ip_ports:
                ip_ports[src_ip] = set()
            ip_ports[src_ip].add(dst_port)

    return ip_ports


def analyze_events(events):
    """
    Runs all analysis functions across the provided events and returns a
    consolidated summary dictionary.

    Args:
        events (list): List of normalized event dictionaries.

    Returns:
        dict: Comprehensive summary of all security statistics.
    """
    return {
        "total_events": len(events) if isinstance(events, (list, tuple)) else 0,
        "event_types": get_event_type_stats(events),
        "actions": get_action_stats(events),
        "protocols": get_protocol_stats(events),
        "top_source_ips": get_top_source_ips(events),
        "top_destination_ports": get_top_destination_ports(events),
        "unique_source_ips": get_unique_source_ips(events),
        "unique_source_ip_count": get_unique_source_ip_count(events),
        "ports_per_source_ip": get_ports_per_source_ip(events),
    }


def format_analysis_report(events):
    """
    Generates a human-readable text report summarizing the event statistics,
    matching SOC analysis presentation standards.

    Args:
        events (list): List of normalized event dictionaries.

    Returns:
        str: Cleanly formatted analysis report.
    """
    summary = analyze_events(events)

    lines = [
        "=" * 29,
        "THREATLENS DAY 3 ANALYSIS",
        "=" * 29,
        "",
        "Top Source IPs:",
    ]

    top_ips = summary["top_source_ips"]
    if top_ips:
        for ip, count in top_ips:
            lines.append(f"{ip} -> {count} events")
    else:
        lines.append("No source IPs recorded")

    lines.append("")
    lines.append("Top Destination Ports:")
    top_ports = summary["top_destination_ports"]
    if top_ports:
        for port, count in top_ports:
            lines.append(f"{port} -> {count}")
    else:
        lines.append("No destination ports recorded")

    lines.append("")
    lines.append("Protocol Statistics:")
    proto_stats = summary["protocols"]
    if proto_stats:
        for proto, count in proto_stats.items():
            lines.append(f"{proto} -> {count}")
    else:
        lines.append("No protocols recorded")

    lines.append("")
    lines.append("Action Statistics:")
    action_stats = summary["actions"]
    if action_stats:
        for action, count in action_stats.items():
            lines.append(f"{action} -> {count}")
    else:
        lines.append("No actions recorded")

    lines.append("")
    lines.append("Unique Source IPs:")
    lines.append(str(summary["unique_source_ip_count"]))

    lines.append("")
    lines.append("Event Types:")
    type_stats = summary["event_types"]
    if type_stats:
        for etype, count in type_stats.items():
            lines.append(f"{etype} -> {count}")
    else:
        lines.append("No event types recorded")

    return "\n".join(lines)
