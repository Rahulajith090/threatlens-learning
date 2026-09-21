"""
ThreatLens Learning Journey - Backend Modules
Day 1: Firewall Log Parser
Day 2: Log Normalization
Day 3: Security Event Analysis
"""

from .log_parser import parse_log, parse_auth_log
from .normalizer import (
    normalize_firewall_event,
    normalize_auth_event,
    normalize_event,
    validate_normalized_event,
    NORMALIZED_FIELDS,
    REQUIRED_NORMALIZED_FIELDS,
)
from .analyzer import (
    get_top_source_ips,
    get_top_destination_ports,
    get_protocol_stats,
    get_action_stats,
    get_unique_source_ips,
    get_unique_source_ip_count,
    get_event_type_stats,
    get_ports_per_source_ip,
    analyze_events,
    format_analysis_report,
)

__all__ = [
    "parse_log",
    "parse_auth_log",
    "normalize_firewall_event",
    "normalize_auth_event",
    "normalize_event",
    "validate_normalized_event",
    "NORMALIZED_FIELDS",
    "REQUIRED_NORMALIZED_FIELDS",
    "get_top_source_ips",
    "get_top_destination_ports",
    "get_protocol_stats",
    "get_action_stats",
    "get_unique_source_ips",
    "get_unique_source_ip_count",
    "get_event_type_stats",
    "get_ports_per_source_ip",
    "analyze_events",
    "format_analysis_report",
]
