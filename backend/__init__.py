"""
ThreatLens Learning Journey - Backend Modules
Day 1: Firewall Log Parser
Day 2: Log Normalization
"""

from .log_parser import parse_log, parse_auth_log
from .normalizer import (
    normalize_firewall_event,
    normalize_auth_event,
    normalize_event,
    validate_normalized_event,
)

__all__ = [
    "parse_log",
    "parse_auth_log",
    "normalize_firewall_event",
    "normalize_auth_event",
    "normalize_event",
    "validate_normalized_event",
]
