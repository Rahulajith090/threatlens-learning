"""
ThreatLens Learning Journey - Day 3: Main Ingestion, Normalization & Analysis Script
===================================================================================

This script demonstrates the end-to-end security log processing pipeline:

RAW LOG
   ↓
DAY 1 PARSER (Regex extraction into source-specific dictionary)
   ↓
PARSED EVENT
   ↓
DAY 2 NORMALIZER (Standardization into canonical schema)
   ↓
NORMALIZED EVENT
   ↓
DAY 3 ANALYZER (Statistical aggregation & summarization)
   ↓
SECURITY STATISTICS

CRITICAL SOC DISTINCTION:
  - ANALYSIS (Day 3): Answers "What is happening?" by summarizing statistics.
  - DETECTION (Day 4): Answers "Does this match an attack pattern?"

How to run:
    python3 backend/main.py
"""

import os
import sys
import json

# Ensure the backend directory is in the import search path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from log_parser import parse_log, parse_auth_log
from normalizer import normalize_firewall_event, normalize_auth_event
from analyzer import format_analysis_report


def process_firewall_logs(log_file_path):
    """
    Reads and normalizes firewall logs from sample_firewall.log.

    Returns:
        tuple: (normalized_events_list, valid_count, invalid_count)
    """
    print("=" * 70)
    print(" 1. FIREWALL LOG NORMALIZATION (Network Events)")
    print("=" * 70)
    print(f"Reading logs from: {log_file_path}\n")

    if not os.path.exists(log_file_path):
        print(f"Error: Log file not found at {log_file_path}")
        return [], 0, 0

    events = []
    valid_count = 0
    invalid_count = 0

    with open(log_file_path, "r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                continue

            parsed_event = parse_log(line)

            if parsed_event:
                normalized_event = normalize_firewall_event(parsed_event, raw_log=line)
                if normalized_event:
                    valid_count += 1
                    events.append(normalized_event)
                    print(f"[Line {line_number}]")
                    print("--- RAW LOG ---")
                    print(line)
                    print("\n--- PARSED EVENT ---")
                    print(json.dumps(parsed_event, indent=4))
                    print("\n--- NORMALIZED EVENT ---")
                    print(json.dumps(normalized_event, indent=4))
                    print("-" * 50)
                else:
                    invalid_count += 1
                    print(f"[Line {line_number}] NORMALIZATION FAILED:")
                    print(f"  {line}")
                    print("-" * 50)
            else:
                invalid_count += 1
                print(f"[Line {line_number}] PARSING FAILED (Invalid log format):")
                print(f"  {line}")
                print("-" * 50)

    return events, valid_count, invalid_count


def process_auth_logs(log_file_path):
    """
    Reads and normalizes Linux authentication logs from sample_auth.log.

    Returns:
        tuple: (normalized_events_list, valid_count, invalid_count)
    """
    print("\n" + "=" * 70)
    print(" 2. LINUX AUTH LOG NORMALIZATION (Authentication Events)")
    print("=" * 70)
    print(f"Reading logs from: {log_file_path}\n")

    if not os.path.exists(log_file_path):
        print(f"Error: Log file not found at {log_file_path}")
        return [], 0, 0

    events = []
    valid_count = 0
    invalid_count = 0

    with open(log_file_path, "r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                continue

            parsed_event = parse_auth_log(line)

            if parsed_event:
                normalized_event = normalize_auth_event(parsed_event, raw_log=line)
                if normalized_event:
                    valid_count += 1
                    events.append(normalized_event)
                    print(f"[Line {line_number}]")
                    print("--- RAW LOG ---")
                    print(line)
                    print("\n--- PARSED EVENT ---")
                    print(json.dumps(parsed_event, indent=4))
                    print("\n--- NORMALIZED EVENT ---")
                    print(json.dumps(normalized_event, indent=4))
                    print("-" * 50)
                else:
                    invalid_count += 1
                    print(f"[Line {line_number}] NORMALIZATION FAILED:")
                    print(f"  {line}")
                    print("-" * 50)
            else:
                invalid_count += 1
                print(f"[Line {line_number}] PARSING FAILED (Invalid auth log format):")
                print(f"  {line}")
                print("-" * 50)

    return events, valid_count, invalid_count


def main():
    project_root = os.path.dirname(current_dir)
    firewall_log_path = os.path.join(project_root, "logs", "sample_firewall.log")
    auth_log_path = os.path.join(project_root, "logs", "sample_auth.log")

    fw_events, fw_valid, fw_invalid = process_firewall_logs(firewall_log_path)
    auth_events, auth_valid, auth_invalid = process_auth_logs(auth_log_path)

    print("\n" + "=" * 70)
    print(" PIPELINE EXECUTION SUMMARY")
    print("=" * 70)
    print(f"  Firewall Events Normalized:       {fw_valid}")
    print(f"  Firewall Lines Rejected/Invalid:  {fw_invalid}")
    print(f"  Auth Events Normalized:           {auth_valid}")
    print(f"  Auth Lines Rejected/Invalid:      {auth_invalid}")
    print(f"  Total Normalized Security Events: {fw_valid + auth_valid}")
    print("=" * 70)

    # Day 3: Security Event Analysis
    # Note: We analyze what happened across all normalized events.
    # We do NOT detect attacks here — detection belongs to Day 4.
    all_events = fw_events + auth_events
    print("\n" + format_analysis_report(all_events))


if __name__ == "__main__":
    main()
