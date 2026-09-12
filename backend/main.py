"""
ThreatLens Learning Journey - Day 1: Main Ingestion Script
==========================================================

This script reads raw firewall logs line-by-line, parses each line
using `log_parser.parse_log()`, and categorizes the result into:
- VALID EVENT (successfully parsed and structured)
- INVALID LOG (malformed or missing required fields)

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

from log_parser import parse_log


def main():
    # Construct relative path to the sample log file
    project_root = os.path.dirname(current_dir)
    log_file_path = os.path.join(project_root, "logs", "sample_firewall.log")

    print("=" * 60)
    print(" ThreatLens Learning - Day 1: Firewall Log Parsing")
    print("=" * 60)
    print(f"Reading logs from: {log_file_path}\n")

    if not os.path.exists(log_file_path):
        print(f"Error: Log file not found at {log_file_path}")
        return

    valid_count = 0
    invalid_count = 0

    with open(log_file_path, "r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                continue  # Skip blank lines

            event = parse_log(line)

            if event:
                valid_count += 1
                print(f"[Line {line_number}] VALID EVENT:")
                print(json.dumps(event, indent=4))
                print("-" * 40)
            else:
                invalid_count += 1
                print(f"[Line {line_number}] INVALID LOG:")
                print(f"  {line}")
                print("-" * 40)

    print("\nParsing Summary:")
    print(f"  Total Valid Events:   {valid_count}")
    print(f"  Total Invalid Lines:  {invalid_count}")
    print("=" * 60)


if __name__ == "__main__":
    main()
