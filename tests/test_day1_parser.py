"""
Unit Tests for Day 1: Firewall Log Parser
=========================================
Verifies that Day 1's `parse_log` function works as expected and that
its core functionality remains intact.
"""

import unittest
import sys
import os

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from log_parser import parse_log


class TestDay1FirewallParser(unittest.TestCase):
    def test_parse_valid_block_log(self):
        line = "Jan 24 10:15:30 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22"
        event = parse_log(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["timestamp"], "Jan 24 10:15:30")
        self.assertEqual(event["action"], "BLOCK")
        self.assertEqual(event["src_ip"], "192.168.1.10")
        self.assertEqual(event["dst_ip"], "192.168.1.1")
        self.assertEqual(event["protocol"], "TCP")
        self.assertEqual(event["src_port"], 54321)
        self.assertEqual(event["dst_port"], 22)

    def test_parse_valid_allow_log(self):
        line = "Jan 24 10:17:01 firewall kernel: [UFW ALLOW] IN=eth0 OUT= MAC= SRC=10.0.0.5 DST=192.168.1.1 PROTO=UDP SPT=12345 DPT=53"
        event = parse_log(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["action"], "ALLOW")
        self.assertEqual(event["protocol"], "UDP")
        self.assertEqual(event["src_port"], 12345)
        self.assertEqual(event["dst_port"], 53)

    def test_parse_empty_or_whitespace_line(self):
        self.assertIsNone(parse_log(""))
        self.assertIsNone(parse_log("   \n\t  "))

    def test_parse_malformed_lines(self):
        self.assertIsNone(parse_log("INVALID LOG ENTRY HERE"))
        self.assertIsNone(
            parse_log(
                "Jan 24 10:18:10 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC= incomplete packet missing destination"
            )
        )


if __name__ == "__main__":
    unittest.main()
