"""
Unit Tests for Day 2: Log Normalization
=======================================
Verifies that the Day 2 normalizer properly converts disparate parsed security
logs into a unified canonical schema according to SOC requirements.

Test Criteria:
1. Valid firewall event is normalized correctly.
2. Missing optional fields become None.
3. Invalid input returns None.
4. Raw log is preserved.
5. Authentication event can be normalized if implemented.
"""

import unittest
import sys
import os

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from normalizer import (
    NORMALIZED_FIELDS,
    normalize_firewall_event,
    normalize_auth_event,
    normalize_event,
    validate_normalized_event,
)


class TestDay2LogNormalization(unittest.TestCase):

    def setUp(self):
        self.sample_firewall_parsed = {
            "timestamp": "Jan 24 10:15:30",
            "action": "BLOCK",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "TCP",
            "src_port": 54321,
            "dst_port": 22,
        }
        self.sample_raw_firewall_log = (
            "Jan 24 10:15:30 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC= "
            "SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22"
        )

    # 1. Valid firewall event is normalized correctly
    def test_valid_firewall_event_normalized_correctly(self):
        normalized = normalize_firewall_event(
            self.sample_firewall_parsed, raw_log=self.sample_raw_firewall_log
        )

        self.assertIsNotNone(normalized)
        # Ensure all expected fields from the canonical schema exist
        for key in NORMALIZED_FIELDS:
            self.assertIn(key, normalized)

        self.assertEqual(normalized["timestamp"], "Jan 24 10:15:30")
        self.assertEqual(normalized["event_type"], "network")
        self.assertEqual(normalized["source"], "ufw")
        self.assertEqual(normalized["src_ip"], "192.168.1.10")
        self.assertEqual(normalized["dst_ip"], "192.168.1.1")
        self.assertEqual(normalized["protocol"], "TCP")
        self.assertEqual(normalized["src_port"], 54321)
        self.assertEqual(normalized["dst_port"], 22)
        self.assertEqual(normalized["action"], "BLOCK")
        self.assertIsNone(normalized["username"])
        self.assertEqual(normalized["raw_log"], self.sample_raw_firewall_log)

    # 2. Missing optional fields become None
    def test_missing_optional_fields_become_none(self):
        minimal_parsed = {
            "timestamp": "Jan 24 10:17:01",
            "action": "ALLOW",
            # Missing: src_ip, dst_ip, src_port, dst_port, protocol, username
        }
        normalized = normalize_firewall_event(minimal_parsed)

        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["timestamp"], "Jan 24 10:17:01")
        self.assertEqual(normalized["action"], "ALLOW")
        self.assertEqual(normalized["event_type"], "network")
        self.assertIsNone(normalized["src_ip"])
        self.assertIsNone(normalized["dst_ip"])
        self.assertIsNone(normalized["src_port"])
        self.assertIsNone(normalized["dst_port"])
        self.assertIsNone(normalized["protocol"])
        self.assertIsNone(normalized["username"])
        self.assertIsNone(normalized["raw_log"])

    # 3. Invalid input returns None
    def test_invalid_input_returns_none(self):
        # Non-dict inputs
        self.assertIsNone(normalize_firewall_event(None))
        self.assertIsNone(normalize_firewall_event("string input"))
        self.assertIsNone(normalize_firewall_event(12345))
        self.assertIsNone(normalize_firewall_event(["list", "not", "dict"]))

        # Missing mandatory 'timestamp'
        self.assertIsNone(normalize_firewall_event({"action": "BLOCK"}))

        # Missing mandatory 'action'
        self.assertIsNone(normalize_firewall_event({"timestamp": "Jan 24 10:15:30"}))

        # Empty string values for required fields
        self.assertIsNone(normalize_firewall_event({"timestamp": "", "action": "BLOCK"}))
        self.assertIsNone(normalize_firewall_event({"timestamp": "Jan 24 10:15:30", "action": "   "}))

    # 4. Raw log is preserved
    def test_raw_log_is_preserved(self):
        raw_text = "Jan 24 10:15:30 raw syslog firewall entry"

        # Explicit parameter
        norm1 = normalize_firewall_event(self.sample_firewall_parsed, raw_log=raw_text)
        self.assertEqual(norm1["raw_log"], raw_text)

        # Dictionary-embedded raw_log
        parsed_with_raw = dict(self.sample_firewall_parsed)
        parsed_with_raw["raw_log"] = raw_text
        norm2 = normalize_firewall_event(parsed_with_raw)
        self.assertEqual(norm2["raw_log"], raw_text)

    # 5. Authentication event can be normalized if implemented
    def test_auth_event_normalized_correctly(self):
        auth_parsed = {
            "timestamp": "Jan 24 10:20:01",
            "action": "FAILED_LOGIN",
            "username": "admin",
            "src_ip": "10.0.0.5",
        }
        raw_auth_log = "Jan 24 10:20:01 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 45123 ssh2"

        normalized = normalize_auth_event(auth_parsed, raw_log=raw_auth_log)

        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["timestamp"], "Jan 24 10:20:01")
        self.assertEqual(normalized["event_type"], "authentication")
        self.assertEqual(normalized["source"], "linux_auth")
        self.assertEqual(normalized["username"], "admin")
        self.assertEqual(normalized["src_ip"], "10.0.0.5")
        self.assertEqual(normalized["action"], "FAILED_LOGIN")
        self.assertEqual(normalized["raw_log"], raw_auth_log)

        # Fields absent in authentication logs must be None
        self.assertIsNone(normalized["dst_ip"])
        self.assertIsNone(normalized["src_port"])
        self.assertIsNone(normalized["dst_port"])
        self.assertIsNone(normalized["protocol"])

    def test_dispatcher_normalize_event(self):
        # Network event via dispatcher
        net_norm = normalize_event(self.sample_firewall_parsed, event_type="network")
        self.assertIsNotNone(net_norm)
        self.assertEqual(net_norm["event_type"], "network")

        # Auth event via dispatcher
        auth_parsed = {"timestamp": "Jan 24 10:20:01", "action": "SUCCESSFUL_LOGIN", "username": "analyst"}
        auth_norm = normalize_event(auth_parsed, event_type="authentication")
        self.assertIsNotNone(auth_norm)
        self.assertEqual(auth_norm["event_type"], "authentication")

        # Unknown event type
        self.assertIsNone(normalize_event(self.sample_firewall_parsed, event_type="unknown_type"))


if __name__ == "__main__":
    unittest.main()
