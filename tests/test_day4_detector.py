"""
Unit Tests for Day 4: Attack Detection
======================================
Verifies that the Day 4 detector module accurately detects security threats
(Port Scanning and SSH Brute Force), enforces configurable thresholds,
avoids false positives on normal traffic, and handles edge cases safely.

Test Criteria:
1. Port scan triggers when unique ports >= threshold.
2. Port scan does not trigger below threshold.
3. SSH brute force triggers when failed attempts >= threshold.
4. SSH brute force does not trigger below threshold.
5. Different source IPs are analyzed independently.
6. Empty event list does not crash.
7. Missing optional fields do not crash.
8. Generated alerts contain evidence.
9. Normal traffic does not generate false alerts in the test data.
10. Non-dict / malformed objects in event lists are handled safely.
11. Event types are respected (non-network ignored for port scan, non-auth ignored for brute force).
12. Configurable threshold overrides work properly.
13. Alert report formatting functions work properly.
"""

import unittest
import sys
import os

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from detector import (
    PORT_SCAN_THRESHOLD,
    SSH_BRUTE_FORCE_THRESHOLD,
    detect_port_scan,
    detect_ssh_bruteforce,
    detect_events,
    format_alert,
    format_detection_report,
)


class TestDay4AttackDetection(unittest.TestCase):

    def setUp(self):
        # Sample normal events
        self.normal_events = [
            {
                "timestamp": "Jan 24 10:15:30",
                "event_type": "network",
                "source": "ufw",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "src_port": 54321,
                "dst_port": 22,
                "protocol": "TCP",
                "action": "BLOCK",
                "username": None,
                "raw_log": "log 1",
            },
            {
                "timestamp": "Jan 24 10:16:00",
                "event_type": "network",
                "source": "ufw",
                "src_ip": "10.0.0.8",
                "dst_ip": "192.168.1.1",
                "src_port": 49152,
                "dst_port": 443,
                "protocol": "TCP",
                "action": "ALLOW",
                "username": None,
                "raw_log": "log 2",
            },
            {
                "timestamp": "Jan 24 10:16:10",
                "event_type": "network",
                "source": "ufw",
                "src_ip": "10.0.0.8",
                "dst_ip": "192.168.1.1",
                "src_port": 49153,
                "dst_port": 80,
                "protocol": "TCP",
                "action": "ALLOW",
                "username": None,
                "raw_log": "log 3",
            },
            {
                "timestamp": "Jan 24 10:17:00",
                "event_type": "authentication",
                "source": "linux_auth",
                "src_ip": "192.168.1.50",
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": None,
                "action": "SUCCESSFUL_LOGIN",
                "username": "analyst",
                "raw_log": "log 4",
            },
            {
                "timestamp": "Jan 24 10:18:00",
                "event_type": "authentication",
                "source": "linux_auth",
                "src_ip": "10.0.0.5",
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": None,
                "action": "FAILED_LOGIN",
                "username": "admin",
                "raw_log": "log 5",
            },
        ]

    # 1. Port scan triggers when unique ports >= threshold
    def test_port_scan_triggers_when_ports_ge_threshold(self):
        # 5 distinct destination ports (equal to threshold 5)
        scan_events = [
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": port, "action": "BLOCK"}
            for port in [21, 22, 23, 25, 80]
        ]
        alerts = detect_port_scan(scan_events, threshold=5)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["alert_type"], "PORT_SCAN")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["source_ip"], "10.0.0.50")
        self.assertEqual(alert["description"], "Possible port scanning detected")
        self.assertEqual(alert["evidence"]["unique_destination_ports"], 5)
        self.assertEqual(alert["evidence"]["threshold"], 5)

        # 6 distinct ports (exceeding threshold 5)
        scan_events_6 = [
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": port, "action": "BLOCK"}
            for port in [21, 22, 23, 25, 80, 443]
        ]
        alerts_6 = detect_port_scan(scan_events_6, threshold=5)
        self.assertEqual(len(alerts_6), 1)
        self.assertEqual(alerts_6[0]["evidence"]["unique_destination_ports"], 6)

    # 2. Port scan does not trigger below threshold
    def test_port_scan_does_not_trigger_below_threshold(self):
        # 4 distinct destination ports (below threshold 5)
        events_4_ports = [
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": port, "action": "BLOCK"}
            for port in [22, 80, 443, 8080]
        ]
        alerts = detect_port_scan(events_4_ports, threshold=5)
        self.assertEqual(alerts, [])

        # Multiple events to the SAME port (e.g. 10 hits to port 80 = only 1 unique port)
        repeated_port_events = [
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 80, "action": "BLOCK"}
            for _ in range(10)
        ]
        alerts_repeated = detect_port_scan(repeated_port_events, threshold=5)
        self.assertEqual(alerts_repeated, [])

    # 3. SSH brute force triggers when failed attempts >= threshold
    def test_ssh_bruteforce_triggers_when_failed_attempts_ge_threshold(self):
        # 5 failed login attempts (equal to threshold 5)
        failed_logins = [
            {
                "event_type": "authentication",
                "source": "linux_auth",
                "src_ip": "10.0.0.60",
                "action": "FAILED_LOGIN",
                "username": f"user_{i}",
            }
            for i in range(5)
        ]
        alerts = detect_ssh_bruteforce(failed_logins, threshold=5)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["alert_type"], "SSH_BRUTE_FORCE")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["source_ip"], "10.0.0.60")
        self.assertEqual(alert["description"], "Possible SSH brute-force activity detected")
        self.assertEqual(alert["evidence"]["failed_attempts"], 5)
        self.assertEqual(alert["evidence"]["threshold"], 5)

        # 8 failed logins (exceeding threshold 5)
        failed_logins_8 = [
            {
                "event_type": "authentication",
                "source": "linux_auth",
                "src_ip": "10.0.0.60",
                "action": "FAILED_LOGIN",
                "username": f"user_{i}",
            }
            for i in range(8)
        ]
        alerts_8 = detect_ssh_bruteforce(failed_logins_8, threshold=5)
        self.assertEqual(len(alerts_8), 1)
        self.assertEqual(alerts_8[0]["evidence"]["failed_attempts"], 8)

    # 4. SSH brute force does not trigger below threshold
    def test_ssh_bruteforce_does_not_trigger_below_threshold(self):
        # 4 failed logins (below threshold 5)
        failed_logins_4 = [
            {
                "event_type": "authentication",
                "source": "linux_auth",
                "src_ip": "10.0.0.60",
                "action": "FAILED_LOGIN",
                "username": f"user_{i}",
            }
            for i in range(4)
        ]
        alerts = detect_ssh_bruteforce(failed_logins_4, threshold=5)
        self.assertEqual(alerts, [])

        # Successful logins must not be counted as failed attempts
        mixed_logins = [
            {
                "event_type": "authentication",
                "source": "linux_auth",
                "src_ip": "10.0.0.60",
                "action": "SUCCESSFUL_LOGIN",
                "username": "analyst",
            }
            for _ in range(10)
        ]
        alerts_success = detect_ssh_bruteforce(mixed_logins, threshold=5)
        self.assertEqual(alerts_success, [])

    # 5. Different source IPs are analyzed independently
    def test_different_source_ips_analyzed_independently(self):
        events = [
            # Attacker 1 (10.0.0.50): scans 6 ports -> should alert
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 21},
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 22},
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 23},
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 25},
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 80},
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 443},
            # Normal IP 1 (192.168.1.10): only 2 ports -> no alert
            {"event_type": "network", "src_ip": "192.168.1.10", "dst_port": 80},
            {"event_type": "network", "src_ip": "192.168.1.10", "dst_port": 443},
            # Attacker 2 (10.0.0.60): 6 failed logins -> should alert
            {"event_type": "authentication", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"},
            {"event_type": "authentication", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"},
            {"event_type": "authentication", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"},
            {"event_type": "authentication", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"},
            {"event_type": "authentication", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"},
            {"event_type": "authentication", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"},
            # Normal IP 2 (10.0.0.5): only 2 failed logins -> no alert
            {"event_type": "authentication", "src_ip": "10.0.0.5", "action": "FAILED_LOGIN"},
            {"event_type": "authentication", "src_ip": "10.0.0.5", "action": "FAILED_LOGIN"},
        ]

        port_alerts = detect_port_scan(events, threshold=5)
        self.assertEqual(len(port_alerts), 1)
        self.assertEqual(port_alerts[0]["source_ip"], "10.0.0.50")

        ssh_alerts = detect_ssh_bruteforce(events, threshold=5)
        self.assertEqual(len(ssh_alerts), 1)
        self.assertEqual(ssh_alerts[0]["source_ip"], "10.0.0.60")

        # Test combined detect_events
        all_alerts = detect_events(events, port_scan_threshold=5, ssh_threshold=5)
        alert_sources = [a["source_ip"] for a in all_alerts]
        self.assertEqual(set(alert_sources), {"10.0.0.50", "10.0.0.60"})
        self.assertNotIn("192.168.1.10", alert_sources)
        self.assertNotIn("10.0.0.5", alert_sources)

    # 6. Empty event list does not crash
    def test_empty_event_list_does_not_crash(self):
        # Empty list
        self.assertEqual(detect_port_scan([]), [])
        self.assertEqual(detect_ssh_bruteforce([]), [])
        self.assertEqual(detect_events([]), [])
        self.assertIn("No alerts triggered", format_detection_report([]))

        # None input
        self.assertEqual(detect_port_scan(None), [])
        self.assertEqual(detect_ssh_bruteforce(None), [])
        self.assertEqual(detect_events(None), [])
        self.assertIn("No alerts triggered", format_detection_report(None))

        # Non-list input
        self.assertEqual(detect_port_scan("not a list"), [])
        self.assertEqual(detect_ssh_bruteforce(12345), [])
        self.assertEqual(detect_events({}), [])

    # 7. Missing optional fields do not crash
    def test_missing_optional_fields_do_not_crash(self):
        events_with_missing_fields = [
            # Missing dst_port
            {"event_type": "network", "src_ip": "10.0.0.50"},
            # Missing src_ip
            {"event_type": "network", "dst_port": 80},
            # Missing username on auth failed login
            {"event_type": "authentication", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"},
            # Missing action on auth event
            {"event_type": "authentication", "src_ip": "10.0.0.60"},
            # Empty dictionary
            {},
            # Invalid port format (non-integer string)
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": "not_a_port"},
        ]

        # Should safely skip missing/invalid fields without raising exceptions
        port_alerts = detect_port_scan(events_with_missing_fields)
        self.assertEqual(port_alerts, [])

        ssh_alerts = detect_ssh_bruteforce(events_with_missing_fields, threshold=2)
        # Only 1 valid failed login was present for 10.0.0.60, so threshold 2 is not reached
        self.assertEqual(ssh_alerts, [])

    # 8. Generated alerts contain evidence
    def test_generated_alerts_contain_evidence(self):
        scan_events = [
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": port}
            for port in [21, 22, 23, 25, 80, 443]
        ]
        port_alerts = detect_port_scan(scan_events, threshold=5)
        self.assertEqual(len(port_alerts), 1)
        alert = port_alerts[0]

        # Check required fields
        self.assertIn("alert_type", alert)
        self.assertIn("severity", alert)
        self.assertIn("source_ip", alert)
        self.assertIn("description", alert)
        self.assertIn("evidence", alert)

        # Check evidence content
        evidence = alert["evidence"]
        self.assertIsInstance(evidence, dict)
        self.assertIn("unique_destination_ports", evidence)
        self.assertIn("threshold", evidence)
        self.assertEqual(evidence["unique_destination_ports"], 6)
        self.assertEqual(evidence["threshold"], 5)

        # SSH Brute Force evidence
        ssh_events = [
            {"event_type": "authentication", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"}
            for _ in range(7)
        ]
        ssh_alerts = detect_ssh_bruteforce(ssh_events, threshold=5)
        self.assertEqual(len(ssh_alerts), 1)
        ssh_alert = ssh_alerts[0]
        ssh_evidence = ssh_alert["evidence"]
        self.assertEqual(ssh_evidence["failed_attempts"], 7)
        self.assertEqual(ssh_evidence["threshold"], 5)

    # 9. Normal traffic does not generate false alerts in the test data
    def test_normal_traffic_does_not_generate_false_alerts(self):
        alerts = detect_events(self.normal_events)
        self.assertEqual(alerts, [])

    # 10. Non-dict / malformed objects in list handled safely
    def test_malformed_objects_handled_safely(self):
        dirty_events = [
            None,
            "corrupted line",
            12345,
            ["nested", "list"],
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 22},
        ]
        port_alerts = detect_port_scan(dirty_events, threshold=2)
        self.assertEqual(port_alerts, [])

        ssh_alerts = detect_ssh_bruteforce(dirty_events, threshold=2)
        self.assertEqual(ssh_alerts, [])

    # 11. Event types are respected
    def test_event_types_are_respected(self):
        # Auth event with dst_port should NOT be processed by detect_port_scan
        auth_with_port = [
            {"event_type": "authentication", "src_ip": "10.0.0.50", "dst_port": port, "action": "FAILED_LOGIN"}
            for port in [21, 22, 23, 25, 80, 443]
        ]
        self.assertEqual(detect_port_scan(auth_with_port, threshold=5), [])

        # Network event with action FAILED_LOGIN should NOT be processed by detect_ssh_bruteforce
        net_with_failed_action = [
            {"event_type": "network", "src_ip": "10.0.0.60", "action": "FAILED_LOGIN"}
            for _ in range(10)
        ]
        self.assertEqual(detect_ssh_bruteforce(net_with_failed_action, threshold=5), [])

    # 12. Configurable threshold overrides work properly
    def test_configurable_threshold_overrides(self):
        events = [
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 80},
            {"event_type": "network", "src_ip": "10.0.0.50", "dst_port": 443},
        ]
        # Default threshold is 5 (should not alert)
        self.assertEqual(detect_port_scan(events), [])
        # Custom threshold of 2 (should alert)
        alerts = detect_port_scan(events, threshold=2)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"]["threshold"], 2)

    # 13. Alert formatting helpers work properly
    def test_format_alert_and_report(self):
        sample_alert = {
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "source_ip": "10.0.0.50",
            "description": "Possible port scanning detected",
            "evidence": {
                "unique_destination_ports": 7,
                "threshold": 5,
            },
        }
        formatted = format_alert(sample_alert)
        self.assertIn("[ALERT]", formatted)
        self.assertIn("Type: PORT_SCAN", formatted)
        self.assertIn("Severity: HIGH", formatted)
        self.assertIn("Source IP: 10.0.0.50", formatted)
        self.assertIn("Unique destination ports: 7", formatted)
        self.assertIn("Threshold: 5", formatted)

        report = format_detection_report([sample_alert])
        self.assertIn("THREATLENS DAY 4 — ATTACK DETECTION", report)
        self.assertIn("Running detection rules...", report)
        self.assertIn("[ALERT]", report)

        # Non-dict format_alert safety
        self.assertEqual(format_alert(None), "")


if __name__ == "__main__":
    unittest.main()
