"""
Unit Tests for Day 3: Security Event Analysis
============================================
Verifies that the Day 3 analyzer module computes accurate security statistics
and aggregates normalized events safely without crashes or side effects.

Test Criteria:
1. Source IP counting works.
2. Destination port counting works.
3. Protocol statistics work.
4. Action statistics work.
5. Unique source IP counting works.
6. Event type statistics work.
7. Empty event list is handled safely.
8. Missing optional fields do not crash the analyzer.
9. Malformed / non-dict objects in event lists are handled safely.
10. Source IP to destination ports mapping works.
"""

import unittest
import sys
import os

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from analyzer import (
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


class TestDay3SecurityEventAnalysis(unittest.TestCase):

    def setUp(self):
        self.sample_events = [
            {
                "timestamp": "Jan 24 10:15:30",
                "event_type": "network",
                "source": "ufw",
                "src_ip": "10.0.0.5",
                "dst_ip": "192.168.1.1",
                "src_port": 54321,
                "dst_port": 22,
                "protocol": "TCP",
                "action": "BLOCK",
                "username": None,
                "raw_log": "raw ufw log 1",
            },
            {
                "timestamp": "Jan 24 10:16:00",
                "event_type": "network",
                "source": "ufw",
                "src_ip": "10.0.0.5",
                "dst_ip": "192.168.1.1",
                "src_port": 54322,
                "dst_port": 80,
                "protocol": "TCP",
                "action": "BLOCK",
                "username": None,
                "raw_log": "raw ufw log 2",
            },
            {
                "timestamp": "Jan 24 10:16:30",
                "event_type": "network",
                "source": "ufw",
                "src_ip": "10.0.0.8",
                "dst_ip": "192.168.1.1",
                "src_port": 12345,
                "dst_port": 53,
                "protocol": "UDP",
                "action": "ALLOW",
                "username": None,
                "raw_log": "raw ufw log 3",
            },
            {
                "timestamp": "Jan 24 10:17:00",
                "event_type": "authentication",
                "source": "linux_auth",
                "src_ip": "10.0.0.5",
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": None,
                "action": "FAILED_LOGIN",
                "username": "admin",
                "raw_log": "raw auth log 1",
            },
            {
                "timestamp": "Jan 24 10:18:00",
                "event_type": "authentication",
                "source": "linux_auth",
                "src_ip": None,  # Sudo event without IP
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": None,
                "action": "SUDO_COMMAND",
                "username": "root",
                "raw_log": "raw auth log 2",
            },
        ]

    # 1. Source IP counting works
    def test_source_ip_counting_works(self):
        top_ips = get_top_source_ips(self.sample_events)
        self.assertEqual(top_ips[0], ("10.0.0.5", 3))
        self.assertEqual(top_ips[1], ("10.0.0.8", 1))

        # Test with top_n limit
        top_1 = get_top_source_ips(self.sample_events, top_n=1)
        self.assertEqual(len(top_1), 1)
        self.assertEqual(top_1[0], ("10.0.0.5", 3))

    # 2. Destination port counting works
    def test_destination_port_counting_works(self):
        top_ports = get_top_destination_ports(self.sample_events)
        port_dict = dict(top_ports)
        self.assertEqual(port_dict[22], 1)
        self.assertEqual(port_dict[80], 1)
        self.assertEqual(port_dict[53], 1)
        # Authentication events have dst_port None and should not be counted
        self.assertNotIn(None, port_dict)

        # Test with top_n limit
        top_2 = get_top_destination_ports(self.sample_events, top_n=2)
        self.assertEqual(len(top_2), 2)

    # 3. Protocol statistics work
    def test_protocol_statistics_work(self):
        stats = get_protocol_stats(self.sample_events)
        self.assertEqual(stats, {"TCP": 2, "UDP": 1})
        self.assertNotIn(None, stats)

    # 4. Action statistics work
    def test_action_statistics_work(self):
        stats = get_action_stats(self.sample_events)
        self.assertEqual(
            stats,
            {
                "BLOCK": 2,
                "ALLOW": 1,
                "FAILED_LOGIN": 1,
                "SUDO_COMMAND": 1,
            },
        )

    # 5. Unique source IP counting works
    def test_unique_source_ip_counting_works(self):
        unique_ips = get_unique_source_ips(self.sample_events)
        self.assertIsInstance(unique_ips, set)
        self.assertEqual(unique_ips, {"10.0.0.5", "10.0.0.8"})

        count = get_unique_source_ip_count(self.sample_events)
        self.assertEqual(count, 2)

    # 6. Event type statistics work
    def test_event_type_statistics_work(self):
        type_stats = get_event_type_stats(self.sample_events)
        self.assertEqual(type_stats, {"network": 3, "authentication": 2})

    # 7. Empty event list is handled safely
    def test_empty_event_list_handled_safely(self):
        self.assertEqual(get_top_source_ips([]), [])
        self.assertEqual(get_top_destination_ports([]), [])
        self.assertEqual(get_protocol_stats([]), {})
        self.assertEqual(get_action_stats([]), {})
        self.assertEqual(get_unique_source_ips([]), set())
        self.assertEqual(get_unique_source_ip_count([]), 0)
        self.assertEqual(get_event_type_stats([]), {})
        self.assertEqual(get_ports_per_source_ip([]), {})

        # None input should also be safe
        self.assertEqual(get_top_source_ips(None), [])
        self.assertEqual(get_top_destination_ports(None), [])
        self.assertEqual(get_protocol_stats(None), {})
        self.assertEqual(get_action_stats(None), {})
        self.assertEqual(get_unique_source_ips(None), set())
        self.assertEqual(get_unique_source_ip_count(None), 0)
        self.assertEqual(get_event_type_stats(None), {})
        self.assertEqual(get_ports_per_source_ip(None), {})

    # 8. Missing optional fields do not crash the analyzer
    def test_missing_optional_fields_do_not_crash(self):
        events_with_missing_fields = [
            {"timestamp": "Jan 24 10:00:00", "action": "BLOCK"},  # Missing all optional fields
            {"timestamp": "Jan 24 10:01:00", "event_type": "network", "src_ip": "1.1.1.1"},
            {},  # Empty dictionary
        ]

        self.assertEqual(get_top_source_ips(events_with_missing_fields), [("1.1.1.1", 1)])
        self.assertEqual(get_top_destination_ports(events_with_missing_fields), [])
        self.assertEqual(get_protocol_stats(events_with_missing_fields), {})
        self.assertEqual(get_action_stats(events_with_missing_fields), {"BLOCK": 1})
        self.assertEqual(get_unique_source_ips(events_with_missing_fields), {"1.1.1.1"})
        self.assertEqual(get_unique_source_ip_count(events_with_missing_fields), 1)
        self.assertEqual(get_event_type_stats(events_with_missing_fields), {"network": 1})
        self.assertEqual(get_ports_per_source_ip(events_with_missing_fields), {})

    # 9. Non-dict / malformed objects in list are handled safely
    def test_malformed_objects_in_list_handled_safely(self):
        dirty_events = [
            None,
            "corrupted string",
            12345,
            {"src_ip": "192.168.1.50", "dst_port": 443, "protocol": "TCP", "action": "ALLOW", "event_type": "network"},
            ["nested", "list"],
        ]

        self.assertEqual(get_top_source_ips(dirty_events), [("192.168.1.50", 1)])
        self.assertEqual(get_top_destination_ports(dirty_events), [(443, 1)])
        self.assertEqual(get_protocol_stats(dirty_events), {"TCP": 1})
        self.assertEqual(get_action_stats(dirty_events), {"ALLOW": 1})
        self.assertEqual(get_unique_source_ips(dirty_events), {"192.168.1.50"})
        self.assertEqual(get_unique_source_ip_count(dirty_events), 1)
        self.assertEqual(get_event_type_stats(dirty_events), {"network": 1})

    # 10. Source IP to destination ports mapping works
    def test_ports_per_source_ip(self):
        port_mapping = get_ports_per_source_ip(self.sample_events)
        self.assertEqual(port_mapping["10.0.0.5"], {22, 80})
        self.assertEqual(port_mapping["10.0.0.8"], {53})
        # Events without src_ip or dst_port are not included
        self.assertNotIn(None, port_mapping)

    # 11. Consolidated report and analyze_events work
    def test_analyze_events_and_report(self):
        summary = analyze_events(self.sample_events)
        self.assertEqual(summary["total_events"], 5)
        self.assertEqual(summary["unique_source_ip_count"], 2)
        self.assertEqual(summary["top_source_ips"][0], ("10.0.0.5", 3))

        report = format_analysis_report(self.sample_events)
        self.assertIn("THREATLENS DAY 3 ANALYSIS", report)
        self.assertIn("10.0.0.5 -> 3 events", report)
        self.assertIn("Unique Source IPs:\n2", report)


if __name__ == "__main__":
    unittest.main()
