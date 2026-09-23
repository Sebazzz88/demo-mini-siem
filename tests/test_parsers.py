from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mini_siem.parsers import parse_firewall_line, parse_ssh_line, parse_web_line


class SshParserTests(unittest.TestCase):
    def test_parses_failed_login_with_invalid_user(self):
        event = parse_ssh_line(
            "Jan 15 12:00:00 lab sshd[100]: Failed password for invalid user admin "
            "from 198.51.100.77 port 45678 ssh2",
            now=datetime(2026, 1, 15, tzinfo=timezone.utc),
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.event_type, "ssh_login")
        self.assertEqual(event.ip, "198.51.100.77")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.outcome, "failed")
        self.assertEqual(event.source_port, 45678)
        self.assertEqual(event.timestamp.year, 2026)

    def test_parses_accepted_public_key_login(self):
        event = parse_ssh_line(
            "Jan 15 12:05:00 lab sshd[101]: Accepted publickey for student "
            "from 192.0.2.10 port 45210 ssh2",
            now=datetime(2026, 1, 15, tzinfo=timezone.utc),
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.username, "student")


class WebParserTests(unittest.TestCase):
    def test_parses_combined_access_log_and_optional_target_port(self):
        event = parse_web_line(
            '203.0.113.99 - - [15/Jan/2026:12:20:00 +0000] '
            '"GET /health HTTP/1.1" 400 0 "-" "Demo" dst_port=8080'
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source, "web")
        self.assertEqual(event.ip, "203.0.113.99")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.status, 400)
        self.assertEqual(event.target_port, 8080)

    def test_ignores_malformed_line(self):
        self.assertIsNone(parse_web_line("esta línea no es un access log"))


class FirewallParserTests(unittest.TestCase):
    def test_parses_ufw_connection_with_target_port(self):
        event = parse_firewall_line(
            "Jan 15 12:20:00 lab kernel: [UFW BLOCK] IN=eth0 OUT= "
            "SRC=203.0.113.99 DST=192.0.2.20 PROTO=TCP SPT=44000 DPT=8080",
            now=datetime(2026, 1, 15, tzinfo=timezone.utc),
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source, "firewall")
        self.assertEqual(event.event_type, "network_connection")
        self.assertEqual(event.ip, "203.0.113.99")
        self.assertEqual(event.target_port, 8080)
        self.assertEqual(event.outcome, "blocked")


if __name__ == "__main__":
    unittest.main()
