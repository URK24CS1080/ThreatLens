"""
Unit tests for Authorized Port and Service Discovery.
"""

import unittest
from services.port_scanner import (
    perform_authorized_port_scan, is_nmap_available, scan_ports_via_socket
)
from services.ssrf_guard import SSRFValidationError


class TestPortScanner(unittest.TestCase):

    def test_skip_when_not_authorized(self):
        """Ensure scanning is skipped if user does not certify authorization."""
        res = perform_authorized_port_scan(
            target_host="example.com",
            target_ip="93.184.216.34",
            user_authorized=False
        )
        self.assertFalse(res["enabled"])
        self.assertEqual(res["status"], "Skipped")
        self.assertIn("authorization", res["message"].lower())

    def test_block_port_scan_on_private_ip(self):
        """Ensure port scan blocks private/loopback destination IPs."""
        with self.assertRaises(SSRFValidationError):
            perform_authorized_port_scan(
                target_host="localhost",
                target_ip="127.0.0.1",
                user_authorized=True
            )

        with self.assertRaises(SSRFValidationError):
            perform_authorized_port_scan(
                target_host="router",
                target_ip="192.168.1.1",
                user_authorized=True
            )

    def test_port_sanitization_and_cap(self):
        """Ensure custom port inputs are sanitized and capped to max 25 ports."""
        res = perform_authorized_port_scan(
            target_host="93.184.216.34",
            target_ip="93.184.216.34",
            user_authorized=True,
            custom_ports=[80, 443, 99999, -5, "bad", 80, 8080]  # duplicates and invalid
        )
        self.assertTrue(res["enabled"])
        self.assertIn(80, res["ports_checked"])
        self.assertIn(443, res["ports_checked"])
        self.assertIn(8080, res["ports_checked"])
        self.assertNotIn(99999, res["ports_checked"])
        self.assertNotIn(-5, res["ports_checked"])

    def test_nmap_availability_check(self):
        """Test is_nmap_available() returns a boolean."""
        self.assertIsInstance(is_nmap_available(), bool)


if __name__ == "__main__":
    unittest.main()
