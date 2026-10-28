"""
Unit tests for SSRF Guard and URL validation.
"""

import unittest
from services.ssrf_guard import validate_target_url, is_ip_address_blocked, SSRFValidationError


class TestSSRFGuard(unittest.TestCase):
    
    def test_block_loopback_and_localhost(self):
        """Ensure localhost, 127.0.0.1, and loopback are blocked."""
        loopback_urls = [
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://localhost:5000",
            "https://127.1.2.3"
        ]
        for url in loopback_urls:
            with self.assertRaises(SSRFValidationError, msg=f"Should block {url}"):
                validate_target_url(url)

    def test_block_private_networks(self):
        """Ensure RFC 1918 private IP ranges are blocked."""
        private_ips = [
            "http://10.0.0.1",
            "http://10.254.1.1:8000",
            "http://172.16.0.1",
            "http://172.31.255.254",
            "http://192.168.1.1",
            "http://192.168.100.50"
        ]
        for url in private_ips:
            with self.assertRaises(SSRFValidationError, msg=f"Should block {url}"):
                validate_target_url(url)

    def test_block_cloud_metadata_and_link_local(self):
        """Ensure cloud metadata endpoints (169.254.169.254) are blocked."""
        metadata_urls = [
            "http://169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.1.1"
        ]
        for url in metadata_urls:
            with self.assertRaises(SSRFValidationError, msg=f"Should block {url}"):
                validate_target_url(url)

    def test_reject_unsupported_schemes(self):
        """Ensure file://, ftp://, and non-http schemes are blocked."""
        bad_schemes = [
            "file:///etc/passwd",
            "ftp://files.example.com",
            "gopher://example.com",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        ]
        for url in bad_schemes:
            with self.assertRaises(SSRFValidationError, msg=f"Should block {url}"):
                validate_target_url(url)

    def test_dns_failure_handling(self):
        """Ensure nonexistent domains fail gracefully with SSRFValidationError."""
        with self.assertRaises(SSRFValidationError):
            validate_target_url("https://nonexistent-fake-domain-xyz-123456789.invalid")

    def test_is_ip_address_blocked_helper(self):
        """Test specific IP address classification."""
        blocked, reason = is_ip_address_blocked("127.0.0.1")
        self.assertTrue(blocked)
        self.assertIn("Loopback", reason)

        blocked, reason = is_ip_address_blocked("10.10.10.10")
        self.assertTrue(blocked)
        self.assertIn("Private", reason)

        blocked, reason = is_ip_address_blocked("8.8.8.8")
        self.assertFalse(blocked)
        self.assertIn("public", reason)


if __name__ == "__main__":
    unittest.main()
