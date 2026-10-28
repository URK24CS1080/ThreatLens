"""
Unit tests for Security Configuration Checks and Risk Scoring.
"""

import unittest
from services.security_checks import (
    check_security_headers, check_tls_posture, check_html_forms, calculate_risk_score
)


class TestSecurityChecks(unittest.TestCase):

    def test_missing_csp_and_hsts(self):
        """Test detection of missing Content-Security-Policy and HSTS."""
        empty_headers = {}
        findings = check_security_headers(empty_headers, is_https=True)
        titles = [f["title"] for f in findings]
        self.assertIn("Missing Content-Security-Policy (CSP) Header", titles)
        self.assertIn("Missing HTTP Strict Transport Security (HSTS) Header", titles)

    def test_proper_headers_no_critical_findings(self):
        """Test headers when all secure configurations are present."""
        secure_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()"
        }
        findings = check_security_headers(secure_headers, is_https=True)
        # Should have 0 findings or only informational
        severities = [f["severity"] for f in findings]
        self.assertNotIn("Critical", severities)
        self.assertNotIn("High", severities)
        self.assertNotIn("Medium", severities)

    def test_server_banner_disclosure(self):
        """Test detection of server software version disclosure."""
        leaky_headers = {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3"
        }
        findings = check_security_headers(leaky_headers, is_https=False)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("Server Banner Information Disclosure" in t for t in titles))
        self.assertTrue(any("Application Framework Disclosure" in t for t in titles))

    def test_insecure_html_form(self):
        """Test detection of form submission over unencrypted HTTP."""
        html = '<form action="http://insecure-api.com/login" method="post"><input name="pass"></form>'
        findings = check_html_forms(html, "https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "HTML Form Submits Data Over Insecure HTTP")
        self.assertEqual(findings[0]["severity"], "High")

    def test_tls_posture_evaluation(self):
        """Test TLS certificate checks for expired and expiring certificates."""
        # Expired cert
        expired_cert = {
            "has_tls": True,
            "is_expired": True,
            "valid_to": "2024-01-01 00:00 UTC",
            "days_left": -100
        }
        findings = check_tls_posture(expired_cert, is_https=True)
        titles = [f["title"] for f in findings]
        self.assertIn("SSL/TLS Certificate Has Expired", titles)

        # Self-signed cert
        self_signed_cert = {
            "has_tls": True,
            "is_self_signed": True,
            "issuer": "MyCA",
            "subject_cn": "MyCA"
        }
        findings = check_tls_posture(self_signed_cert, is_https=True)
        titles = [f["title"] for f in findings]
        self.assertIn("Self-Signed SSL/TLS Certificate Detected", titles)

    def test_risk_score_calculation(self):
        """Test the weighted deduction formula and letter grades."""
        # 1. Zero findings -> 100 A
        score, grade, counts = calculate_risk_score([])
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A")

        # 2. One Critical (-25) -> 75 C
        crit_findings = [{"severity": "Critical"}]
        score, grade, counts = calculate_risk_score(crit_findings)
        self.assertEqual(score, 75)
        self.assertEqual(grade, "C")

        # 3. Multiple findings: 1 High (-15), 1 Medium (-8), 1 Low (-3) -> 100 - 26 = 74 C
        mixed = [{"severity": "High"}, {"severity": "Medium"}, {"severity": "Low"}]
        score, grade, counts = calculate_risk_score(mixed)
        self.assertEqual(score, 74)
        self.assertEqual(grade, "C")

        # 4. Heavy findings clamped to 0 F
        heavy = [{"severity": "Critical"}] * 5
        score, grade, counts = calculate_risk_score(heavy)
        self.assertEqual(score, 0)
        self.assertEqual(grade, "F")


if __name__ == "__main__":
    unittest.main()
