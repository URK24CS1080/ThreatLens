"""
Unit tests for Threat Intelligence Engine and Heuristics.
"""

import unittest
from unittest.mock import patch, MagicMock
from services.threat_intelligence import (
    check_heuristics_and_reputation,
    query_google_safe_browsing,
    query_urlhaus_api,
    perform_threat_intelligence_lookup,
    calculate_shannon_entropy
)


class TestThreatIntelligence(unittest.TestCase):

    def test_shannon_entropy(self):
        """Test entropy calculation for normal vs randomized strings."""
        low_ent = calculate_shannon_entropy("google")
        high_ent = calculate_shannon_entropy("xj7q9z2w1v0p4lk8")
        self.assertGreater(high_ent, low_ent)

    def test_punycode_homoglyph_heuristic(self):
        """Test detection of IDN homoglyphs in domain name."""
        res = check_heuristics_and_reputation("xn--apple-43a.com", "https://xn--apple-43a.com")
        self.assertTrue(res["has_indicators"])
        types = [i["type"] for i in res["indicators"]]
        self.assertIn("IDN Homograph Indicator", types)

    def test_raw_ip_heuristic(self):
        """Test detection of raw IP used as hostname."""
        res = check_heuristics_and_reputation("93.184.216.34", "http://93.184.216.34")
        self.assertTrue(res["has_indicators"])
        types = [i["type"] for i in res["indicators"]]
        self.assertIn("Raw IP Hostname", types)

    def test_google_safe_browsing_unconfigured(self):
        """When API key is missing, should return 'API Key Not Configured' gracefully."""
        with patch("services.threat_intelligence.Config.SAFE_BROWSING_API_KEY", ""):
            res = query_google_safe_browsing("https://example.com")
            self.assertEqual(res["status"], "API Key Not Configured")
            self.assertFalse(res["match_found"])

    @patch("requests.post")
    def test_urlhaus_match_found(self, mock_post):
        """Test URLhaus lookup when a malware distribution match is returned."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_count": 5,
            "firstseen": "2025-01-01"
        }
        mock_post.return_value = mock_resp

        res = query_urlhaus_api("malware-domain.com")
        self.assertEqual(res["status"], "Match Found")
        self.assertTrue(res["match_found"])
        self.assertEqual(res["threat_category"], "Malware Distribution")

    @patch("requests.post")
    def test_urlhaus_no_results(self, mock_post):
        """Test URLhaus lookup when no matches exist."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp

        res = query_urlhaus_api("safe-domain.org")
        self.assertEqual(res["status"], "No Match Found")
        self.assertFalse(res["match_found"])

    @patch("requests.post")
    def test_network_failure_not_treated_as_clean(self, mock_post):
        """Ensure network errors are reported as errors, not false 'clean' verdicts."""
        mock_post.side_effect = Exception("Connection reset by peer")

        res = query_urlhaus_api("some-site.org")
        self.assertEqual(res["status"], "Lookup Error")
        self.assertFalse(res["match_found"])


if __name__ == "__main__":
    unittest.main()
