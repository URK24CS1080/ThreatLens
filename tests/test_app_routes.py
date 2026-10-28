"""
Integration tests for ThreatLens Flask application routes and view rendering.
"""

import unittest
from app import app
from database.db import init_db


class TestAppRoutes(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False  # Disable CSRF token requirement for test requests
        self.client = app.test_client()
        init_db()

    def test_dashboard_route(self):
        """GET / should render 200 with ThreatLens dashboard content."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ThreatLens", response.data)
        self.assertIn(b"Web Reconnaissance", response.data)

    def test_scan_page_route(self):
        """GET /scan should render 200 with scan configuration form."""
        response = self.client.get("/scan")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Launch Website Security Reconnaissance", response.data)
        self.assertIn(b"Authorized Port & Service Discovery", response.data)

    def test_findings_page_route(self):
        """GET /findings should render 200 with security findings explorer."""
        response = self.client.get("/findings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Findings Explorer", response.data)

    def test_ai_analysis_page_route(self):
        """GET /ai-analysis should render 200 with AI analyst view."""
        response = self.client.get("/ai-analysis")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AI Security Analyst", response.data)

    def test_compare_page_route(self):
        """GET /compare should render 200 with scan comparison view."""
        response = self.client.get("/compare")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Comparative Security Assessment", response.data)

    def test_threat_intel_route(self):
        """GET /threat-intel should render 200 with threat lookup form."""
        response = self.client.get("/threat-intel")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Threat Intelligence Database Lookup", response.data)

    def test_history_route(self):
        """GET /history should render 200 with scan history table."""
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Assessment History", response.data)

    def test_settings_route(self):
        """GET /settings should render 200 with database and API configuration."""
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"System Settings & API Configuration", response.data)
        self.assertIn(b"MongoDB Database Storage", response.data)

    def test_about_route(self):
        """GET /about should render 200 with architecture and educational guide."""
        response = self.client.get("/about")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ThreatLens Platform", response.data)
        self.assertIn(b"Modular Application Architecture", response.data)

    def test_scan_blocks_ssrf_submission(self):
        """POST /scan with a blocked localhost address must reject with 400."""
        response = self.client.post("/scan", data={"url": "http://127.0.0.1"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"prohibited", response.data.lower())

    def test_scan_blocks_private_ip_submission(self):
        """POST /scan with private IP must reject with 400."""
        response = self.client.post("/scan", data={"url": "http://192.168.1.1"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"prohibited", response.data.lower())

    def test_nonexistent_result_returns_404(self):
        """GET /results/<invalid_id> must return 404."""
        response = self.client.get("/results/fake-uuid-not-found")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
