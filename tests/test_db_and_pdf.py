"""
Unit tests for SQLite Database persistence and PDF report generation.
"""

import unittest
import uuid
from pathlib import Path
from database.db import (
    init_db, save_scan_result, get_scan, get_recent_scans,
    get_dashboard_metrics, delete_scan
)
from services.report_generator import generate_pdf_report
from config import Config


class TestDatabaseAndPDF(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_database_crud_operations(self):
        """Test inserting, querying, and deleting scan records in SQLite."""
        test_id = str(uuid.uuid4())
        
        findings = [
            {
                "title": "Missing Content-Security-Policy",
                "severity": "Medium",
                "category": "HTTP Security Headers",
                "evidence": "CSP Header absent",
                "explanation": "Allows script injection",
                "remediation": "Add CSP header"
            }
        ]
        
        recon = {
            "http_status": 200,
            "https_enabled": True,
            "page_title": "Test Domain",
            "server_header": "nginx",
            "redirect_chain": [],
            "dns_records": {"A": ["93.184.216.34"]},
            "tls_cert": {"has_tls": True, "issuer": "Let's Encrypt", "valid_to": "2026-12-31"},
            "technologies": [{"name": "Nginx", "category": "Web Server"}],
            "open_ports": [{"port": 443, "service": "HTTPS", "state": "open"}],
            "threat_intel": {"overall_status": "Clean", "providers": {}}
        }

        # 1. Save scan
        save_scan_result(
            scan_id=test_id,
            target_url="https://test-domain.org",
            domain="test-domain.org",
            ip_address="93.184.216.34",
            risk_score=92,
            risk_grade="A",
            severity_counts={"Medium": 1, "Critical": 0, "High": 0, "Low": 0, "Informational": 0},
            status="completed",
            duration=1.45,
            port_scan_enabled=True,
            threat_intel_status="Clean",
            findings=findings,
            recon_data=recon,
            ai_explanation="Test educational summary."
        )

        # 2. Retrieve scan
        retrieved = get_scan(test_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["domain"], "test-domain.org")
        self.assertEqual(retrieved["risk_score"], 92)
        self.assertEqual(len(retrieved["findings"]), 1)
        self.assertEqual(retrieved["findings"][0]["title"], "Missing Content-Security-Policy")

        # 3. Test Dashboard metrics
        metrics = get_dashboard_metrics()
        self.assertGreaterEqual(metrics["total_scans"], 1)

        # 4. Test PDF Generation
        pdf_path = Config.REPORTS_DIR / f"{test_id}_test.pdf"
        generate_pdf_report(retrieved, pdf_path)
        self.assertTrue(pdf_path.exists())
        self.assertGreater(pdf_path.stat().st_size, 1000)

        with open(pdf_path, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")

        # Clean up PDF file
        pdf_path.unlink()

        # 5. Delete scan record
        deleted = delete_scan(test_id)
        self.assertTrue(deleted)
        self.assertIsNone(get_scan(test_id))


if __name__ == "__main__":
    unittest.main()
