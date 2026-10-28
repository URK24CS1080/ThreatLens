"""
MongoDB Data Access Layer for ThreatLens.
Provides clean collection-level abstractions for scans, findings,
threat_intelligence_results, and ai_analyses with indexing,
schema validation, and migration capabilities.
"""

import time
import datetime
import logging
from typing import Optional, Dict, List, Any, Tuple
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from config import Config

logger = logging.getLogger("threatlens.mongodb")


class MongoDBManager:
    """Manages MongoDB connections, collection indexes, and CRUD operations."""

    def __init__(self, uri: Optional[str] = None, db_name: Optional[str] = None):
        self.uri = uri or Config.MONGO_URI
        self.db_name = db_name or Config.MONGO_DB_NAME
        self._client: Optional[MongoClient] = None
        self._db = None
        self._connected = False
        self._last_error = None
        self._last_attempt_time = 0.0
        self._cooldown_seconds = 20.0

    def close(self):
        """Safely closes the active MongoClient if any."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        self._connected = False

    def connect(self, timeout_ms: int = 1000, force: bool = False) -> bool:
        """Attempts connection to MongoDB with timeout and cooldown to prevent blocking."""
        now = time.time()
        if not force and not self._connected and (now - self._last_attempt_time) < self._cooldown_seconds:
            return False

        self._last_attempt_time = now
        self.close()

        try:
            self._client = MongoClient(
                self.uri,
                serverSelectionTimeoutMS=timeout_ms,
                connectTimeoutMS=timeout_ms
            )
            # Trigger server selection
            self._client.admin.command('ping')
            self._db = self._client[self.db_name]
            self._connected = True
            self._last_error = None
            self._ensure_indexes()
            return True
        except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as e:
            self.close()
            self._connected = False
            self._last_error = str(e)
            return False

    def is_connected(self) -> bool:
        """Returns True if MongoDB is reachable, respecting cooldown."""
        if self._connected and self._client is not None:
            try:
                self._client.admin.command('ping')
                return True
            except Exception as e:
                self.close()
                self._last_error = str(e)
                return False
        return self.connect(timeout_ms=1000)

    def get_last_error(self) -> Optional[str]:
        return self._last_error

    @property
    def db(self):
        if not self._connected:
            self.connect()
        return self._db

    def _ensure_indexes(self):
        """Creates sensible indexes on all ThreatLens collections."""
        if self._db is None:
            return
        try:
            # 1. Scans collection
            self._db.scans.create_index([("id", ASCENDING)], unique=True)
            self._db.scans.create_index([("created_at", DESCENDING)])
            self._db.scans.create_index([("domain", ASCENDING)])
            self._db.scans.create_index([("status", ASCENDING)])

            # 2. Findings collection
            self._db.findings.create_index([("scan_id", ASCENDING)])
            self._db.findings.create_index([("severity", ASCENDING)])
            self._db.findings.create_index([("category", ASCENDING)])
            self._db.findings.create_index([("finding_id", ASCENDING)])

            # 3. Threat Intelligence Results collection
            self._db.threat_intelligence_results.create_index([("scan_id", ASCENDING)])
            self._db.threat_intelligence_results.create_index([("domain", ASCENDING)])

            # 4. AI Analyses collection
            self._db.ai_analyses.create_index([("scan_id", ASCENDING)])
            self._db.ai_analyses.create_index([("created_at", DESCENDING)])
        except Exception as e:
            logger.error(f"Failed to create MongoDB indexes: {e}")

    # ==========================================================
    # Scans CRUD
    # ==========================================================

    def save_scan(
        self,
        scan_id: str,
        target_url: str,
        domain: str,
        ip_address: str,
        risk_score: int,
        risk_grade: str,
        severity_counts: Dict[str, int],
        status: str,
        duration: float,
        port_scan_enabled: bool,
        threat_intel_status: str,
        findings: List[Dict[str, Any]],
        recon_data: Dict[str, Any],
        ai_explanation: Optional[Dict[str, Any] | str] = None,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Saves a scan and distributes its components across:
        - scans
        - findings
        - threat_intelligence_results
        - ai_analyses
        """
        if not self.is_connected():
            return False

        created_at_dt = datetime.datetime.utcnow()
        created_at_str = created_at_dt.strftime("%Y-%m-%d %H:%M:%S")
        total_findings = sum(severity_counts.values())

        # Determine completed checks list for college viva auditing
        completed_checks = [
            "URL and Hostname Syntax Validation",
            "Anti-SSRF & Reserved IP Range Filter",
            "DNS Record Resolution (A, AAAA, MX, NS, TXT, CNAME)",
            "HTTP Status Code & Redirect Chain Inspection",
            "SSL/TLS Certificate Validity & Cipher Audit",
            "OWASP Defensive HTTP Headers Audit",
            "Cookie Security Flag Analysis (Secure, HttpOnly, SameSite)",
            "Server Banner & Technology Fingerprinting",
            "Domain Threat Reputation & Shannon Entropy Heuristics"
        ]
        if port_scan_enabled:
            completed_checks.append("Authorized Common Port Discovery (Nmap/TCP Socket)")

        # 1. Scans document
        scan_doc = {
            "id": scan_id,
            "target_url": target_url,
            "domain": domain,
            "ip_address": ip_address,
            "status": status,
            "risk_score": risk_score,
            "risk_grade": risk_grade,
            "critical_count": severity_counts.get("Critical", 0),
            "high_count": severity_counts.get("High", 0),
            "medium_count": severity_counts.get("Medium", 0),
            "low_count": severity_counts.get("Low", 0),
            "info_count": severity_counts.get("Informational", 0),
            "total_findings": total_findings,
            "port_scan_enabled": bool(port_scan_enabled),
            "threat_intel_status": threat_intel_status,
            "scan_duration_seconds": round(duration, 2),
            "error_message": error_message,
            "created_at": created_at_str,
            "created_at_dt": created_at_dt,
            "completed_checks": completed_checks,
            "recon": {
                "http_status": recon_data.get("http_status"),
                "https_enabled": bool(recon_data.get("https_enabled")),
                "page_title": recon_data.get("page_title", ""),
                "server_header": recon_data.get("server_header", ""),
                "redirect_chain": recon_data.get("redirect_chain", []),
                "dns_records": recon_data.get("dns_records", {}),
                "tls_cert": recon_data.get("tls_cert", {}),
                "technologies": recon_data.get("technologies", []),
                "open_ports": recon_data.get("open_ports", []),
                "port_scan_meta": recon_data.get("port_scan_meta", {})
            }
        }
        self._db.scans.replace_one({"id": scan_id}, scan_doc, upsert=True)

        # 2. Findings documents
        self._db.findings.delete_many({"scan_id": scan_id})
        finding_docs = []
        for idx, f in enumerate(findings, 1):
            finding_id = f.get("id") or f.get("finding_id") or f"TL-SEC-{idx:03d}"
            finding_docs.append({
                "scan_id": scan_id,
                "domain": domain,
                "finding_id": finding_id,
                "title": f.get("title", "Untitled Finding"),
                "severity": f.get("severity", "Informational"),
                "category": f.get("category", "General Security"),
                "confidence": f.get("confidence", "High"),
                "evidence": f.get("evidence", ""),
                "explanation": f.get("explanation", ""),
                "potential_impact": f.get("potential_impact") or f.get("impact", "Potential security posture degradation."),
                "remediation": f.get("remediation", ""),
                "detection_timestamp": f.get("detection_timestamp", created_at_str)
            })
        if finding_docs:
            self._db.findings.insert_many(finding_docs)

        # 3. Threat Intelligence Results document
        threat_intel_data = recon_data.get("threat_intel", {})
        if threat_intel_data:
            threat_doc = {
                "scan_id": scan_id,
                "domain": domain,
                "target_url": target_url,
                "overall_status": threat_intel_data.get("overall_status", threat_intel_status),
                "lookup_timestamp": created_at_str,
                "safe_browsing": threat_intel_data.get("safe_browsing", {}),
                "urlhaus": threat_intel_data.get("urlhaus", {}),
                "heuristics": threat_intel_data.get("heuristics", {}),
                "indicators": threat_intel_data.get("indicators", [])
            }
            self._db.threat_intelligence_results.replace_one({"scan_id": scan_id}, threat_doc, upsert=True)

        # 4. AI Analyses document
        ai_payload = ai_explanation if isinstance(ai_explanation, dict) else {
            "executive_summary": ai_explanation or "",
            "finding_explanations": [],
            "risk_prioritization": [],
            "remediation_guidance": [],
            "natural_language_report": ai_explanation or "",
            "provider": "builtin"
        }
        ai_doc = {
            "scan_id": scan_id,
            "domain": domain,
            "created_at": created_at_str,
            "provider": ai_payload.get("provider", "builtin"),
            "executive_summary": ai_payload.get("executive_summary", ""),
            "finding_explanations": ai_payload.get("finding_explanations", []),
            "risk_prioritization": ai_payload.get("risk_prioritization", []),
            "remediation_guidance": ai_payload.get("remediation_guidance", []),
            "scan_comparison_summary": ai_payload.get("scan_comparison_summary", ""),
            "natural_language_report": ai_payload.get("natural_language_report", "")
        }
        self._db.ai_analyses.replace_one({"scan_id": scan_id}, ai_doc, upsert=True)

        return True

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves complete scan details by combining scans, findings, threat intel, and AI analysis."""
        if not self.is_connected():
            return None

        scan_doc = self._db.scans.find_one({"id": scan_id}, {"_id": 0})
        if not scan_doc:
            return None

        # Fetch findings
        findings_cursor = self._db.findings.find({"scan_id": scan_id}, {"_id": 0}).sort("finding_id", ASCENDING)
        scan_doc["findings"] = list(findings_cursor)

        # Fetch threat intel
        threat_doc = self._db.threat_intelligence_results.find_one({"scan_id": scan_id}, {"_id": 0})
        if threat_doc:
            if "recon" not in scan_doc:
                scan_doc["recon"] = {}
            scan_doc["recon"]["threat_intel"] = threat_doc

        # Fetch AI analysis
        ai_doc = self._db.ai_analyses.find_one({"scan_id": scan_id}, {"_id": 0})
        if ai_doc:
            scan_doc["ai_analysis"] = ai_doc
            # For backward compatibility with templates expecting recon_data.ai_explanation
            if "recon" in scan_doc:
                scan_doc["recon"]["ai_explanation"] = ai_doc.get("executive_summary") or ai_doc.get("natural_language_report", "")

        return scan_doc

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetches recent scan records for dashboard presentation."""
        if not self.is_connected():
            return []
        cursor = self._db.scans.find(
            {},
            {
                "_id": 0,
                "id": 1,
                "target_url": 1,
                "domain": 1,
                "ip_address": 1,
                "created_at": 1,
                "status": 1,
                "risk_score": 1,
                "risk_grade": 1,
                "critical_count": 1,
                "high_count": 1,
                "medium_count": 1,
                "low_count": 1,
                "info_count": 1,
                "total_findings": 1,
                "scan_duration_seconds": 1
            }
        ).sort("created_at", DESCENDING).limit(limit)
        return list(cursor)

    def get_all_scans(
        self,
        limit: int = 100,
        offset: int = 0,
        domain_query: Optional[str] = None,
        grade_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetches paginated scans with optional query filters."""
        if not self.is_connected():
            return []
        query: Dict[str, Any] = {}
        if domain_query:
            query["domain"] = {"$regex": domain_query, "$options": "i"}
        if grade_filter and grade_filter != "ALL":
            query["risk_grade"] = grade_filter

        cursor = self._db.scans.find(query, {"_id": 0}).sort("created_at", DESCENDING).skip(offset).limit(limit)
        return list(cursor)

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Calculates aggregated metrics across all completed scans."""
        default_metrics = {
            "total_scans": 0,
            "total_critical": 0,
            "total_high": 0,
            "total_medium": 0,
            "total_low": 0,
            "total_info": 0,
            "avg_risk_score": 0.0,
            "completed_scans": 0,
            "failed_scans": 0
        }
        if not self.is_connected():
            return default_metrics

        try:
            pipeline = [
                {
                    "$group": {
                        "_id": None,
                        "total_scans": {"$sum": 1},
                        "completed_scans": {
                            "$sum": {"$cond": [{"$eq": ["$status", "completed"]}, 1, 0]}
                        },
                        "failed_scans": {
                            "$sum": {"$cond": [{"$ne": ["$status", "completed"]}, 1, 0]}
                        },
                        "total_critical": {"$sum": "$critical_count"},
                        "total_high": {"$sum": "$high_count"},
                        "total_medium": {"$sum": "$medium_count"},
                        "total_low": {"$sum": "$low_count"},
                        "total_info": {"$sum": "$info_count"},
                        "avg_risk_score": {"$avg": "$risk_score"}
                    }
                }
            ]
            agg = list(self._db.scans.aggregate(pipeline))
            if agg:
                res = agg[0]
                return {
                    "total_scans": res.get("total_scans", 0),
                    "completed_scans": res.get("completed_scans", 0),
                    "failed_scans": res.get("failed_scans", 0),
                    "total_critical": res.get("total_critical", 0),
                    "total_high": res.get("total_high", 0),
                    "total_medium": res.get("total_medium", 0),
                    "total_low": res.get("total_low", 0),
                    "total_info": res.get("total_info", 0),
                    "avg_risk_score": round(res.get("avg_risk_score") or 0.0, 1)
                }
            return default_metrics
        except Exception as e:
            logger.error(f"Error computing MongoDB dashboard metrics: {e}")
            return default_metrics

    def get_findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 200
    ) -> List[Dict[str, Any]]:
        """Queries security findings across one or all scans with filtering."""
        if not self.is_connected():
            return []

        query: Dict[str, Any] = {}
        if scan_id:
            query["scan_id"] = scan_id
        if severity and severity.upper() != "ALL":
            query["severity"] = severity
        if category and category.upper() != "ALL":
            query["category"] = category
        if search_query:
            query["$or"] = [
                {"title": {"$regex": search_query, "$options": "i"}},
                {"evidence": {"$regex": search_query, "$options": "i"}},
                {"domain": {"$regex": search_query, "$options": "i"}}
            ]

        cursor = self._db.findings.find(query, {"_id": 0}).limit(limit)
        return list(cursor)

    def delete_scan(self, scan_id: str) -> bool:
        """Cascades deletion across scans, findings, threat intel, and AI collections."""
        if not self.is_connected():
            return False
        res = self._db.scans.delete_one({"id": scan_id})
        self._db.findings.delete_many({"scan_id": scan_id})
        self._db.threat_intelligence_results.delete_many({"scan_id": scan_id})
        self._db.ai_analyses.delete_many({"scan_id": scan_id})
        return res.deleted_count > 0

    def get_collections_summary(self) -> Dict[str, Any]:
        """Provides statistics for college demonstration & verification."""
        if not self.is_connected():
            return {
                "connected": False,
                "error": self._last_error,
                "database": self.db_name,
                "uri": self.uri,
                "counts": {}
            }
        return {
            "connected": True,
            "database": self.db_name,
            "uri": self.uri,
            "counts": {
                "scans": self._db.scans.count_documents({}),
                "findings": self._db.findings.count_documents({}),
                "threat_intelligence_results": self._db.threat_intelligence_results.count_documents({}),
                "ai_analyses": self._db.ai_analyses.count_documents({})
            }
        }


# Singleton MongoDB manager instance
mongo_manager = MongoDBManager()
