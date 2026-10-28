"""
Database Unified Access Layer for ThreatLens.
Handles MongoDB as primary persistence engine with graceful SQLite compatibility,
automatic schema initialization, and SQLite-to-MongoDB migration.
"""

import json
import sqlite3
import logging
from pathlib import Path
from typing import Optional, Dict, List, Any
from contextlib import contextmanager

from config import Config
from database.mongo_db import mongo_manager

logger = logging.getLogger("threatlens.database")

DB_FILE = Config.DATABASE_PATH
SCHEMA_FILE = Config.BASE_DIR / "database" / "schema.sql"


@contextmanager
def get_sqlite_connection():
    """Context manager for SQLite database connection."""
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initializes SQLite schema and MongoDB connection."""
    # Ensure SQLite directory and schema exist
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with get_sqlite_connection() as conn:
            with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
                conn.executescript(f.read())
            conn.commit()
    except Exception as e:
        logger.error(f"Error initializing SQLite database: {e}")

    # Attempt MongoDB connection
    mongo_connected = mongo_manager.connect()
    if mongo_connected:
        logger.info("MongoDB connected successfully. ThreatLens using MongoDB as primary store.")
        # Auto-migrate any existing SQLite records into MongoDB if MongoDB is empty
        migrate_sqlite_to_mongo()
    else:
        logger.warning(
            f"MongoDB connection failed ({mongo_manager.get_last_error()}). "
            "Falling back to local SQLite storage."
        )


def get_db_status() -> Dict[str, Any]:
    """Returns real-time status of database backends for the UI and Settings page."""
    mongo_info = mongo_manager.get_collections_summary()
    sqlite_scans = 0
    try:
        with get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scans")
            sqlite_scans = cursor.fetchone()[0]
    except Exception:
        pass

    return {
        "mongo_connected": mongo_info.get("connected", False),
        "mongo_uri": Config.MONGO_URI,
        "mongo_db_name": Config.MONGO_DB_NAME,
        "mongo_error": mongo_info.get("error"),
        "mongo_counts": mongo_info.get("counts", {}),
        "sqlite_scans_count": sqlite_scans,
        "active_backend": "MongoDB" if mongo_info.get("connected") else "SQLite (Fallback)"
    }


def save_scan_result(
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
):
    """
    Saves a scan record. Writes to MongoDB if connected; always writes to SQLite
    as durable backup so data is never lost.
    """
    total_findings = sum(severity_counts.values())

    # 1. Primary write to MongoDB if reachable
    if mongo_manager.is_connected():
        try:
            mongo_manager.save_scan(
                scan_id=scan_id,
                target_url=target_url,
                domain=domain,
                ip_address=ip_address,
                risk_score=risk_score,
                risk_grade=risk_grade,
                severity_counts=severity_counts,
                status=status,
                duration=duration,
                port_scan_enabled=port_scan_enabled,
                threat_intel_status=threat_intel_status,
                findings=findings,
                recon_data=recon_data,
                ai_explanation=ai_explanation,
                error_message=error_message
            )
        except Exception as e:
            logger.error(f"Failed to save scan to MongoDB: {e}")

    # 2. Always persist to SQLite for local durability & backup
    try:
        with get_sqlite_connection() as conn:
            cursor = conn.cursor()
            
            # Scans
            cursor.execute(
                """
                INSERT OR REPLACE INTO scans (
                    id, target_url, domain, ip_address, status, risk_score, risk_grade,
                    critical_count, high_count, medium_count, low_count, info_count,
                    total_findings, port_scan_enabled, threat_intel_status,
                    scan_duration_seconds, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target_url,
                    domain,
                    ip_address,
                    status,
                    risk_score,
                    risk_grade,
                    severity_counts.get("Critical", 0),
                    severity_counts.get("High", 0),
                    severity_counts.get("Medium", 0),
                    severity_counts.get("Low", 0),
                    severity_counts.get("Informational", 0),
                    total_findings,
                    1 if port_scan_enabled else 0,
                    threat_intel_status,
                    round(duration, 2),
                    error_message
                )
            )

            # Findings
            cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            for f in findings:
                cursor.execute(
                    """
                    INSERT INTO findings (
                        scan_id, title, severity, category, evidence, explanation, remediation, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        f.get("title", "Untitled Finding"),
                        f.get("severity", "Informational"),
                        f.get("category", "General Security"),
                        f.get("evidence", ""),
                        f.get("explanation", ""),
                        f.get("remediation", ""),
                        f.get("confidence", "High")
                    )
                )

            # Recon Data
            ai_text = ai_explanation if isinstance(ai_explanation, str) else (
                ai_explanation.get("executive_summary") if isinstance(ai_explanation, dict) else ""
            )
            cursor.execute(
                """
                INSERT OR REPLACE INTO recon_data (
                    scan_id, http_status, https_enabled, page_title, server_header,
                    redirect_chain_json, dns_records_json, tls_cert_json,
                    technologies_json, open_ports_json, threat_intel_json, ai_explanation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    recon_data.get("http_status"),
                    1 if recon_data.get("https_enabled") else 0,
                    recon_data.get("page_title", ""),
                    recon_data.get("server_header", ""),
                    json.dumps(recon_data.get("redirect_chain", [])),
                    json.dumps(recon_data.get("dns_records", {})),
                    json.dumps(recon_data.get("tls_cert", {})),
                    json.dumps(recon_data.get("technologies", [])),
                    json.dumps(recon_data.get("open_ports", [])),
                    json.dumps(recon_data.get("threat_intel", {})),
                    ai_text or ""
                )
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Error persisting scan to SQLite: {e}")


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full scan details from MongoDB (or SQLite if MongoDB is offline)."""
    if mongo_manager.is_connected():
        doc = mongo_manager.get_scan(scan_id)
        if doc:
            return doc

    # Fallback to SQLite
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            return None
        
        scan_dict = dict(scan_row)
        cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
        scan_dict["findings"] = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM recon_data WHERE scan_id = ?", (scan_id,))
        recon_row = cursor.fetchone()
        if recon_row:
            recon_dict = dict(recon_row)
            recon_dict["redirect_chain"] = json.loads(recon_dict.get("redirect_chain_json") or "[]")
            recon_dict["dns_records"] = json.loads(recon_dict.get("dns_records_json") or "{}")
            recon_dict["tls_cert"] = json.loads(recon_dict.get("tls_cert_json") or "{}")
            recon_dict["technologies"] = json.loads(recon_dict.get("technologies_json") or "[]")
            recon_dict["open_ports"] = json.loads(recon_dict.get("open_ports_json") or "[]")
            recon_dict["threat_intel"] = json.loads(recon_dict.get("threat_intel_json") or "{}")
            scan_dict["recon"] = recon_dict
        else:
            scan_dict["recon"] = {}

        return scan_dict


def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """Fetches recent scans from MongoDB or SQLite."""
    if mongo_manager.is_connected():
        scans = mongo_manager.get_recent_scans(limit=limit)
        if scans:
            return scans

    # SQLite fallback
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, target_url, domain, ip_address, created_at, status,
                   risk_score, risk_grade, critical_count, high_count, medium_count,
                   low_count, info_count, total_findings, scan_duration_seconds
            FROM scans
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_all_scans(
    limit: int = 100,
    offset: int = 0,
    domain_query: Optional[str] = None,
    grade_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Fetches all scans with filtering from MongoDB or SQLite."""
    if mongo_manager.is_connected():
        scans = mongo_manager.get_all_scans(limit=limit, offset=offset, domain_query=domain_query, grade_filter=grade_filter)
        if scans:
            return scans

    # SQLite fallback
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        if domain_query:
            query += " AND domain LIKE ?"
            params.append(f"%{domain_query}%")
        if grade_filter and grade_filter != "ALL":
            query += " AND risk_grade = ?"
            params.append(grade_filter)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, tuple(params))
        return [dict(row) for row in cursor.fetchall()]


def get_dashboard_metrics() -> Dict[str, Any]:
    """Computes aggregated dashboard metrics from MongoDB or SQLite."""
    if mongo_manager.is_connected():
        m = mongo_manager.get_dashboard_metrics()
        if m and m.get("total_scans", 0) > 0:
            return m

    # SQLite fallback
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT 
                COUNT(*) as total_scans,
                COALESCE(SUM(critical_count), 0) as total_critical,
                COALESCE(SUM(high_count), 0) as total_high,
                COALESCE(SUM(medium_count), 0) as total_medium,
                COALESCE(SUM(low_count), 0) as total_low,
                COALESCE(SUM(info_count), 0) as total_info,
                COALESCE(AVG(risk_score), 0) as avg_risk_score,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
                SUM(CASE WHEN status != 'completed' THEN 1 ELSE 0 END) as failed_scans
            FROM scans
            """
        )
        row = cursor.fetchone()
        metrics = dict(row) if row else {
            "total_scans": 0,
            "total_critical": 0,
            "total_high": 0,
            "total_medium": 0,
            "total_low": 0,
            "total_info": 0,
            "avg_risk_score": 0,
            "completed_scans": 0,
            "failed_scans": 0
        }
        metrics["avg_risk_score"] = round(metrics.get("avg_risk_score") or 0.0, 1)
        metrics["completed_scans"] = metrics.get("completed_scans") or 0
        metrics["failed_scans"] = metrics.get("failed_scans") or 0
        return metrics


def get_all_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    search_query: Optional[str] = None,
    limit: int = 200
) -> List[Dict[str, Any]]:
    """Retrieves filtered findings for the dedicated Security Findings page."""
    if mongo_manager.is_connected():
        results = mongo_manager.get_findings(
            scan_id=scan_id,
            severity=severity,
            category=category,
            search_query=search_query,
            limit=limit
        )
        if results:
            return results

    # SQLite fallback
    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        query = (
            "SELECT f.*, s.domain, s.target_url, s.created_at as scan_created_at "
            "FROM findings f JOIN scans s ON f.scan_id = s.id WHERE 1=1"
        )
        params = []
        if scan_id:
            query += " AND f.scan_id = ?"
            params.append(scan_id)
        if severity and severity.upper() != "ALL":
            query += " AND f.severity = ?"
            params.append(severity)
        if category and category.upper() != "ALL":
            query += " AND f.category = ?"
            params.append(category)
        if search_query:
            query += " AND (f.title LIKE ? OR f.evidence LIKE ? OR s.domain LIKE ?)"
            like_term = f"%{search_query}%"
            params.extend([like_term, like_term, like_term])

        query += " ORDER BY f.id DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, tuple(params))
        rows = [dict(r) for r in cursor.fetchall()]
        for idx, r in enumerate(rows, 1):
            if "finding_id" not in r or not r.get("finding_id"):
                r["finding_id"] = f"TL-SEC-{r.get('id', idx):03d}"
            if "potential_impact" not in r:
                r["potential_impact"] = "Potential security posture degradation."
            if "detection_timestamp" not in r:
                r["detection_timestamp"] = r.get("scan_created_at", "")
        return rows


def delete_scan(scan_id: str) -> bool:
    """Deletes scan from both MongoDB and SQLite."""
    deleted_mongo = False
    if mongo_manager.is_connected():
        deleted_mongo = mongo_manager.delete_scan(scan_id)

    with get_sqlite_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        deleted_sqlite = cursor.rowcount > 0

    return deleted_mongo or deleted_sqlite


def migrate_sqlite_to_mongo() -> int:
    """
    Migrates existing SQLite scans into MongoDB.
    Returns the count of newly migrated scans.
    """
    if not mongo_manager.is_connected():
        return 0

    migrated_count = 0
    try:
        with get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM scans")
            sqlite_ids = [row[0] for row in cursor.fetchall()]

            for scan_id in sqlite_ids:
                # Check if already present in MongoDB
                existing = mongo_manager._db.scans.find_one({"id": scan_id})
                if existing:
                    continue

                # Fetch from SQLite
                cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
                s = dict(cursor.fetchone())

                cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
                findings = [dict(f) for f in cursor.fetchall()]

                cursor.execute("SELECT * FROM recon_data WHERE scan_id = ?", (scan_id,))
                recon_row = cursor.fetchone()
                recon_data = {}
                ai_explanation = ""
                if recon_row:
                    rd = dict(recon_row)
                    recon_data = {
                        "http_status": rd.get("http_status"),
                        "https_enabled": bool(rd.get("https_enabled")),
                        "page_title": rd.get("page_title"),
                        "server_header": rd.get("server_header"),
                        "redirect_chain": json.loads(rd.get("redirect_chain_json") or "[]"),
                        "dns_records": json.loads(rd.get("dns_records_json") or "{}"),
                        "tls_cert": json.loads(rd.get("tls_cert_json") or "{}"),
                        "technologies": json.loads(rd.get("technologies_json") or "[]"),
                        "open_ports": json.loads(rd.get("open_ports_json") or "[]"),
                        "threat_intel": json.loads(rd.get("threat_intel_json") or "{}")
                    }
                    ai_explanation = rd.get("ai_explanation") or ""

                severity_counts = {
                    "Critical": s.get("critical_count", 0),
                    "High": s.get("high_count", 0),
                    "Medium": s.get("medium_count", 0),
                    "Low": s.get("low_count", 0),
                    "Informational": s.get("info_count", 0)
                }

                mongo_manager.save_scan(
                    scan_id=scan_id,
                    target_url=s.get("target_url", ""),
                    domain=s.get("domain", ""),
                    ip_address=s.get("ip_address", ""),
                    risk_score=s.get("risk_score", 0),
                    risk_grade=s.get("risk_grade", "F"),
                    severity_counts=severity_counts,
                    status=s.get("status", "completed"),
                    duration=s.get("scan_duration_seconds", 0.0),
                    port_scan_enabled=bool(s.get("port_scan_enabled")),
                    threat_intel_status=s.get("threat_intel_status", "Completed"),
                    findings=findings,
                    recon_data=recon_data,
                    ai_explanation=ai_explanation,
                    error_message=s.get("error_message")
                )
                migrated_count += 1
                logger.info(f"Migrated scan {scan_id} ({s.get('domain')}) from SQLite to MongoDB.")

    except Exception as e:
        logger.error(f"Error during SQLite to MongoDB migration: {e}")

    return migrated_count
