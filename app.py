"""
ThreatLens: Web-Based Security Reconnaissance and AI-Powered Threat Intelligence Platform
Flask Application Controller and API Endpoints
"""

import os
import time
import uuid
import warnings
from pathlib import Path
from typing import Dict, Any, Optional

# Suppress minor external dependency warnings
warnings.filterwarnings("ignore", message="urllib3 .* or chardet .* doesn't match")

from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
)
from flask_wtf.csrf import CSRFProtect

from config import Config
from database.db import (
    init_db, save_scan_result, get_scan, get_recent_scans,
    get_dashboard_metrics, delete_scan, get_all_scans,
    get_all_findings, get_db_status
)
from database.mongo_db import mongo_manager
from services.ssrf_guard import validate_target_url, SSRFValidationError
from services.reconnaissance import perform_reconnaissance
from services.security_checks import run_security_analysis
from services.port_scanner import perform_authorized_port_scan, is_nmap_available
from services.threat_intelligence import perform_threat_intelligence_lookup
from services.ai_explainer import explain_findings
from services.comparison import compare_scans
from services.report_generator import generate_pdf_report

app = Flask(__name__)
app.config.from_object(Config)

# Enable CSRF protection across all routes
csrf = CSRFProtect(app)

# Ensure database is initialized on startup
with app.app_context():
    init_db()


@app.context_processor
def inject_global_vars():
    """Injects common template variables across all views."""
    status = get_db_status()
    return {
        "app_name": "ThreatLens",
        "app_tagline": "Security Reconnaissance & AI Threat Intelligence Platform",
        "nmap_available": is_nmap_available(),
        "has_gsb_key": bool(Config.SAFE_BROWSING_API_KEY),
        "has_gemini_key": bool(Config.GEMINI_API_KEY),
        "has_openai_key": bool(Config.OPENAI_API_KEY),
        "ai_provider": Config.AI_PROVIDER,
        "db_status": status,
        "default_ports": ", ".join(str(p) for p in Config.DEFAULT_COMMON_PORTS)
    }


# ==========================================================
# 1. Dashboard Page
# ==========================================================

@app.route("/")
def index():
    """Dashboard homepage showing genuine stored metrics, scan status, and recent activity."""
    metrics = get_dashboard_metrics()
    recent_scans = get_recent_scans(limit=8)
    recent_findings = get_all_findings(limit=5)
    return render_template(
        "index.html",
        metrics=metrics,
        recent_scans=recent_scans,
        recent_findings=recent_findings
    )


# ==========================================================
# 2. New Website Scan Page
# ==========================================================

@app.route("/scan", methods=["GET", "POST"])
def scan():
    """Scan submission form and execution coordinator."""
    if request.method == "GET":
        return render_template("scan.html")

    raw_url = request.form.get("url", "").strip()
    authorize_port_scan = bool(request.form.get("authorize_port_scan"))
    custom_ports_str = request.form.get("ports", "").strip()

    custom_ports = None
    if custom_ports_str:
        try:
            custom_ports = [
                int(p.strip()) for p in custom_ports_str.replace(";", ",").split(",")
                if p.strip().isdigit()
            ]
        except Exception:
            custom_ports = None

    # Step 1: Input & SSRF Validation
    try:
        validated_url, domain, resolved_ips = validate_target_url(raw_url)
    except SSRFValidationError as e:
        flash(str(e), "danger")
        return render_template("scan.html", target_url=raw_url), 400
    except Exception as e:
        flash(f"Invalid target URL or DNS resolution failed: {str(e)}", "danger")
        return render_template("scan.html", target_url=raw_url), 400

    scan_id = str(uuid.uuid4())
    start_time = time.time()
    primary_ip = resolved_ips[0] if resolved_ips else "Unknown"

    try:
        # Step 2: Website Reconnaissance
        recon_data = perform_reconnaissance(validated_url)
        recon_data["primary_ip"] = primary_ip

        # Step 3: Security Configuration Checks & Risk Scoring
        findings, risk_score, risk_grade, severity_counts = run_security_analysis(recon_data)

        # Step 4: Threat Intelligence Lookup
        threat_intel = perform_threat_intelligence_lookup(validated_url, domain)
        recon_data["threat_intel"] = threat_intel
        threat_status = threat_intel.get("overall_status", "Completed")

        # Step 5: Authorized Port & Service Probing
        port_scan_result = perform_authorized_port_scan(
            target_host=domain,
            target_ip=primary_ip,
            user_authorized=authorize_port_scan,
            custom_ports=custom_ports
        )
        recon_data["open_ports"] = port_scan_result.get("open_ports", [])
        recon_data["port_scan_meta"] = port_scan_result

        # Step 6: AI-Assisted Security Analysis
        ai_summary = explain_findings(domain, risk_score, risk_grade, findings, recon_data)

        # Step 7: Persist in MongoDB & SQLite
        duration = round(time.time() - start_time, 2)
        save_scan_result(
            scan_id=scan_id,
            target_url=validated_url,
            domain=domain,
            ip_address=primary_ip,
            risk_score=risk_score,
            risk_grade=risk_grade,
            severity_counts=severity_counts,
            status="completed",
            duration=duration,
            port_scan_enabled=authorize_port_scan,
            threat_intel_status=threat_status,
            findings=findings,
            recon_data=recon_data,
            ai_explanation=ai_summary
        )

        flash(f"Security reconnaissance for {domain} completed in {duration}s.", "success")
        return redirect(url_for("results", scan_id=scan_id))

    except SSRFValidationError as e:
        flash(f"Security Policy Blocked: {str(e)}", "danger")
        return render_template("scan.html", target_url=raw_url), 400
    except Exception as e:
        flash(f"Scan encountered an unexpected error: {str(e)}", "danger")
        return render_template("scan.html", target_url=raw_url), 500


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """AJAX JSON endpoint for interactive scan requests with progress status."""
    data = request.get_json(silent=True) or request.form
    raw_url = data.get("url", "").strip()
    authorize_port_scan = bool(data.get("authorize_port_scan"))

    try:
        validated_url, domain, resolved_ips = validate_target_url(raw_url)
    except SSRFValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Invalid target: {str(e)}"}), 400

    scan_id = str(uuid.uuid4())
    start_time = time.time()
    primary_ip = resolved_ips[0] if resolved_ips else "Unknown"

    try:
        recon_data = perform_reconnaissance(validated_url)
        recon_data["primary_ip"] = primary_ip

        findings, risk_score, risk_grade, severity_counts = run_security_analysis(recon_data)
        threat_intel = perform_threat_intelligence_lookup(validated_url, domain)
        recon_data["threat_intel"] = threat_intel
        threat_status = threat_intel.get("overall_status", "Completed")

        port_scan_result = perform_authorized_port_scan(
            target_host=domain,
            target_ip=primary_ip,
            user_authorized=authorize_port_scan
        )
        recon_data["open_ports"] = port_scan_result.get("open_ports", [])
        recon_data["port_scan_meta"] = port_scan_result

        ai_summary = explain_findings(domain, risk_score, risk_grade, findings, recon_data)
        duration = round(time.time() - start_time, 2)

        save_scan_result(
            scan_id=scan_id,
            target_url=validated_url,
            domain=domain,
            ip_address=primary_ip,
            risk_score=risk_score,
            risk_grade=risk_grade,
            severity_counts=severity_counts,
            status="completed",
            duration=duration,
            port_scan_enabled=authorize_port_scan,
            threat_intel_status=threat_status,
            findings=findings,
            recon_data=recon_data,
            ai_explanation=ai_summary
        )

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "redirect_url": url_for("results", scan_id=scan_id)
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ==========================================================
# 3. Scan Results Page
# ==========================================================

@app.route("/results/<scan_id>")
def results(scan_id: str):
    """Detailed scan results page showing reconnaissance, posture score, and findings."""
    scan_data = get_scan(scan_id)
    if not scan_data:
        abort(404, description="Scan record not found in database.")

    return render_template("results.html", scan=scan_data)


# ==========================================================
# 4. Security Findings Page
# ==========================================================

@app.route("/findings")
@app.route("/findings/<scan_id>")
def findings_view(scan_id: Optional[str] = None):
    """Dedicated finding browser with severity, category, and text filters."""
    severity_filter = request.args.get("severity", "ALL")
    category_filter = request.args.get("category", "ALL")
    search_query = request.args.get("q", "").strip()

    all_scans = get_all_scans(limit=50)
    findings = get_all_findings(
        scan_id=scan_id,
        severity=severity_filter,
        category=category_filter,
        search_query=search_query
    )
    
    current_scan = get_scan(scan_id) if scan_id else None

    # Determine unique categories for filter dropdown
    categories = sorted(list(set(f.get("category", "General Security") for f in findings)))
    if not categories:
        categories = ["HTTP Security Headers", "Transport Security", "Cookie Security", "Information Disclosure", "HTML Security"]

    return render_template(
        "findings.html",
        findings=findings,
        all_scans=all_scans,
        selected_scan_id=scan_id,
        current_scan=current_scan,
        severity_filter=severity_filter,
        category_filter=category_filter,
        search_query=search_query,
        categories=categories
    )


# ==========================================================
# 5. Threat Intelligence Page
# ==========================================================

@app.route("/threat-intel", methods=["GET", "POST"])
def threat_intel_view():
    """Dedicated threat intelligence lookup page querying URLhaus, Safe Browsing, and domain heuristics."""
    result = None
    target_query = ""

    if request.method == "POST":
        target_query = request.form.get("target", "").strip()
        if target_query:
            try:
                validated_url, domain, _ = validate_target_url(target_query)
                result = perform_threat_intelligence_lookup(validated_url, domain)
            except SSRFValidationError as e:
                flash(str(e), "danger")
            except Exception as e:
                flash(f"Could not complete threat lookup: {str(e)}", "danger")

    recent_scans = get_recent_scans(limit=5)
    return render_template(
        "threat_intel.html",
        result=result,
        target_query=target_query,
        recent_scans=recent_scans
    )


# ==========================================================
# 6. AI Security Analysis Page
# ==========================================================

@app.route("/ai-analysis")
@app.route("/ai-analysis/<scan_id>")
def ai_analysis_view(scan_id: Optional[str] = None):
    """Dedicated AI Security Analyst page."""
    all_scans = get_all_scans(limit=50)
    
    # If no scan_id specified, pick the most recent completed scan
    if not scan_id and all_scans:
        scan_id = all_scans[0]["id"]

    scan_data = get_scan(scan_id) if scan_id else None
    ai_doc = scan_data.get("ai_analysis") if scan_data else None

    # If AI analysis was stored as simple text, adapt it gracefully
    if scan_data and not ai_doc:
        recon = scan_data.get("recon", {})
        findings = scan_data.get("findings", [])
        ai_doc = explain_findings(
            scan_data.get("domain", ""),
            scan_data.get("risk_score", 100),
            scan_data.get("risk_grade", "A"),
            findings,
            recon
        )

    return render_template(
        "ai_analysis.html",
        scan=scan_data,
        ai=ai_doc,
        all_scans=all_scans,
        selected_scan_id=scan_id
    )


# ==========================================================
# 7. Scan History Page
# ==========================================================

@app.route("/history")
def history():
    """MongoDB-backed scan history page with search and pagination."""
    domain_query = request.args.get("q", "").strip()
    grade_filter = request.args.get("grade", "ALL")
    
    scans = get_all_scans(
        limit=100,
        domain_query=domain_query if domain_query else None,
        grade_filter=grade_filter if grade_filter != "ALL" else None
    )
    return render_template(
        "history.html",
        scans=scans,
        search_query=domain_query,
        grade_filter=grade_filter
    )


# ==========================================================
# 8. Scan Comparison Page
# ==========================================================

@app.route("/compare", methods=["GET", "POST"])
def compare_view():
    """Compares two historical scans of the same target domain."""
    all_scans = get_all_scans(limit=100)
    
    scan_id_a = request.args.get("scan_a") or request.form.get("scan_a")
    scan_id_b = request.args.get("scan_b") or request.form.get("scan_b")

    # If parameters not passed, attempt to find two scans of the same domain
    if not scan_id_a or not scan_id_b:
        if len(all_scans) >= 2:
            # Try to pick 2 scans with same domain
            domains = {}
            for s in all_scans:
                d = s["domain"]
                domains.setdefault(d, []).append(s["id"])
            
            picked = False
            for d, ids in domains.items():
                if len(ids) >= 2:
                    scan_id_a = ids[1]  # older baseline
                    scan_id_b = ids[0]  # newer follow-up
                    picked = True
                    break
            
            if not picked:
                scan_id_a = all_scans[1]["id"]
                scan_id_b = all_scans[0]["id"]

    comparison = None
    if scan_id_a and scan_id_b:
        scan_a = get_scan(scan_id_a)
        scan_b = get_scan(scan_id_b)
        if scan_a and scan_b:
            comparison = compare_scans(scan_a, scan_b)
        else:
            flash("One or both scans selected for comparison could not be loaded.", "warning")

    return render_template(
        "compare.html",
        all_scans=all_scans,
        selected_a=scan_id_a,
        selected_b=scan_id_b,
        comparison=comparison
    )


# ==========================================================
# 9. Report Viewer & PDF Export
# ==========================================================

@app.route("/reports/<scan_id>")
def report_viewer(scan_id: str):
    """In-browser print-ready report viewer with section breakdown and PDF export."""
    scan_data = get_scan(scan_id)
    if not scan_data:
        abort(404, description="Scan report not found.")

    return render_template("report_viewer.html", scan=scan_data)


@app.route("/reports/<scan_id>/pdf")
def download_pdf(scan_id: str):
    """Generates and serves downloadable PDF security report."""
    scan_data = get_scan(scan_id)
    if not scan_data:
        abort(404, description="Scan report not found.")

    pdf_filename = f"threatlens_report_{scan_data['domain']}_{scan_id[:8]}.pdf"
    pdf_path = Config.REPORTS_DIR / f"{scan_id}.pdf"

    if not pdf_path.exists():
        generate_pdf_report(scan_data, pdf_path)

    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=pdf_filename
    )


# ==========================================================
# 10. Settings & API Configuration Page
# ==========================================================

@app.route("/settings", methods=["GET", "POST"])
def settings_view():
    """Settings page for inspecting and configuring MongoDB, APIs, and scanning parameters."""
    status = get_db_status()
    return render_template("settings.html", db_status=status)


@app.route("/api/settings/test-mongo", methods=["POST"])
def test_mongo_connection():
    """AJAX test to check MongoDB connection status."""
    connected = mongo_manager.connect(timeout_ms=2000, force=True)
    summary = mongo_manager.get_collections_summary()
    return jsonify({
        "success": connected,
        "connected": connected,
        "database": summary.get("database"),
        "error": summary.get("error"),
        "counts": summary.get("counts", {})
    })


# ==========================================================
# 11. About ThreatLens Page
# ==========================================================

@app.route("/about")
def about():
    """Educational about page explaining project architecture, methodology, and limitations."""
    return render_template("about.html")


# ==========================================================
# Record Deletion Route
# ==========================================================

@app.route("/scans/<scan_id>/delete", methods=["POST"])
def delete_scan_route(scan_id: str):
    """Deletes an individual scan from database and removes any cached PDF."""
    success = delete_scan(scan_id)
    pdf_path = Config.REPORTS_DIR / f"{scan_id}.pdf"
    if pdf_path.exists():
        try:
            pdf_path.unlink()
        except Exception:
            pass

    if success:
        flash("Scan record successfully deleted from database.", "info")
    else:
        flash("Scan record could not be found.", "warning")

    return redirect(url_for("history"))


# ==========================================================
# Error Handlers
# ==========================================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template(
        "base.html",
        error_title="404 - Page Not Found",
        error_message="The requested scan, finding, or platform resource does not exist."
    ), 404


@app.errorhandler(500)
def server_error(e):
    return render_template(
        "base.html",
        error_title="500 - Internal Server Error",
        error_message="An internal error occurred while processing the security reconnaissance request."
    ), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1")
    print(f"[*] Starting ThreatLens Platform on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug)
