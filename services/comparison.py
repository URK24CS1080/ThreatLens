"""
Scan Comparison Service for ThreatLens.
Compares two scans of a target to identify:
- New findings (regressions)
- Resolved findings (remediations)
- Unchanged findings (persistent risks)
- Risk posture score delta
- Infrastructure changes (TLS, server headers, open ports)
"""

from typing import Dict, Any, List, Tuple, Optional


def compare_scans(scan_a: Dict[str, Any], scan_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compares baseline scan (scan_a) with follow-up scan (scan_b).
    Returns structured delta report.
    """
    score_a = scan_a.get("risk_score", 0)
    score_b = scan_b.get("risk_score", 0)
    score_delta = score_b - score_a

    grade_a = scan_a.get("risk_grade", "F")
    grade_b = scan_b.get("risk_grade", "F")

    findings_a = scan_a.get("findings", [])
    findings_b = scan_b.get("findings", [])

    # Map findings by a normalized key: (category, title)
    def normalize_key(f: Dict[str, Any]) -> Tuple[str, str]:
        return (f.get("category", "").strip().lower(), f.get("title", "").strip().lower())

    dict_a = {normalize_key(f): f for f in findings_a}
    dict_b = {normalize_key(f): f for f in findings_b}

    keys_a = set(dict_a.keys())
    keys_b = set(dict_b.keys())

    resolved_keys = keys_a - keys_b
    new_keys = keys_b - keys_a
    unchanged_keys = keys_a & keys_b

    resolved_findings = [dict_a[k] for k in resolved_keys]
    new_findings = [dict_b[k] for k in new_keys]
    unchanged_findings = [dict_b[k] for k in unchanged_keys]

    # Port comparisons
    ports_a = set(scan_a.get("recon", {}).get("open_ports", []))
    ports_b = set(scan_b.get("recon", {}).get("open_ports", []))
    new_ports = sorted(list(ports_b - ports_a))
    closed_ports = sorted(list(ports_a - ports_b))
    unchanged_ports = sorted(list(ports_a & ports_b))

    # TLS / Server changes
    recon_a = scan_a.get("recon", {})
    recon_b = scan_b.get("recon", {})
    server_changed = recon_a.get("server_header") != recon_b.get("server_header")
    tls_a = recon_a.get("tls_cert", {})
    tls_b = recon_b.get("tls_cert", {})

    # Generate narrative comparison summary
    narrative = _generate_comparison_narrative(
        domain_a=scan_a.get("domain", "Target"),
        date_a=scan_a.get("created_at", "Baseline"),
        date_b=scan_b.get("created_at", "Follow-up"),
        score_a=score_a,
        score_b=score_b,
        score_delta=score_delta,
        grade_a=grade_a,
        grade_b=grade_b,
        resolved_count=len(resolved_findings),
        new_count=len(new_findings),
        unchanged_count=len(unchanged_findings),
        resolved_findings=resolved_findings,
        new_findings=new_findings,
        new_ports=new_ports,
        closed_ports=closed_ports
    )

    return {
        "scan_a": {
            "id": scan_a.get("id"),
            "domain": scan_a.get("domain"),
            "created_at": scan_a.get("created_at"),
            "risk_score": score_a,
            "risk_grade": grade_a,
            "total_findings": len(findings_a),
            "open_ports": sorted(list(ports_a))
        },
        "scan_b": {
            "id": scan_b.get("id"),
            "domain": scan_b.get("domain"),
            "created_at": scan_b.get("created_at"),
            "risk_score": score_b,
            "risk_grade": grade_b,
            "total_findings": len(findings_b),
            "open_ports": sorted(list(ports_b))
        },
        "score_delta": score_delta,
        "score_direction": "improved" if score_delta > 0 else ("degraded" if score_delta < 0 else "unchanged"),
        "grade_changed": grade_a != grade_b,
        "resolved_findings": resolved_findings,
        "new_findings": new_findings,
        "unchanged_findings": unchanged_findings,
        "resolved_count": len(resolved_findings),
        "new_count": len(new_findings),
        "unchanged_count": len(unchanged_findings),
        "port_changes": {
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "unchanged_ports": unchanged_ports
        },
        "server_changed": server_changed,
        "server_a": recon_a.get("server_header", ""),
        "server_b": recon_b.get("server_header", ""),
        "narrative_summary": narrative
    }


def _generate_comparison_narrative(
    domain_a: str,
    date_a: str,
    date_b: str,
    score_a: int,
    score_b: int,
    score_delta: int,
    grade_a: str,
    grade_b: str,
    resolved_count: int,
    new_count: int,
    unchanged_count: int,
    resolved_findings: List[Dict[str, Any]],
    new_findings: List[Dict[str, Any]],
    new_ports: List[int],
    closed_ports: List[int]
) -> str:
    """Produces a plain-English delta summary suitable for executive reporting."""
    lines = []
    lines.append(f"Comparative Security Posture Review for {domain_a}")
    lines.append("-" * 50)
    lines.append(f"Baseline Scan: {date_a} (Score: {score_a}/100, Grade: {grade_a})")
    lines.append(f"Follow-Up Scan: {date_b} (Score: {score_b}/100, Grade: {grade_b})")
    lines.append("")

    if score_delta > 0:
        lines.append(f"Overall Posture: IMPROVED by +{score_delta} points ({grade_a} -> {grade_b}).")
    elif score_delta < 0:
        lines.append(f"Overall Posture: DEGRADED by {score_delta} points ({grade_a} -> {grade_b}).")
    else:
        lines.append("Overall Posture: UNCHANGED score.")

    lines.append(
        f"Findings Summary: {resolved_count} issue(s) resolved, {new_count} new issue(s) introduced, "
        f"{unchanged_count} persistent issue(s)."
    )
    lines.append("")

    if resolved_findings:
        lines.append("Remediated Vulnerabilities / Hardened Configurations:")
        for f in resolved_findings[:5]:
            lines.append(f"  [FIXED] {f.get('title')} ({f.get('severity')})")
        lines.append("")

    if new_findings:
        lines.append("New Configuration Exposures:")
        for f in new_findings[:5]:
            lines.append(f"  [NEW] {f.get('title')} ({f.get('severity')}) - {f.get('remediation')}")
        lines.append("")

    if new_ports:
        lines.append(f"Network Exposure Alert: New open port(s) detected: {new_ports}")
    if closed_ports:
        lines.append(f"Network Hardening: Closed port(s): {closed_ports}")

    return "\n".join(lines)
