"""
AI-Powered Security Analysis & Threat Intelligence Explainer.
Processes verified scanner observations and synthesizes:
A. Executive Summary
B. Finding Explanations
C. Risk Prioritization
D. Practical Remediation Guidance
E. Scan Comparison Summary
F. Professional Natural-Language Narrative Report

Supports Google Gemini, OpenAI, and a built-in pedagogical cybersecurity engine.
Treats all target page contents, headers, and banners as untrusted data with strict sanitization.
"""

import re
import json
import logging
from typing import List, Dict, Any, Optional
import requests
from config import Config

logger = logging.getLogger("threatlens.ai")


def sanitize_untrusted_input(text: str, max_chars: int = 200) -> str:
    """
    Sanitizes untrusted web inputs (server headers, HTML titles) before LLM prompt inclusion
    to mitigate prompt injection risks.
    """
    if not text:
        return ""
    # Strip markdown code delimiters, newlines, and prompt injection patterns
    cleaned = text.replace("\r", " ").replace("\n", " ").replace("```", " ")
    cleaned = re.sub(r"(ignore\s+(all\s+)?previous\s+instructions|system\s*:|assistant\s*:|user\s*:)", "[filtered]", cleaned, flags=re.IGNORECASE)
    return cleaned[:max_chars].strip()


def build_risk_prioritization(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Ranks findings objectively into a structured remediation queue based on
    severity weight, confidence level, and potential impact.
    """
    severity_weights = {
        "Critical": 100,
        "High": 75,
        "Medium": 50,
        "Low": 25,
        "Informational": 10
    }
    confidence_multipliers = {
        "High": 1.0,
        "Medium": 0.8,
        "Low": 0.6
    }

    prioritized = []
    for f in findings:
        sev = f.get("severity", "Informational")
        conf = f.get("confidence", "High")
        weight = severity_weights.get(sev, 10) * confidence_multipliers.get(conf, 1.0)
        
        urgency = "Immediate (24-48 Hours)" if sev in ("Critical", "High") else (
            "Next Maintenance Cycle" if sev == "Medium" else "Low Priority / Best Practice"
        )

        prioritized.append({
            "finding_id": f.get("finding_id") or f.get("id", "TL-SEC"),
            "title": f.get("title", "Untitled Finding"),
            "severity": sev,
            "confidence": conf,
            "weight": round(weight, 1),
            "urgency": urgency,
            "potential_impact": f.get("potential_impact", "Weakened defense-in-depth posture."),
            "action": f.get("remediation", "Apply defensive configuration."),
            "evidence": f.get("evidence", "")
        })

    # Sort descending by priority weight
    prioritized.sort(key=lambda x: x["weight"], reverse=True)
    return prioritized


def generate_structured_remediation_guidance(findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Categorizes remediation actions into phased execution milestones:
    Phase 1: Urgent Remediations
    Phase 2: Configuration Hardening
    Phase 3: Defensive Best Practices
    """
    phase1_urgent = []
    phase2_hardening = []
    phase3_hygiene = []

    for f in findings:
        sev = f.get("severity", "Informational")
        title = f.get("title", "")
        remediation = f.get("remediation", "")
        item_text = f"{title}: {remediation}"

        if sev in ("Critical", "High"):
            phase1_urgent.append(item_text)
        elif sev == "Medium":
            phase2_hardening.append(item_text)
        else:
            phase3_hygiene.append(item_text)

    return {
        "phase1_urgent": phase1_urgent or ["No critical or high severity exposures detected."],
        "phase2_hardening": phase2_hardening or ["Defensive headers and configurations meet standard requirements."],
        "phase3_hygiene": phase3_hygiene or ["Informational best practices are in good order."]
    }


def generate_builtin_ai_analysis(
    domain: str,
    risk_score: int,
    risk_grade: str,
    findings: List[Dict[str, Any]],
    recon_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generates a high-fidelity, deterministic cybersecurity analysis without external API dependencies.
    """
    critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")
    info_count = sum(1 for f in findings if f.get("severity") == "Informational")

    tls = recon_data.get("tls_cert", {})
    tls_info = (
        f"The host negotiated {tls.get('tls_version', 'TLS')} with cipher {tls.get('cipher_suite', 'standard')} "
        f"and {tls.get('days_left', 0)} days remaining on its certificate."
        if tls.get("has_tls") else "No valid SSL/TLS certificate was presented on port 443."
    )

    open_ports = recon_data.get("open_ports", [])
    ports_info = f"Active port reconnaissance identified {len(open_ports)} exposed port(s): {open_ports}." if open_ports else "No common service ports were identified open during non-intrusive probing."

    # 1. Executive Summary
    exec_summary = (
        f"Automated threat intelligence and security reconnaissance completed for target '{domain}'. "
        f"The target achieved a calculated Security Posture Score of {risk_score}/100, earning a letter grade of '{risk_grade}'. "
        f"ThreatLens identified {len(findings)} total observable security finding(s): {critical_count} Critical, "
        f"{high_count} High, {med_count} Medium, {low_count} Low, and {info_count} Informational. "
        f"{tls_info} {ports_info} "
        f"Implementation of the prioritized defensive mitigations below will harden the target against contemporary automated threats."
    )

    # 2. Finding Explanations
    finding_explanations = []
    for f in findings:
        finding_explanations.append({
            "finding_id": f.get("finding_id") or f.get("id", "TL-SEC"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "what_it_means": f.get("explanation"),
            "why_it_matters": f.get("potential_impact", "Weakens defense-in-depth posture."),
            "how_to_fix": f.get("remediation"),
            "evidence": f.get("evidence")
        })

    # 3. Risk Prioritization
    risk_prioritization = build_risk_prioritization(findings)

    # 4. Remediation Guidance
    remediation_guidance = generate_structured_remediation_guidance(findings)

    # 5. Natural-Language Comprehensive Report
    report_lines = [
        f"# ThreatLens Cybersecurity Assessment Report: {domain}",
        f"**Posture Score:** {risk_score}/100 | **Grade:** {grade_descriptor(risk_grade)} ({risk_grade})",
        "",
        "## 1. Executive Overview",
        exec_summary,
        "",
        "## 2. Risk Exposure Breakdown",
        f"- **Critical Vulnerabilities:** {critical_count}",
        f"- **High Severity Issues:** {high_count}",
        f"- **Medium Severity Configurations:** {med_count}",
        f"- **Low / Informational:** {low_count + info_count}",
        "",
        "## 3. Remediation Roadmap",
        "### Immediate Action Items (Phase 1):"
    ]
    for action in remediation_guidance["phase1_urgent"][:4]:
        report_lines.append(f"• {action}")
    report_lines.append("\n### Hardening Measures (Phase 2):")
    for action in remediation_guidance["phase2_hardening"][:4]:
        report_lines.append(f"• {action}")
    report_lines.append(
        "\n## 4. Educational & Academic Demonstration Note\n"
        "This assessment was generated safely via passive reconnaissance and authorized service probing. "
        "No intrusive penetration testing, brute-force exploits, or state-altering requests were dispatched."
    )
    natural_language_report = "\n".join(report_lines)

    return {
        "provider": "builtin",
        "executive_summary": exec_summary,
        "finding_explanations": finding_explanations,
        "risk_prioritization": risk_prioritization,
        "remediation_guidance": remediation_guidance,
        "natural_language_report": natural_language_report,
        "scan_comparison_summary": ""
    }


def grade_descriptor(grade: str) -> str:
    descriptors = {
        "A": "Excellent Defensive Posture",
        "B": "Good Configuration, Minor Gaps",
        "C": "Moderate Posture Exposure",
        "D": "Elevated Exposure, Action Recommended",
        "F": "Severe Posture Deficiencies"
    }
    return descriptors.get(grade, "Evaluated Posture")


def generate_gemini_analysis(
    domain: str,
    risk_score: int,
    risk_grade: str,
    findings: List[Dict[str, Any]],
    recon_data: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Queries Google Gemini API (gemini-1.5-flash / gemini-2.0-flash) to produce an executive cybersecurity analysis.
    Safely sanitizes inputs and falls back to builtin on any error.
    """
    api_key = Config.GEMINI_API_KEY
    if not api_key:
        return None

    safe_domain = sanitize_untrusted_input(domain, 100)
    top_findings = [
        f"[{f.get('severity')}] {sanitize_untrusted_input(f.get('title', ''))}: {sanitize_untrusted_input(f.get('evidence', ''))}"
        for f in findings[:10]
    ]

    prompt = (
        f"You are a Senior Cyber Threat Analyst reviewing an authorized web security scan.\n"
        f"Target Domain: {safe_domain}\n"
        f"Calculated Score: {risk_score}/100 (Grade {risk_grade})\n"
        f"Verified Findings:\n" + "\n".join(top_findings) + "\n\n"
        f"Provide a concise executive report with the following structure:\n"
        f"1. Executive Summary: 2 concise paragraphs analyzing the overall posture.\n"
        f"2. Risk Prioritization: The top 3 items requiring remediation.\n"
        f"3. Practical Remediation: Exact server configuration steps.\n"
        f"Do not invent any vulnerabilities, scores, or port states not provided above."
    )

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 800}
    }

    try:
        resp = requests.post(url, json=payload, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            candidates = data.get("candidates", [])
            if candidates:
                text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if text_content:
                    builtin = generate_builtin_ai_analysis(domain, risk_score, risk_grade, findings, recon_data)
                    builtin["provider"] = "gemini"
                    builtin["executive_summary"] = text_content[:500] + "..."
                    builtin["natural_language_report"] = text_content
                    return builtin
    except Exception as e:
        logger.warning(f"Gemini API request failed, falling back to built-in explainer: {e}")

    return None


def generate_openai_analysis(
    domain: str,
    risk_score: int,
    risk_grade: str,
    findings: List[Dict[str, Any]],
    recon_data: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Queries OpenAI API if configured.
    """
    api_key = Config.OPENAI_API_KEY
    if not api_key:
        return None

    safe_domain = sanitize_untrusted_input(domain, 100)
    top_findings = [
        f"[{f.get('severity')}] {sanitize_untrusted_input(f.get('title', ''))}"
        for f in findings[:8]
    ]

    prompt = (
        f"You are a Cybersecurity Operations Analyst evaluating a web assessment.\n"
        f"Target Domain: {safe_domain}\n"
        f"Score: {risk_score}/100 (Grade {risk_grade})\n"
        f"Findings:\n" + "\n".join(top_findings) + "\n\n"
        f"Write a concise executive summary, top risk priorities, and practical remediation guidance."
    )

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are an objective cybersecurity analyst."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.4,
                "max_tokens": 600
            },
            timeout=8.0
        )
        if resp.status_code == 200:
            data = resp.json()
            text_content = data["choices"][0]["message"]["content"].strip()
            builtin = generate_builtin_ai_analysis(domain, risk_score, risk_grade, findings, recon_data)
            builtin["provider"] = "openai"
            builtin["executive_summary"] = text_content[:500] + "..."
            builtin["natural_language_report"] = text_content
            return builtin
    except Exception as e:
        logger.warning(f"OpenAI API request failed, falling back to built-in explainer: {e}")

    return None


def explain_findings(
    domain: str,
    risk_score: int,
    risk_grade: str,
    findings: List[Dict[str, Any]],
    recon_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Orchestrates AI analysis according to AI_PROVIDER configuration (gemini, openai, builtin).
    Always returns a fully structured analysis dictionary.
    """
    provider_pref = Config.AI_PROVIDER

    if provider_pref == "gemini" or (provider_pref == "auto" and Config.GEMINI_API_KEY):
        analysis = generate_gemini_analysis(domain, risk_score, risk_grade, findings, recon_data)
        if analysis:
            return analysis

    if provider_pref == "openai" or (provider_pref == "auto" and Config.OPENAI_API_KEY):
        analysis = generate_openai_analysis(domain, risk_score, risk_grade, findings, recon_data)
        if analysis:
            return analysis

    return generate_builtin_ai_analysis(domain, risk_score, risk_grade, findings, recon_data)
