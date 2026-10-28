"""
Security Configuration Checks Module.
Performs non-destructive static and response analysis for common web security
misconfigurations, missing headers, cookie security, SSL/TLS posture,
and information disclosure.
"""

import re
import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple
from bs4 import BeautifulSoup


def check_security_headers(headers: Dict[str, str], is_https: bool) -> List[Dict[str, Any]]:
    """
    Audits HTTP response headers against OWASP security guidelines.
    Returns a list of structured findings.
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # 1. Content-Security-Policy (CSP)
    csp = headers_lower.get("content-security-policy")
    if not csp:
        findings.append({
            "title": "Missing Content-Security-Policy (CSP) Header",
            "severity": "Medium",
            "category": "HTTP Security Headers",
            "confidence": "High",
            "evidence": "Header 'Content-Security-Policy' is absent from the HTTP response.",
            "explanation": (
                "Content-Security-Policy restricts the sources from which scripts, styles, images, and "
                "other resources can be loaded. Without a CSP header, the browser cannot prevent unauthorized "
                "script execution, leaving the site more susceptible to Cross-Site Scripting (XSS) and data injection."
            ),
            "remediation": (
                "Configure a Content-Security-Policy header defining trusted sources. Example:\n"
                "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';"
            )
        })
    else:
        # Check for weak directives
        if "'unsafe-inline'" in csp and "'nonce-" not in csp and "'sha256-" not in csp:
            findings.append({
                "title": "Permissive Content-Security-Policy ('unsafe-inline')",
                "severity": "Low",
                "category": "HTTP Security Headers",
                "confidence": "High",
                "evidence": f"CSP directive allows 'unsafe-inline': {csp[:120]}...",
                "explanation": (
                    "The CSP contains the 'unsafe-inline' keyword without cryptographic nonces or hashes. "
                    "This weakens the protection against inline script injection (XSS)."
                ),
                "remediation": "Replace 'unsafe-inline' with cryptographic nonces (nonce-...) or SHA-256 hashes."
            })

    # 2. Strict-Transport-Security (HSTS)
    hsts = headers_lower.get("strict-transport-security")
    if is_https:
        if not hsts:
            findings.append({
                "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                "severity": "Medium",
                "category": "Transport Security",
                "confidence": "High",
                "evidence": "Header 'Strict-Transport-Security' is absent from the HTTPS response.",
                "explanation": (
                    "HSTS forces compatible browsers to interact with the domain exclusively over HTTPS. "
                    "Without HSTS, the initial connection or any HTTP bookmark can be intercepted via "
                    "SSL-stripping Man-in-the-Middle (MitM) attacks."
                ),
                "remediation": (
                    "Enable HSTS on your web server with an adequate max-age duration (e.g., at least 1 year).\n"
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                )
            })
        else:
            # Check max-age duration
            max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if max_age_match:
                max_age_val = int(max_age_match.group(1))
                if max_age_val < 15768000:  # less than ~6 months
                    findings.append({
                        "title": "Short HSTS max-age Duration",
                        "severity": "Low",
                        "category": "Transport Security",
                        "confidence": "High",
                        "evidence": f"Strict-Transport-Security max-age is {max_age_val} seconds (less than 6 months).",
                        "explanation": (
                            "HSTS max-age should ideally be configured for at least 6 months (15768000 seconds) "
                            "or 1 year (31536000 seconds) to provide persistent protection against downgrade attacks."
                        ),
                        "remediation": "Increase HSTS max-age to 31536000 (1 year)."
                    })
    else:
        # Site is serving over unencrypted HTTP
        findings.append({
            "title": "Website Not Enforcing HTTPS Encryption",
            "severity": "High",
            "category": "Transport Security",
            "confidence": "High",
            "evidence": "Website connects over plain unencrypted HTTP protocol.",
            "explanation": (
                "Serving websites over plain HTTP allows network eavesdroppers to inspect traffic, "
                "steal session tokens or credentials, and inject malicious content into web pages."
            ),
            "remediation": "Obtain an SSL/TLS certificate (e.g., via Let's Encrypt) and redirect all HTTP traffic to HTTPS (301 Permanent Redirect)."
        })

    # 3. X-Content-Type-Options
    x_content_type = headers_lower.get("x-content-type-options")
    if not x_content_type:
        findings.append({
            "title": "Missing X-Content-Type-Options Header",
            "severity": "Low",
            "category": "HTTP Security Headers",
            "confidence": "High",
            "evidence": "Header 'X-Content-Type-Options' is absent.",
            "explanation": (
                "The X-Content-Type-Options header instructs the browser not to 'sniff' or guess MIME types "
                "different from what the server declared. Without this header, non-executable files (like images) "
                "might be interpreted as HTML/JavaScript if malicious code is embedded within them."
            ),
            "remediation": "Add the following response header:\nX-Content-Type-Options: nosniff"
        })
    elif "nosniff" not in x_content_type.lower():
        findings.append({
            "title": "Improper X-Content-Type-Options Configuration",
            "severity": "Low",
            "category": "HTTP Security Headers",
            "confidence": "High",
            "evidence": f"X-Content-Type-Options value is '{x_content_type}' instead of 'nosniff'.",
            "explanation": "The only valid and secure value for X-Content-Type-Options is 'nosniff'.",
            "remediation": "Set header: X-Content-Type-Options: nosniff"
        })

    # 4. X-Frame-Options (Clickjacking mitigation)
    x_frame = headers_lower.get("x-frame-options")
    csp_frame_ancestors = csp and ("frame-ancestors" in csp.lower())
    if not x_frame and not csp_frame_ancestors:
        findings.append({
            "title": "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
            "severity": "Medium",
            "category": "HTTP Security Headers",
            "confidence": "High",
            "evidence": "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' directive was detected.",
            "explanation": (
                "Clickjacking attacks trick users into clicking invisible or disguised UI elements by "
                "embedding the vulnerable website inside an invisible iframe on a malicious third-party site."
            ),
            "remediation": (
                "Configure clickjacking defenses using either:\n"
                "X-Frame-Options: DENY (or SAMEORIGIN)\n"
                "Or in CSP: frame-ancestors 'self';"
            )
        })

    # 5. Referrer-Policy
    referrer_policy = headers_lower.get("referrer-policy")
    if not referrer_policy:
        findings.append({
            "title": "Missing Referrer-Policy Header",
            "severity": "Low",
            "category": "HTTP Security Headers",
            "confidence": "High",
            "evidence": "Header 'Referrer-Policy' is absent from the HTTP response.",
            "explanation": (
                "When a user clicks a link to an external website, the browser sends the current page URL "
                "in the 'Referer' header. Without a strict Referrer-Policy, sensitive parameters (such as tokens, "
                "session identifiers, or private user IDs in query strings) may leak to third parties."
            ),
            "remediation": (
                "Set a privacy-preserving Referrer-Policy header:\n"
                "Referrer-Policy: strict-origin-when-cross-origin"
            )
        })
    elif referrer_policy.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append({
            "title": f"Weak Referrer-Policy Detected ('{referrer_policy}')",
            "severity": "Low",
            "category": "HTTP Security Headers",
            "confidence": "High",
            "evidence": f"Referrer-Policy is set to '{referrer_policy}'.",
            "explanation": (
                f"The '{referrer_policy}' setting leaks full URL query parameters to third-party endpoints.",
            ),
            "remediation": "Change Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'."
        })

    # 6. Permissions-Policy (Feature-Policy)
    perm_policy = headers_lower.get("permissions-policy") or headers_lower.get("feature-policy")
    if not perm_policy:
        findings.append({
            "title": "Missing Permissions-Policy Header",
            "severity": "Informational",
            "category": "HTTP Security Headers",
            "confidence": "High",
            "evidence": "Header 'Permissions-Policy' is absent.",
            "explanation": (
                "Permissions-Policy allows site owners to explicitly restrict which browser hardware features "
                "and APIs (e.g. camera, microphone, geolocation, payment) can be accessed by the page or embedded iframes."
            ),
            "remediation": "Add Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"
        })

    # 7. Information Disclosure (Server & Technology Headers)
    server = headers_lower.get("server")
    if server:
        # Check if version number is revealed (e.g., Apache/2.4.41 or nginx/1.18.0)
        has_version = bool(re.search(r"\d+\.\d+", server))
        if has_version:
            findings.append({
                "title": f"Server Banner Information Disclosure ('{server}')",
                "severity": "Low",
                "category": "Information Disclosure",
                "confidence": "High",
                "evidence": f"Server header reveals exact software version: '{server}'.",
                "explanation": (
                    "Exposing exact web server software versions helps attackers identify specific, known CVEs "
                    "or unpatched vulnerabilities targeting that release."
                ),
                "remediation": (
                    "Configure the web server to suppress detailed version banners:\n"
                    "- Nginx: server_tokens off;\n"
                    "- Apache: ServerTokens Prod; ServerSignature Off;"
                )
            })

    x_powered_by = headers_lower.get("x-powered-by")
    if x_powered_by:
        findings.append({
            "title": f"Application Framework Disclosure ('{x_powered_by}')",
            "severity": "Low",
            "category": "Information Disclosure",
            "confidence": "High",
            "evidence": f"X-Powered-By header: '{x_powered_by}'.",
            "explanation": (
                "The X-Powered-By header reveals the backend programming language, runtime, or CMS "
                "(e.g., PHP, Express, ASP.NET). Attackers can tailor exploit vectors to this stack."
            ),
            "remediation": (
                "Disable X-Powered-By in your application configuration:\n"
                "- PHP: expose_php = Off in php.ini\n"
                "- Express.js: app.disable('x-powered-by')"
            )
        })

    return findings


def check_cookies(raw_response) -> List[Dict[str, Any]]:
    """
    Audits Set-Cookie headers for Secure, HttpOnly, and SameSite security flags.
    """
    findings = []
    if not raw_response or not hasattr(raw_response, "cookies"):
        return findings

    # Look through response cookies
    for cookie in raw_response.cookies:
        name = cookie.name
        is_secure = cookie.secure
        is_httponly = cookie.has_nonstandard_attr("HttpOnly") or "HttpOnly" in cookie._rest
        samesite = cookie._rest.get("SameSite", cookie._rest.get("samesite"))

        issues = []
        if not is_secure and raw_response.url.startswith("https://"):
            issues.append("Missing 'Secure' flag (cookie could be transmitted over unencrypted HTTP)")
        if not is_httponly:
            issues.append("Missing 'HttpOnly' flag (cookie is accessible to JavaScript / XSS scripts)")
        if not samesite:
            issues.append("Missing 'SameSite' attribute (leaves cookie vulnerable to cross-site requests)")
        elif samesite.lower() == "none" and not is_secure:
            issues.append("SameSite=None configured without Secure flag")

        if issues:
            severity = "Medium" if ("Missing 'Secure'" in str(issues) or "Missing 'HttpOnly'" in str(issues)) else "Low"
            findings.append({
                "title": f"Insecure Cookie Flags on '{name}'",
                "severity": severity,
                "category": "Cookie Security",
                "confidence": "High",
                "evidence": f"Cookie '{name}': " + "; ".join(issues),
                "explanation": (
                    f"The cookie '{name}' is missing one or more essential defense-in-depth flags. "
                    "Cookies without 'Secure' can be sniffed over cleartext networks. "
                    "Cookies without 'HttpOnly' can be extracted by malicious JavaScript if an XSS vulnerability exists. "
                    "Cookies without 'SameSite' (Strict or Lax) are sent with third-party requests, increasing CSRF risks."
                ),
                "remediation": (
                    f"Update cookie settings for '{name}':\n"
                    f"Set-Cookie: {name}=value; Secure; HttpOnly; SameSite=Lax; Path=/"
                )
            })

    return findings


def check_tls_posture(tls_cert: Dict[str, Any], is_https: bool) -> List[Dict[str, Any]]:
    """
    Evaluates SSL/TLS certificate validity, expiry, and cipher suites.
    """
    findings = []
    if not is_https:
        return findings

    if not tls_cert.get("has_tls"):
        findings.append({
            "title": "TLS/SSL Certificate Not Accessible",
            "severity": "High",
            "category": "Transport Security",
            "confidence": "Medium",
            "evidence": tls_cert.get("error", "No TLS handshake established on port 443."),
            "explanation": "The service attempted HTTPS but could not complete a standard TLS handshake.",
            "remediation": "Verify that port 443 has an active SSL/TLS listener and valid certificate binding."
        })
        return findings

    if tls_cert.get("is_expired"):
        findings.append({
            "title": "SSL/TLS Certificate Has Expired",
            "severity": "Critical",
            "category": "Transport Security",
            "confidence": "High",
            "evidence": f"Certificate expired on {tls_cert.get('valid_to')} ({abs(tls_cert.get('days_left', 0))} days ago).",
            "explanation": (
                "An expired certificate triggers prominent browser security warnings, breaking user trust and "
                "preventing secure encrypted communication."
            ),
            "remediation": "Renew the SSL/TLS certificate immediately using your certificate authority or Let's Encrypt."
        })

    elif tls_cert.get("is_expiring_soon"):
        days = tls_cert.get("days_left", 0)
        findings.append({
            "title": f"SSL/TLS Certificate Expiring Soon ({days} days remaining)",
            "severity": "Low",
            "category": "Transport Security",
            "confidence": "High",
            "evidence": f"Certificate expires on {tls_cert.get('valid_to')} ({days} days left).",
            "explanation": "Certificates expiring within 30 days should be renewed to prevent unintended service disruption.",
            "remediation": "Renew the certificate before expiration date."
        })

    if tls_cert.get("is_self_signed"):
        findings.append({
            "title": "Self-Signed SSL/TLS Certificate Detected",
            "severity": "High",
            "category": "Transport Security",
            "confidence": "High",
            "evidence": f"Issuer ({tls_cert.get('issuer')}) matches Subject ({tls_cert.get('subject_cn')}).",
            "explanation": (
                "Self-signed certificates are not signed by a trusted Public Certificate Authority (CA). "
                "Browsers reject them with security warnings, and they do not protect against Man-in-the-Middle attacks."
            ),
            "remediation": "Obtain a certificate signed by a publicly trusted CA (such as Let's Encrypt)."
        })

    if tls_cert.get("error") and "verification failed" in str(tls_cert.get("error")).lower():
        findings.append({
            "title": "SSL/TLS Certificate Validation Error",
            "severity": "High",
            "category": "Transport Security",
            "confidence": "High",
            "evidence": tls_cert.get("error", "Verification failure"),
            "explanation": "The certificate presented by the server failed validation against standard CA root stores.",
            "remediation": "Ensure the complete certificate chain (intermediate and root) is properly configured on the server."
        })

    return findings


def check_html_forms(html_content: str, effective_url: str) -> List[Dict[str, Any]]:
    """
    Checks if HTML contains forms that submit credentials or data over insecure HTTP.
    """
    findings = []
    if not html_content:
        return findings

    try:
        soup = BeautifulSoup(html_content, "html.parser")
        forms = soup.find_all("form")
        for i, form in enumerate(forms):
            action = form.get("action", "").strip()
            if action.startswith("http://"):
                findings.append({
                    "title": "HTML Form Submits Data Over Insecure HTTP",
                    "severity": "High",
                    "category": "HTML Security",
                    "confidence": "High",
                    "evidence": f"Form #{i+1} has insecure action attribute: '{action}'.",
                    "explanation": (
                        "Submitting form data over cleartext HTTP exposes user input (passwords, search queries, personal data) "
                        "to network interception and eavesdropping."
                    ),
                    "remediation": f"Update form action to submit to a secure HTTPS URL: action='{action.replace('http://', 'https://')}'"
                })
    except Exception:
        pass

    return findings


def calculate_risk_score(findings: List[Dict[str, Any]]) -> Tuple[int, str, Dict[str, int]]:
    """
    Computes a transparent risk score (0-100) and letter grade based on severity counts.
    
    Formula:
      Base Score = 100
      Critical finding:   -25 points
      High finding:       -15 points
      Medium finding:     -8 points
      Low finding:        -3 points
      Informational:       0 points
    
    Clamped to range [0, 100].
    
    Grade scale:
      90 - 100: A (Strong configuration)
      80 - 89:  B (Good posture, minor issues)
      70 - 79:  C (Moderate risk, noticeable gaps)
      50 - 69:  D (Elevated risk, significant weaknesses)
      < 50:     F (High risk, immediate attention required)
    """
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    for f in findings:
        sev = f.get("severity", "Informational")
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Informational"] += 1

    deductions = (
        (severity_counts["Critical"] * 25) +
        (severity_counts["High"] * 15) +
        (severity_counts["Medium"] * 8) +
        (severity_counts["Low"] * 3)
    )

    score = max(0, min(100, 100 - deductions))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return score, grade, severity_counts


def run_security_analysis(recon_results: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], int, str, Dict[str, int]]:
    """
    Coordinates all static and dynamic security configuration checks on reconnaissance data.
    Returns (findings_list, risk_score, risk_grade, severity_counts).
    """
    all_findings = []

    headers = recon_results.get("headers", {})
    is_https = recon_results.get("https_enabled", False)
    raw_response = recon_results.get("raw_response")
    tls_cert = recon_results.get("tls_cert", {})
    html_content = recon_results.get("html_content", "")
    effective_url = recon_results.get("effective_url", "")

    # 1. Header checks
    all_findings.extend(check_security_headers(headers, is_https))

    # 2. Cookie security
    all_findings.extend(check_cookies(raw_response))

    # 3. TLS / SSL Posture
    all_findings.extend(check_tls_posture(tls_cert, is_https))

    # 4. Form checks
    all_findings.extend(check_html_forms(html_content, effective_url))

    # 5. Normalize finding structure with unique IDs, impact, and timestamps
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # ID Prefix map by category
    prefix_map = {
        "HTTP Security Headers": "TL-HDR",
        "Transport Security": "TL-TLS",
        "Cookie Security": "TL-CKI",
        "HTML Security": "TL-FRM",
        "Information Disclosure": "TL-SRV"
    }
    
    category_counters: Dict[str, int] = {}
    for f in all_findings:
        cat = f.get("category", "General Security")
        category_counters[cat] = category_counters.get(cat, 0) + 1
        prefix = prefix_map.get(cat, "TL-SEC")
        if not f.get("id"):
            f["id"] = f"{prefix}-{category_counters[cat]:03d}"
        if not f.get("finding_id"):
            f["finding_id"] = f["id"]
        if not f.get("detection_timestamp"):
            f["detection_timestamp"] = now_str
        if not f.get("potential_impact"):
            f["potential_impact"] = _derive_potential_impact(f.get("title", ""), cat)

    # 6. Compute score and grade
    score, grade, severity_counts = calculate_risk_score(all_findings)

    return all_findings, score, grade, severity_counts


def _derive_potential_impact(title: str, category: str) -> str:
    """Provides a realistic, non-sensationalized potential impact description."""
    t_lower = title.lower()
    if "content-security-policy" in t_lower:
        return "Increased susceptibility to Cross-Site Scripting (XSS) and unauthorized external resource injection."
    elif "strict transport security" in t_lower or "hsts" in t_lower:
        return "Vulnerability to SSL-stripping attacks and eavesdropping on unencrypted initial HTTP connections."
    elif "x-content-type-options" in t_lower:
        return "Potential MIME-sniffing attacks where untrusted files are executed by browsers as active scripts."
    elif "clickjacking" in t_lower or "x-frame-options" in t_lower:
        return "Adversaries could frame the website to trick users into executing unauthorized state-changing actions."
    elif "referrer-policy" in t_lower:
        return "Sensitive query parameters, internal paths, or tokens may leak to external third-party referrers."
    elif "permissions-policy" in t_lower:
        return "Embedded iframes or scripts might invoke browser sensors (microphone, camera, location) unchecked."
    elif "cookie" in t_lower:
        return "Session tokens could be exposed to network eavesdropping (missing Secure) or script theft via XSS (missing HttpOnly)."
    elif "expired" in t_lower:
        return "Users encounter severe browser warnings; communications lose cryptographic trust and integrity."
    elif "self-signed" in t_lower:
        return "Lack of Certificate Authority validation permits undetected Man-in-the-Middle spoofing."
    elif "insecure http" in t_lower or "html form" in t_lower:
        return "Data submitted across the network travels unencrypted and can be intercepted by third parties."
    elif "banner" in t_lower or "disclosure" in t_lower:
        return "Discloses specific server releases, assisting attackers in targeting known CVEs."
    return "Weakened defensive posture increases risk exposure under targeted application testing."

