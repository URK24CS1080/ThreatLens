"""
Website Reconnaissance Module.
Gathers domain information, DNS records, HTTP response headers,
SSL/TLS certificate details, and technology stack fingerprints.
"""

import socket
import ssl
import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import dns.resolver
from bs4 import BeautifulSoup

from services.ssrf_guard import safe_http_fetch, SSRFValidationError
from config import Config


def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """
    Queries common DNS record types (A, AAAA, MX, NS, TXT, CNAME) using dnspython.
    Handles timeouts and query errors gracefully.
    """
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": []
    }
    
    # Configure custom resolver with short timeout
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 2.0

    for r_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = resolver.resolve(domain, r_type)
            for rdata in answers:
                if r_type == "MX":
                    records[r_type].append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
                elif r_type == "TXT":
                    records[r_type].append(str(b"".join(rdata.strings).decode(errors="replace")))
                elif r_type in ("NS", "CNAME"):
                    records[r_type].append(str(rdata.target).rstrip('.'))
                else:
                    records[r_type].append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue

    # Fallback to standard socket resolution if A record wasn't found by dnspython
    if not records["A"]:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            records["A"] = ips
        except Exception:
            pass

    return records


def get_tls_certificate_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Connects to the target on port 443 and inspects the TLS certificate.
    Extracts issuer, subject, expiration date, SANs, TLS version, and cipher.
    """
    cert_info = {
        "has_tls": False,
        "is_valid": False,
        "subject_cn": "Unknown",
        "issuer": "Unknown",
        "serial_number": "Unknown",
        "valid_from": None,
        "valid_to": None,
        "days_left": None,
        "san_list": [],
        "tls_version": "Unknown",
        "cipher_suite": "Unknown",
        "is_expired": False,
        "is_self_signed": False,
        "is_expiring_soon": False,
        "error": None
    }

    try:
        # Create standard SSL context that verifies certificates
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_info["has_tls"] = True
                cert_info["is_valid"] = True
                cert_info["tls_version"] = ssock.version()
                cipher_tuple = ssock.cipher()
                cert_info["cipher_suite"] = cipher_tuple[0] if cipher_tuple else "Unknown"

                # Parse Subject Common Name
                for item in cert.get("subject", []):
                    for k, v in item:
                        if k == "commonName":
                            cert_info["subject_cn"] = v

                # Parse Issuer Name
                issuer_parts = []
                for item in cert.get("issuer", []):
                    for k, v in item:
                        if k in ("organizationName", "commonName"):
                            issuer_parts.append(v)
                cert_info["issuer"] = " - ".join(issuer_parts) if issuer_parts else "Unknown"

                # Check self-signed
                cert_info["is_self_signed"] = (cert.get("subject") == cert.get("issuer"))

                # Serial Number
                cert_info["serial_number"] = cert.get("serialNumber", "Unknown")

                # Parse dates
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    # Format: 'May 15 12:00:00 2025 GMT'
                    expiry = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.utcnow()
                    cert_info["valid_to"] = expiry.strftime("%Y-%m-%d %H:%M UTC")
                    days_left = (expiry - now).days
                    cert_info["days_left"] = days_left
                    cert_info["is_expired"] = (days_left < 0)
                    cert_info["is_expiring_soon"] = (0 <= days_left <= 30)

                if not_before_str:
                    start_date = datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                    cert_info["valid_from"] = start_date.strftime("%Y-%m-%d %H:%M UTC")

                # Parse SANs (Subject Alternative Names)
                sans = []
                for san_type, san_val in cert.get("subjectAltName", []):
                    if san_type == "DNS":
                        sans.append(san_val)
                cert_info["san_list"] = sans[:15]  # Limit display to top 15

    except ssl.SSLCertVerificationError as e:
        cert_info["has_tls"] = True
        cert_info["is_valid"] = False
        cert_info["error"] = f"Certificate verification failed: {e.verify_message}"
    except (socket.timeout, TimeoutError):
        cert_info["error"] = "TLS handshake connection timed out."
    except ConnectionRefusedError:
        cert_info["error"] = "Port 443 connection refused (No HTTPS service listening)."
    except Exception as e:
        cert_info["error"] = f"Could not inspect TLS certificate: {str(e)}"

    return cert_info


def identify_technologies(headers: Dict[str, str], html_content: str) -> List[Dict[str, str]]:
    """
    Fingerprints web server, framework, CDN, CMS, and frontend libraries
    based on HTTP response headers and HTML elements.
    """
    technologies = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    html_lower = html_content.lower()

    # 1. Web Servers & CDNs from headers
    server_hdr = headers_lower.get("server", "")
    if "nginx" in server_hdr.lower():
        technologies.append({"name": "Nginx", "category": "Web Server", "confidence": "High", "evidence": f"Server: {server_hdr}"})
    elif "apache" in server_hdr.lower():
        technologies.append({"name": "Apache HTTP Server", "category": "Web Server", "confidence": "High", "evidence": f"Server: {server_hdr}"})
    elif "cloudflare" in server_hdr.lower():
        technologies.append({"name": "Cloudflare", "category": "CDN / Reverse Proxy", "confidence": "High", "evidence": f"Server: {server_hdr}"})
    elif "caddy" in server_hdr.lower():
        technologies.append({"name": "Caddy", "category": "Web Server", "confidence": "High", "evidence": f"Server: {server_hdr}"})
    elif "microsoft-iis" in server_hdr.lower():
        technologies.append({"name": "Microsoft IIS", "category": "Web Server", "confidence": "High", "evidence": f"Server: {server_hdr}"})
    elif "litespeed" in server_hdr.lower():
        technologies.append({"name": "LiteSpeed", "category": "Web Server", "confidence": "High", "evidence": f"Server: {server_hdr}"})
    elif server_hdr:
        technologies.append({"name": server_hdr, "category": "Web Server", "confidence": "Medium", "evidence": f"Server: {server_hdr}"})

    # Additional CDN headers
    if "cf-ray" in headers_lower:
        if not any(t["name"] == "Cloudflare" for t in technologies):
            technologies.append({"name": "Cloudflare CDN", "category": "CDN / WAF", "confidence": "High", "evidence": "cf-ray header detected"})
    if "x-amz-cf-id" in headers_lower or "cloudfront" in headers_lower.get("via", "").lower():
        technologies.append({"name": "Amazon CloudFront", "category": "CDN", "confidence": "High", "evidence": "CloudFront header"})

    # 2. Application Platforms / Frameworks from X-Powered-By
    powered_by = headers_lower.get("x-powered-by", "")
    if powered_by:
        technologies.append({"name": powered_by, "category": "Backend Framework", "confidence": "High", "evidence": f"X-Powered-By: {powered_by}"})

    aspnet_version = headers_lower.get("x-aspnet-version", "")
    if aspnet_version:
        technologies.append({"name": f"ASP.NET {aspnet_version}", "category": "Web Framework", "confidence": "High", "evidence": f"X-AspNet-Version: {aspnet_version}"})

    # 3. HTML-based fingerprinting (Meta tags, scripts)
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        meta_gen = soup.find("meta", attrs={"name": lambda x: x and x.lower() == "generator"})
        if meta_gen and meta_gen.get("content"):
            gen_content = meta_gen.get("content")
            technologies.append({"name": gen_content, "category": "CMS / Generator", "confidence": "High", "evidence": f'<meta name="generator" content="{gen_content}">' })
    except Exception:
        pass

    # CMS & Framework clues in HTML body
    if "wp-content" in html_lower or "wp-includes" in html_lower:
        if not any("WordPress" in t["name"] for t in technologies):
            technologies.append({"name": "WordPress", "category": "CMS", "confidence": "High", "evidence": "wp-content / wp-includes path in HTML"})
    if "drupal.js" in html_lower or "sites/all/themes" in html_lower:
        technologies.append({"name": "Drupal", "category": "CMS", "confidence": "High", "evidence": "Drupal assets detected in HTML"})
    if "cdn.shopify.com" in html_lower:
        technologies.append({"name": "Shopify", "category": "E-Commerce Platform", "confidence": "High", "evidence": "Shopify CDN assets"})
    if "bootstrap" in html_lower:
        technologies.append({"name": "Bootstrap", "category": "UI Framework", "confidence": "Medium", "evidence": "Bootstrap CSS/JS reference in HTML"})
    if "__next" in html_lower:
        technologies.append({"name": "Next.js (React)", "category": "JavaScript Framework", "confidence": "High", "evidence": "Next.js root element (__next) detected"})

    return technologies


def perform_reconnaissance(target_url: str) -> Dict[str, Any]:
    """
    Executes full reconnaissance on the target URL:
    - DNS resolution
    - HTTP request & redirect tracing
    - Page title extraction
    - Server response headers
    - TLS certificate inspection
    - Technology identification
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""

    # 1. DNS Information
    dns_records = get_dns_records(hostname)
    primary_ip = dns_records["A"][0] if dns_records["A"] else "Unknown"

    # 2. HTTP/HTTPS probe with SSRF protection
    response, redirect_chain = safe_http_fetch(target_url)

    # 3. HTML parsing
    html_text = response.text if response else ""
    page_title = "Untitled Page"
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            page_title = title_tag.string.strip()[:100]
    except Exception:
        pass

    # 4. Extract headers
    response_headers = dict(response.headers) if response else {}
    server_header = response_headers.get("Server", response_headers.get("server", "Not Disclosed"))

    # 5. TLS Certificate (if target uses HTTPS or redirects to HTTPS)
    effective_url = response.url if response else target_url
    effective_parsed = urlparse(effective_url)
    is_https = (effective_parsed.scheme == "https")
    tls_info = {}
    if is_https or parsed.scheme == "https":
        tls_info = get_tls_certificate_info(hostname, 443)

    # 6. Technology detection
    technologies = identify_technologies(response_headers, html_text)

    return {
        "domain": hostname,
        "primary_ip": primary_ip,
        "http_status": response.status_code if response else 0,
        "https_enabled": is_https,
        "effective_url": effective_url,
        "page_title": page_title,
        "server_header": server_header,
        "headers": response_headers,
        "redirect_chain": redirect_chain,
        "dns_records": dns_records,
        "tls_cert": tls_info,
        "technologies": technologies,
        "raw_response": response,
        "html_content": html_text
    }
