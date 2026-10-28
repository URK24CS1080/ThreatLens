"""
Threat Intelligence Checker Module.
Queries Google Safe Browsing v4 (if configured), URLhaus (abuse.ch open intelligence),
and computes heuristic domain threat indicators (Punycode homoglyphs, IP hostnames, entropy).
"""

import math
import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import requests
from config import Config

# Frequently abused TLDs often seen in bulk spam/phishing campaigns (used for heuristic context only)
SUSPICIOUS_TLDS = {".buzz", ".top", ".xyz", ".work", ".click", ".link", ".rest", ".gq", ".ml", ".cf"}


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string to detect randomized DGA domains."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    frequencies = {c: text.count(c) / length for c in set(text)}
    for p in frequencies.values():
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def check_heuristics_and_reputation(domain: str, url: str) -> Dict[str, Any]:
    """
    Evaluates domain reputation heuristics:
    - Punycode (IDN homograph attacks)
    - Raw IP address used as hostname
    - Domain entropy (DGA indicators)
    - Suspicious TLD patterns
    """
    indicators = []
    
    # 1. Punycode detection (IDN Homograph attack vector)
    if "xn--" in domain.lower():
        indicators.append({
            "type": "IDN Homograph Indicator",
            "severity": "Medium",
            "detail": f"Domain '{domain}' contains Punycode ('xn--'), which can be used in visual spoofing / homograph phishing attacks."
        })

    # 2. Raw IP address in URL
    parsed = urlparse(url)
    hostname = parsed.hostname or domain
    # Remove brackets for IPv6
    clean_host = hostname.strip("[]")
    if all(part.isdigit() for part in clean_host.split(".")) and clean_host.count(".") == 3:
        indicators.append({
            "type": "Raw IP Hostname",
            "severity": "Medium",
            "detail": f"Target uses raw IP address '{clean_host}' instead of a registered domain name."
        })

    # 3. Suspicious / Abused TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.lower().endswith(tld):
            indicators.append({
                "type": "High-Abuse TLD Indicator",
                "severity": "Informational",
                "detail": f"Domain utilizes '{tld}', a top-level domain frequently associated with automated campaign abuse."
            })
            break

    # 4. Domain Entropy (DGA detection)
    # Check the main subdomain/SLD part
    sld_part = domain.split(".")[0] if "." in domain else domain
    entropy = calculate_shannon_entropy(sld_part)
    if len(sld_part) > 12 and entropy > 3.8:
        indicators.append({
            "type": "High Entropy Domain Name",
            "severity": "Low",
            "detail": f"Domain prefix '{sld_part}' exhibits high Shannon entropy ({entropy}), resembling an algorithmic or randomly generated name."
        })

    return {
        "provider": "Static Threat & Heuristic Indicators",
        "status": "Completed",
        "has_indicators": len(indicators) > 0,
        "indicators": indicators
    }


def query_urlhaus_api(domain: str) -> Dict[str, Any]:
    """
    Queries abuse.ch's URLhaus open threat intelligence feed.
    No API key required; checks for active malware distribution.
    """
    result = {
        "provider": "abuse.ch URLhaus Threat Feed",
        "status": "Pending",
        "match_found": False,
        "threat_category": None,
        "details": None
    }

    api_endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
    try:
        resp = requests.post(
            api_endpoint,
            data={"host": domain},
            timeout=5.0,
            headers={"User-Agent": "CyberSecurity-Analyzer/1.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            query_status = data.get("query_status")
            if query_status == "ok":
                url_count = data.get("url_count", 0)
                result["status"] = "Match Found"
                result["match_found"] = True
                result["threat_category"] = "Malware Distribution"
                result["details"] = (
                    f"Host is indexed in URLhaus database with {url_count} documented malware URL records. "
                    f"First seen: {data.get('firstseen', 'Unknown')}."
                )
            elif query_status == "no_results":
                result["status"] = "No Match Found"
                result["match_found"] = False
                result["details"] = "Host has no active malware distribution entries in the URLhaus database."
            else:
                result["status"] = "Query Completed"
                result["details"] = f"URLhaus response: {query_status}"
        else:
            result["status"] = f"HTTP Error {resp.status_code}"
            result["details"] = "Could not complete lookup with URLhaus endpoint."
    except requests.exceptions.Timeout:
        result["status"] = "Lookup Timed Out"
        result["details"] = "URLhaus API request timed out after 5 seconds."
    except Exception as e:
        result["status"] = "Lookup Error"
        result["details"] = f"Error communicating with URLhaus: {str(e)}"

    return result


def query_google_safe_browsing(target_url: str) -> Dict[str, Any]:
    """
    Queries Google Safe Browsing API v4 if SAFE_BROWSING_API_KEY is configured.
    Checks for MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, and POTENTIALLY_HARMFUL_APPLICATION.
    """
    api_key = Config.SAFE_BROWSING_API_KEY
    result = {
        "provider": "Google Safe Browsing v4",
        "status": "Not Configured",
        "match_found": False,
        "threat_category": None,
        "details": None
    }

    if not api_key:
        result["status"] = "API Key Not Configured"
        result["details"] = (
            "Google Safe Browsing API key not set. To enable this lookup, obtain a free API key "
            "from Google Cloud Console and set SAFE_BROWSING_API_KEY in your .env file."
        )
        return result

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "websec-analyzer",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": target_url}
            ]
        }
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = list(set(m.get("threatType") for m in matches))
                result["status"] = "Threat Match Found"
                result["match_found"] = True
                result["threat_category"] = ", ".join(threat_types)
                result["details"] = (
                    f"Target URL matched known entries in Google Safe Browsing database for: {', '.join(threat_types)}."
                )
            else:
                result["status"] = "No Match Found"
                result["match_found"] = False
                result["details"] = "No threat matches found for this URL in Google Safe Browsing database."
        else:
            result["status"] = f"API Error ({resp.status_code})"
            result["details"] = f"Safe Browsing API responded with status {resp.status_code}. Lookup could not be completed."
    except requests.exceptions.Timeout:
        result["status"] = "Lookup Timed Out"
        result["details"] = "Safe Browsing API lookup timed out after 5 seconds."
    except Exception as e:
        result["status"] = "Lookup Error"
        result["details"] = f"Failed to query Google Safe Browsing: {str(e)}"

    return result


def perform_threat_intelligence_lookup(target_url: str, domain: str) -> Dict[str, Any]:
    """
    Aggregates threat intelligence from Google Safe Browsing, URLhaus, and heuristic analyzers.
    Never declares a site 'illegal' or treats API errors as clean.
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # 1. Google Safe Browsing
    gsb_result = query_google_safe_browsing(target_url)

    # 2. URLhaus (abuse.ch)
    urlhaus_result = query_urlhaus_api(domain)

    # 3. Static Heuristics
    heuristics_result = check_heuristics_and_reputation(domain, target_url)

    # Determine overall status
    any_match = gsb_result.get("match_found", False) or urlhaus_result.get("match_found", False)
    
    overall_status = "Clean (No Matches)"
    if any_match:
        overall_status = "Known Threat Match Detected"
    elif gsb_result.get("status") == "API Key Not Configured" and urlhaus_result.get("status") == "No Match Found":
        overall_status = "No URLhaus Matches (Google Safe Browsing Unconfigured)"
    elif "Error" in gsb_result.get("status", "") or "Error" in urlhaus_result.get("status", ""):
        overall_status = "Inconclusive (One or more queries failed)"

    return {
        "timestamp": timestamp,
        "overall_status": overall_status,
        "any_match_found": any_match,
        "providers": {
            "google_safe_browsing": gsb_result,
            "urlhaus": urlhaus_result,
            "heuristics": heuristics_result
        },
        "disclaimer": (
            "Threat intelligence lookups reflect matches against external security threat databases at the time of query. "
            "A clean result does not guarantee that a website is free of compromise, nor do matches indicate legal conclusions."
        )
    }
