"""
SSRF (Server-Side Request Forgery) Guard Module.
Validates URLs, resolves domain names, and blocks requests to private, loopback,
multicast, link-local, carrier-grade NAT, and cloud metadata IP addresses.
Includes a safe HTTP client wrapper with redirect re-validation and size limits.
"""

import ipaddress
import socket
import warnings
from urllib.parse import urlparse, urljoin
from typing import Tuple, List, Optional

# Suppress minor dependency warning for requests/urllib3 mismatch
warnings.filterwarnings("ignore", message="urllib3 .* or chardet .* doesn't match")

import requests
from config import Config

# IPv4 blocked networks (RFC 1918, RFC 3927 link-local, loopback, carrier-grade NAT, multicast, reserved)
BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source address)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private-Use
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (Carrier-Grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (includes 169.254.169.254 AWS/GCP metadata)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private-Use
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private-Use
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

# IPv6 blocked networks
BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),             # Unspecified address
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local Addresses (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]


class SSRFValidationError(Exception):
    """Raised when a URL or resolved destination fails security validation."""
    pass


def is_ip_address_blocked(ip_str: str) -> Tuple[bool, str]:
    """
    Checks if an IP address string belongs to a forbidden/private/internal range.
    Returns (is_blocked, reason).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if ip.is_loopback:
        return True, f"Loopback address ({ip_str}) is prohibited."
    if ip.is_private:
        return True, f"Private/internal network address ({ip_str}) is prohibited."
    if ip.is_link_local:
        return True, f"Link-local / cloud metadata address ({ip_str}) is prohibited."
    if ip.is_multicast:
        return True, f"Multicast address ({ip_str}) is prohibited."
    if ip.is_reserved:
        return True, f"Reserved IP address ({ip_str}) is prohibited."

    if isinstance(ip, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if ip in net:
                return True, f"IPv4 address {ip_str} falls within blocked network {net}."
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in BLOCKED_IPV6_NETWORKS:
            if ip in net:
                return True, f"IPv6 address {ip_str} falls within blocked network {net}."

    return False, "IP address is public and routable."


def resolve_and_validate_hostname(hostname: str) -> List[str]:
    """
    Resolves hostname to IP addresses and ensures EVERY resolved IP is public.
    Returns a list of resolved public IP addresses.
    Raises SSRFValidationError if resolution fails or any IP is in a blocked range.
    """
    if not hostname:
        raise SSRFValidationError("Hostname cannot be empty.")

    # Strip port if present in hostname string
    if ":" in hostname and not hostname.startswith("["):
        hostname = hostname.split(":", 1)[0]
    elif hostname.startswith("[") and "]" in hostname:
        hostname = hostname[1:hostname.index("]")]

    # Reject localhost explicitly
    if hostname.lower() in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        raise SSRFValidationError(f"Target host '{hostname}' is a forbidden local name.")

    try:
        # Resolve address records (both IPv4 and IPv6)
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise SSRFValidationError(f"DNS resolution failed for '{hostname}': {e.strerror or 'Host not found'}")
    except Exception as e:
        raise SSRFValidationError(f"DNS lookup error for '{hostname}': {str(e)}")

    if not addr_info:
        raise SSRFValidationError(f"No IP addresses could be resolved for '{hostname}'.")

    resolved_ips = []
    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    # Validate all resolved IPs
    for ip in resolved_ips:
        blocked, reason = is_ip_address_blocked(ip)
        if blocked:
            raise SSRFValidationError(
                f"Security Restriction: Target '{hostname}' resolved to blocked address '{ip}'. {reason}"
            )

    return resolved_ips


def validate_target_url(raw_url: str) -> Tuple[str, str, List[str]]:
    """
    Validates a target URL:
    - Checks scheme (only http and https allowed)
    - If scheme is omitted, defaults to https://
    - Resolves and verifies destination IPs against SSRF restrictions
    Returns (normalized_url, hostname, resolved_ips).
    """
    url = raw_url.strip()
    if not url:
        raise SSRFValidationError("Please provide a valid website URL.")

    # Check if a scheme was provided
    parsed_initial = urlparse(url)
    if parsed_initial.scheme:
        if parsed_initial.scheme.lower() not in ("http", "https"):
            raise SSRFValidationError(
                f"Scheme '{parsed_initial.scheme}' is unsupported. Only HTTP and HTTPS protocols are permitted."
            )
    else:
        # If no scheme was specified, default to https://
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFValidationError(f"Scheme '{parsed.scheme}' is unsupported. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError(f"Invalid URL '{raw_url}': missing hostname.")

    resolved_ips = resolve_and_validate_hostname(hostname)
    return url, hostname, resolved_ips


def safe_http_fetch(url: str, timeout: Optional[int] = None, max_redirects: Optional[int] = None) -> Tuple[requests.Response, List[dict]]:
    """
    Safely fetches a URL by:
    1. Validating initial URL and resolved IPs.
    2. Enforcing max redirect limits manually.
    3. Re-validating every redirect target IP before following.
    4. Streaming response content up to MAX_CONTENT_SIZE_BYTES to prevent memory exhaustion / zip bombs.
    
    Returns (final_response, redirect_history_list).
    """
    timeout = timeout or Config.MAX_SCAN_TIMEOUT
    max_redirects = max_redirects or Config.MAX_REDIRECTS
    max_size = Config.MAX_CONTENT_SIZE_BYTES

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (Security-Scanner-Bot/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })

    current_url = url
    redirect_history = []
    response = None

    for hop in range(max_redirects + 1):
        # Validate current hop destination against SSRF
        validate_target_url(current_url)

        try:
            # We set allow_redirects=False to inspect each redirection jump
            resp = session.get(current_url, timeout=timeout, allow_redirects=False, stream=True, verify=True)
        except requests.exceptions.SSLError:
            # If verification fails, try again with verify=False to inspect self-signed/invalid certs,
            # but record cert failure
            try:
                resp = session.get(current_url, timeout=timeout, allow_redirects=False, stream=True, verify=False)
                resp.ssl_verification_error = True
            except requests.exceptions.RequestException as e:
                raise SSRFValidationError(f"Connection failed to '{current_url}': {str(e)}")
        except requests.exceptions.Timeout:
            raise SSRFValidationError(f"Connection to '{current_url}' timed out after {timeout} seconds.")
        except requests.exceptions.RequestException as e:
            raise SSRFValidationError(f"Failed to connect to '{current_url}': {str(e)}")

        response = resp

        # Check if redirect status code
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                break
            
            # Form absolute URL for next jump
            next_url = urljoin(current_url, location)
            redirect_history.append({
                "from_url": current_url,
                "status_code": resp.status_code,
                "to_url": next_url
            })
            current_url = next_url
        else:
            # Terminal destination reached
            break

    # Read response content safely up to MAX_CONTENT_SIZE_BYTES
    content_chunks = []
    total_bytes = 0
    for chunk in response.iter_content(chunk_size=8192):
        if chunk:
            content_chunks.append(chunk)
            total_bytes += len(chunk)
            if total_bytes > max_size:
                # Truncate content once max size is exceeded
                break
    
    # Store aggregated raw content on response object
    response._content = b"".join(content_chunks)
    return response, redirect_history
