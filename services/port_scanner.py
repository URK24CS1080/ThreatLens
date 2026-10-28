"""
Port and Service Discovery Module.
Performs authorized, safe port scanning on explicitly verified targets.
Uses Nmap when installed on the system; otherwise provides a safe, non-intrusive
TCP connect probe fallback while clearly reporting Nmap's availability.
"""

import shutil
import socket
import subprocess
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from config import Config
from services.ssrf_guard import is_ip_address_blocked, SSRFValidationError

# Map of standard well-known ports to common service names
WELL_KNOWN_SERVICES = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Service)",
    110: "POP3 (Post Office Protocol)",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (Encrypted Web Service)",
    465: "SMTPS (Secure Mail)",
    587: "SMTP Submission",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database",
    8080: "HTTP-Alt / Proxy",
    8443: "HTTPS-Alt"
}


def is_nmap_available() -> bool:
    """Checks whether the 'nmap' executable is available in the system PATH."""
    return shutil.which("nmap") is not None


def scan_ports_via_socket(target_ip: str, ports: List[int]) -> List[Dict[str, Any]]:
    """
    Performs a safe, non-destructive TCP connect scan using standard Python sockets.
    Used when Nmap is not installed or when non-privileged probe is requested.
    """
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)  # strict short timeout per port
        start_t = time.time()
        try:
            res = sock.connect_ex((target_ip, port))
            if res == 0:
                # Port is open
                results.append({
                    "port": port,
                    "state": "open",
                    "service": WELL_KNOWN_SERVICES.get(port, "Unknown Service"),
                    "version": "TCP Connect Handshake Successful",
                    "latency_ms": round((time.time() - start_t) * 1000, 1)
                })
        except Exception:
            pass
        finally:
            sock.close()
    return results


def scan_ports_via_nmap(target_ip: str, ports: List[int]) -> Tuple[List[Dict[str, Any]], str]:
    """
    Invokes Nmap safely using a structured argument list (no shell concatenation).
    Parses open ports and detected service versions.
    """
    port_arg = ",".join(str(p) for p in ports)
    # Safe argument list with strict target IP and timeout
    cmd = [
        "nmap",
        "-sV",
        "--version-light",
        "-Pn",
        "-T4",
        "-p", port_arg,
        "--open",
        target_ip
    ]
    
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=25,
            shell=False  # Crucial security safeguard: prevent shell injection
        )
        output = proc.stdout
    except subprocess.TimeoutExpired:
        return [], "Nmap scan timed out after 25 seconds."
    except Exception as e:
        return [], f"Failed to execute Nmap process: {str(e)}"

    # Parse standard Nmap output lines: e.g. "80/tcp open  http    Apache httpd 2.4.41"
    results = []
    pattern = re.compile(r"^(\d+)/tcp\s+(\w+)\s+([\w\-]+)\s*(.*)$")

    for line in output.splitlines():
        line = line.strip()
        match = pattern.match(line)
        if match:
            port_num = int(match.group(1))
            state = match.group(2)
            svc = match.group(3)
            version_info = match.group(4).strip()
            results.append({
                "port": port_num,
                "state": state,
                "service": WELL_KNOWN_SERVICES.get(port_num, svc),
                "version": version_info or svc,
                "latency_ms": None
            })

    return results, output


def perform_authorized_port_scan(
    target_host: str,
    target_ip: str,
    user_authorized: bool,
    custom_ports: Optional[List[int]] = None
) -> Dict[str, Any]:
    """
    Performs port scanning only when explicitly authorized by the user.
    Enforces SSRF checks, rate limits, and safe execution.
    """
    start_time = time.time()
    
    # 1. Authorization check
    if not user_authorized:
        return {
            "enabled": False,
            "status": "Skipped",
            "message": "Port scanning was skipped: Explicit authorization confirmation was not provided.",
            "open_ports": [],
            "nmap_available": is_nmap_available(),
            "duration_seconds": 0.0
        }

    # 2. Global configuration toggle
    if not Config.ALLOW_PORT_SCAN:
        return {
            "enabled": False,
            "status": "Disabled",
            "message": "Port scanning is disabled in the application configuration (ALLOW_PORT_SCAN=False).",
            "open_ports": [],
            "nmap_available": is_nmap_available(),
            "duration_seconds": 0.0
        }

    # 3. SSRF destination check
    blocked, reason = is_ip_address_blocked(target_ip)
    if blocked:
        raise SSRFValidationError(f"Port scanning blocked: Destination IP '{target_ip}' is not permitted. {reason}")

    # 4. Filter and cap port list (maximum 25 ports to prevent flooding)
    candidate_ports = custom_ports if custom_ports else Config.DEFAULT_COMMON_PORTS
    sanitized_ports = []
    for p in candidate_ports:
        try:
            p_int = int(p)
            if 1 <= p_int <= 65535 and p_int not in sanitized_ports:
                sanitized_ports.append(p_int)
        except (ValueError, TypeError):
            continue
    
    ports_to_scan = sanitized_ports[:25]
    if not ports_to_scan:
        ports_to_scan = Config.DEFAULT_COMMON_PORTS

    # 5. Execute scan using Nmap or Fallback
    nmap_present = is_nmap_available()
    open_ports = []
    raw_info = ""

    if nmap_present:
        method = "Nmap (-sV Service Detection)"
        open_ports, raw_info = scan_ports_via_nmap(target_ip, ports_to_scan)
    else:
        method = "TCP Connect Socket Probe (Nmap not installed on system path)"
        open_ports = scan_ports_via_socket(target_ip, ports_to_scan)
        raw_info = (
            "Nmap binary was not detected on this machine. "
            "A non-intrusive TCP socket handshake probe was performed on common authorized ports."
        )

    duration = round(time.time() - start_time, 2)

    return {
        "enabled": True,
        "status": "Completed",
        "method": method,
        "nmap_available": nmap_present,
        "target_ip": target_ip,
        "ports_checked": ports_to_scan,
        "open_ports": open_ports,
        "duration_seconds": duration,
        "notes": raw_info,
        "security_warning": (
            "Notice: An open port indicates an accessible network service, not necessarily an exploitable vulnerability. "
            "Inspect running services to verify they are intended to be publicly exposed."
        )
    }
