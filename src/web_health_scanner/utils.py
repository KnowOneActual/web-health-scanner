import socket
import ipaddress
import subprocess
import shutil
import os
from urllib.parse import urlparse

def resolve_and_validate_target(hostname):
    """
    FIX: SSRF Mitigation
    Resolves hostname to IP and checks for private IP ranges (RFC 1918, loopback).
    Returns a dict with status and the resolved IP address if successful.
    """
    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    try:
        ip_address = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_address)

        for network in PRIVATE_NETWORKS:
            if ip_obj in network:
                return {
                    "status": "error",
                    "details": f"Resolved IP '{ip_address}' is a private address. SSRF attempt blocked.",
                }

        return {"status": "success", "ip_address": ip_address}
    except socket.gaierror:
        return {
            "status": "error",
            "details": f"Target hostname '{hostname}' could not be resolved.",
        }
    except ValueError as e:
        return {
            "status": "error",
            "details": f"Invalid address format from resolution: {e}",
        }

def run_subprocess(command, timeout=60):
    """Helper to run a subprocess, capture output, and handle errors."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            timeout=timeout,
        )
        return result.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None

def check_dependencies(nmap_path, testssl_path, skip_slow_tools=False):
    """Checks if external tools (nmap, testssl.sh) are installed/available."""
    missing = []

    if not shutil.which(nmap_path):
        if not skip_slow_tools:
            missing.append("nmap (not found in PATH)")

    if not skip_slow_tools:
        if not os.path.exists(testssl_path):
            missing.append(f"testssl.sh (not found at {testssl_path})")
        else:
            if not os.access(testssl_path, os.X_OK):
                try:
                    os.chmod(testssl_path, 0o755)
                except OSError:
                    missing.append(
                        f"testssl.sh found but not executable (try 'chmod +x {testssl_path}')"
                    )

    return missing
