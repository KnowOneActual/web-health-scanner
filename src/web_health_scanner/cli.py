import argparse
import json
import os
import subprocess
import sys
import shutil
import requests
import dns.resolver
import tempfile
from urllib.parse import urlparse, urljoin
import lxml.etree as ET
import socket
import ipaddress
from datetime import datetime
from bs4 import BeautifulSoup
import webtech
from webtech.utils import ConnectionException
from concurrent.futures import ThreadPoolExecutor, as_completed

# Rich for beautiful CLI
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box

console = Console()

# --- Security Helpers ---


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


# --- Configuration ---
TESTSSL_PATH = "./testssl.sh/testssl.sh"
NMAP_PATH = "nmap"
DEFAULT_OUTPUT_FILENAME = "report.json"


# --- Helper Functions ---


def check_dependencies(skip_slow_tools=False):
    """Checks if external tools (nmap, testssl.sh) are installed/available."""
    missing = []

    if not shutil.which(NMAP_PATH):
        if not skip_slow_tools:
            missing.append("nmap (not found in PATH)")

    if not skip_slow_tools:
        if not os.path.exists(TESTSSL_PATH):
            missing.append(f"testssl.sh (not found at {TESTSSL_PATH})")
        else:
            if not os.access(TESTSSL_PATH, os.X_OK):
                try:
                    os.chmod(TESTSSL_PATH, 0o755)
                except OSError:
                    missing.append(
                        f"testssl.sh found but not executable (try 'chmod +x {TESTSSL_PATH}')"
                    )

    return missing


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


def parse_nmap_xml(xml_output):
    """Parses the raw Nmap XML to extract open ports and services."""
    try:
        if isinstance(xml_output, dict) and "status" in xml_output:
            return xml_output

        parser = ET.XMLParser(
            no_network=True, dtd_validation=False, resolve_entities=False
        )
        root = ET.fromstring(xml_output.encode("utf-8"), parser=parser)

        host = root.find("host")
        if host is None:
            return {"status": "error", "details": "No host information found."}

        host_status_elem = host.find("status")
        host_status = host_status_elem.get("state") if host_status_elem is not None else "unknown"
        open_ports = []

        for port in host.findall("ports/port"):
            if port.find("state").get("state") == "open":
                service = port.find("service")
                port_info = {
                    "portid": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": "open",
                    "service": service.get("name") if service is not None else "unknown",
                    "product": service.get("product") if service is not None else "",
                    "version": service.get("version") if service is not None else "",
                }
                open_ports.append(port_info)

        return {"status": "success", "host_status": host_status, "open_ports": open_ports}
    except Exception as e:
        return {"status": "error", "details": f"XML parsing error: {str(e)}"}


def parse_pagespeed(raw_data):
    """Parses the raw PageSpeed JSON to extract key scores."""
    try:
        if "status" in raw_data and raw_data["status"] != "success":
            return raw_data

        if "lighthouseResult" not in raw_data:
            return {"status": "error", "details": "PageSpeed response missing lighthouseResult."}

        categories = raw_data["lighthouseResult"]["categories"]

        def get_score(category_name):
            score = categories.get(category_name, {}).get("score")
            return int(score * 100) if score is not None else 0

        return {
            "status": "success",
            "scores": {
                "performance": get_score("performance"),
                "accessibility": get_score("accessibility"),
                "best_practices": get_score("best_practices"),
                "seo": get_score("seo"),
            },
        }
    except Exception as e:
        return {"status": "error", "details": f"Failed to parse PageSpeed JSON: {str(e)}"}


def parse_linkchecker(raw_data):
    """Parses the raw linkchecker output to extract a summary."""
    if "status" not in raw_data or raw_data["status"] != "success":
        return raw_data
    return {
        "status": "success",
        "summary": raw_data.get("summary", {}),
        "broken_links": raw_data.get("broken_links", []),
    }


def parse_dns_records(raw_data):
    """Parses the raw DNS records to remove empty entries."""
    if "status" not in raw_data or raw_data["status"] != "success":
        return raw_data
    raw_records = raw_data.get("data", {})
    cleaned_records = {k: v for k, v in raw_records.items() if v}
    if not cleaned_records:
        return {"status": "error", "details": "No DNS data found."}
    return {"status": "success", "records": cleaned_records}


def print_summary(report):
    """Prints a beautiful summary of the scan results using Rich."""
    
    console.print(Panel(f"[bold cyan]SCAN SUMMARY:[/bold cyan] [green]{report['scan_target']}[/green]", box=box.DOUBLE))

    # 1. PageSpeed
    ps = report["reports"].get("pagespeed", {})
    if ps.get("status") == "success":
        scores = ps.get("scores", {})
        table = Table(title="Google PageSpeed", box=box.SIMPLE)
        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right")
        
        for cat, score in scores.items():
            color = "green" if score >= 90 else "yellow" if score >= 70 else "red"
            table.add_row(cat.replace("_", " ").title(), f"[{color}]{score}/100[/{color}]")
        console.print(table)
    else:
        console.print(f"[bold red]![/bold red] PageSpeed: {ps.get('details', 'Skipped')}")

    # 2. Tech Stack & Headers
    grid = Table.grid(expand=True)
    grid.add_column()
    grid.add_column()

    # Tech Stack
    tech = report["reports"].get("tech_stack", {})
    tech_content = ""
    if tech.get("status") == "success":
        technologies = tech.get("technologies", [])
        if technologies:
            tech_content = "\n".join([f"• {t}" for t in technologies])
        else:
            tech_content = "[dim]No technologies detected[/dim]"
    else:
        tech_content = f"[red]Scan Failed: {tech.get('details')}[/red]"
    
    # Headers
    headers = report["reports"].get("security_headers", {})
    header_content = ""
    if headers.get("status") == "success":
        missing = headers.get("missing_headers", [])
        if not missing:
            header_content = "[green]All key headers found![/green]"
        else:
            header_content = "[red]Missing Headers:[/red]\n" + "\n".join([f"• {h}" for h in missing])
    else:
        header_content = f"[red]Scan Failed: {headers.get('details')}[/red]"

    grid.add_row(
        Panel(tech_content, title="[bold]Identified Technologies[/bold]", border_style="blue"),
        Panel(header_content, title="[bold]Security Headers[/bold]", border_style="magenta")
    )
    console.print(grid)

    # 3. Broken Links & DNS
    grid2 = Table.grid(expand=True)
    grid2.add_column()
    grid2.add_column()

    # Links
    links = report["reports"].get("linkchecker", {})
    link_content = ""
    if links.get("status") == "success":
        count = links.get("summary", {}).get("broken_count", 0)
        if count == 0:
            link_content = "[green]No broken links found.[/green]"
        else:
            link_content = f"[red]Found {count} broken links.[/red]\n" + "\n".join([f"• {l['status_code']}: {l['url']}" for l in links.get('broken_links', [])[:3]])
    else:
        link_content = f"[red]Scan Failed: {links.get('details')}[/red]"

    # DNS
    dns_rep = report["reports"].get("dns", {})
    dns_content = ""
    if dns_rep.get("status") == "success":
        records = dns_rep.get("records", {})
        dns_content = "\n".join([f"[bold]{k}:[/bold] {', '.join(v[:2])}{'...' if len(v)>2 else ''}" for k, v in records.items()])
    else:
        dns_content = f"[red]Scan Failed: {dns_rep.get('details')}[/red]"

    grid2.add_row(
        Panel(link_content, title="[bold]Broken Links[/bold]", border_style="yellow"),
        Panel(dns_content, title="[bold]DNS Records[/bold]", border_style="cyan")
    )
    console.print(grid2)

    # 4. Infrastructure (Nmap & SSL)
    nmap = report["reports"].get("nmap", {})
    ssl = report["reports"].get("testssl", {})
    
    infra_table = Table(title="Infrastructure Security", box=box.SIMPLE, expand=True)
    infra_table.add_column("Scanner", style="bold")
    infra_table.add_column("Result")

    if nmap.get("status") == "success":
        ports = nmap.get("open_ports", [])
        res = ", ".join([f"{p['portid']}/{p['service']}" for p in ports]) if ports else "No open ports found"
        infra_table.add_row("Nmap (Ports)", res)
    else:
        infra_table.add_row("Nmap (Ports)", f"[dim]{nmap.get('status', 'Skipped')}[/dim]")

    if ssl.get("status") == "success":
        infra_table.add_row("SSL/TLS", "[green]Scan complete. See JSON for details.[/green]")
    else:
        infra_table.add_row("SSL/TLS", f"[dim]{ssl.get('status', 'Skipped')}[/dim]")

    console.print(infra_table)
    console.print("\n" + "=" * 40 + "\n")


# --- Scan Functions ---


def get_tech_stack(target_url):
    """Runs the webtech scan to identify site technologies."""
    try:
        wt = webtech.WebTech()
        report = wt.start_from_url(target_url, timeout=5)
        if isinstance(report, dict):
            return {"status": "success", "technologies": report.get("tech_names", [])}
        elif isinstance(report, str):
            tech_names = []
            capture = False
            for line in report.split("\n"):
                clean_line = line.strip()
                if "Detected technologies:" in clean_line: capture = True; continue
                if "Detected the following" in clean_line: capture = False; continue
                if capture and clean_line.startswith("-"):
                    tech_name = clean_line.lstrip("- ").strip()
                    if tech_name: tech_names.append(tech_name)
            return {"status": "success", "technologies": tech_names}
        return {"status": "error", "details": "Invalid report object."}
    except Exception as e:
        return {"status": "error", "details": str(e)}


def get_pagespeed(target_url, api_key):
    """Runs the Google PageSpeed Insights scan."""
    hostname = urlparse(target_url).hostname
    validation = resolve_and_validate_target(hostname)
    if validation["status"] != "success":
        return {"status": "error", "details": f"SSRF Blocked: {validation['details']}"}

    if not api_key:
        return {"status": "skipped", "details": "No API key provided."}

    api_url = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
    params = {
        "url": target_url,
        "key": api_key,
        "strategy": "DESKTOP",
        "category": ["PERFORMANCE", "ACCESSIBILITY", "BEST_PRACTICES", "SEO"],
    }

    try:
        response = requests.get(api_url, params=params, timeout=60)
        response.raise_for_status()
        data = response.json()
        data["status"] = "success"
        return data
    except Exception as e:
        return {"status": "error", "details": str(e)}


def analyze_security_headers(target_url):
    """Fetches headers using 'requests' and checks for key security headers."""
    HEADERS_TO_CHECK = [
        "Content-Security-Policy", "Strict-Transport-Security",
        "X-Content-Type-Options", "X-Frame-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()
        response_headers = response.headers
        missing = [h for h in HEADERS_TO_CHECK if h not in response_headers]
        found = [h for h in HEADERS_TO_CHECK if h in response_headers]
        return {"status": "success", "found_headers": found, "missing_headers": missing}
    except Exception as e:
        return {"status": "error", "details": str(e)}


def get_testssl(target_url):
    """Runs the testssl.sh scan."""
    hostname = urlparse(target_url).hostname
    validation = resolve_and_validate_target(hostname)
    if validation["status"] != "success":
        return {"status": "error", "details": f"SSRF Blocked: {validation['details']}"}

    try:
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json") as tmpfile:
            json_output_file = tmpfile.name
        command = [TESTSSL_PATH, "--jsonfile", json_output_file, "-U", hostname]
        run_subprocess(command, timeout=600)
        if os.path.exists(json_output_file) and os.path.getsize(json_output_file) > 0:
            with open(json_output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            os.remove(json_output_file)
            return {"status": "success", "data": data}
        if os.path.exists(json_output_file): os.remove(json_output_file)
        return {"status": "error", "details": "testssl.sh failed or timed out."}
    except Exception as e:
        return {"status": "error", "details": str(e)}


def get_nmap(target_url):
    """Runs the nmap scan."""
    hostname = urlparse(target_url).hostname
    validation = resolve_and_validate_target(hostname)
    if validation["status"] != "success":
        return {"status": "error", "details": f"SSRF Blocked: {validation['details']}"}

    command = [NMAP_PATH, "-F", "-sV", "-oX", "-", validation["ip_address"]]
    try:
        raw_output = run_subprocess(command, timeout=120)
        if raw_output: return {"status": "success", "xml_data": raw_output}
        return {"status": "error", "details": "nmap returned no output."}
    except Exception as e:
        return {"status": "error", "details": str(e)}


def get_linkchecker(target_url):
    """Runs a simple link check on the target URL's homepage."""
    hostname = urlparse(target_url).hostname
    validation = resolve_and_validate_target(hostname)
    if validation["status"] != "success":
        return {"status": "error", "details": f"SSRF Blocked: {validation['details']}"}

    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(target_url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "lxml")
        links = soup.find_all("a", href=True)
        broken_links = []
        total_found = 0
        
        # Limit to first 20 links for speed in a health check
        for link in links[:20]:
            href = link["href"]
            full_url = urljoin(target_url, href)
            if full_url.startswith(("mailto:", "tel:", "#")): continue
            total_found += 1
            try:
                l_res = requests.head(full_url, headers=headers, timeout=5, allow_redirects=True)
                if l_res.status_code >= 400:
                    broken_links.append({"url": full_url, "status_code": l_res.status_code})
            except Exception:
                broken_links.append({"url": full_url, "status_code": "Error"})

        return {
            "status": "success",
            "summary": {"total_links_checked": total_found, "broken_count": len(broken_links)},
            "broken_links": broken_links,
        }
    except Exception as e:
        return {"status": "error", "details": str(e)}


def get_dns_records(target_url):
    """Runs the dnspython scan."""
    hostname = urlparse(target_url).hostname
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
    results = {}
    try:
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(hostname, rtype)
                results[rtype] = [r.to_text() for r in answers]
            except Exception:
                results[rtype] = []
        return {"status": "success", "data": results}
    except Exception as e:
        return {"status": "error", "details": str(e)}


# --- Main Execution ---


def main():
    parser = argparse.ArgumentParser(
        description="Run a full website health check and audit.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("url", type=str, help="The target URL to scan")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT_FILENAME, help="JSON output report.")
    parser.add_argument("--api-key", type=str, default=os.environ.get("PAGESPEED_API_KEY"), help="Google PageSpeed API key.")
    parser.add_argument("--summary", action="store_true", help="Print summary to terminal.")
    parser.add_argument("--fast", action="store_true", help="Skip slow scans (nmap, testssl).")

    args = parser.parse_args()
    
    missing = check_dependencies(skip_slow_tools=args.fast)
    if missing:
        console.print(Panel(f"[bold red]Missing Dependencies:[/bold red]\n" + "\n".join([f"• {m}" for m in missing]), title="Error"))
        sys.exit(1)

    if not args.url.startswith(("http://", "https://")): args.url = f"https://{args.url}"
    args.url = args.url.rstrip(')/"')
    target_hostname = urlparse(args.url).hostname.replace("www.", "")

    master_report = {
        "scan_target": args.url,
        "scan_timestamp": datetime.now().isoformat(),
        "reports": {},
    }

    scans = [
        ("tech_stack", get_tech_stack, (args.url,)),
        ("pagespeed", lambda u, k: parse_pagespeed(get_pagespeed(u, k)), (args.url, args.api_key)),
        ("security_headers", analyze_security_headers, (args.url,)),
        ("linkchecker", lambda u: parse_linkchecker(get_linkchecker(u)), (args.url,)),
        ("dns", lambda u: parse_dns_records(get_dns_records(u)), (args.url,)),
    ]

    if not args.fast:
        scans.append(("testssl", get_testssl, (args.url,)))
        scans.append(("nmap", lambda u: parse_nmap_xml(get_nmap(u).get("xml_data", "")), (args.url,)))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        
        overall_task = progress.add_task("[cyan]Running scans...", total=len(scans))
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_name = {executor.submit(func, *args_): name for name, func, args_ in scans}
            
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    master_report["reports"][name] = future.result()
                except Exception as e:
                    master_report["reports"][name] = {"status": "error", "details": str(e)}
                progress.update(overall_task, advance=1)

    # File Naming
    if args.output == DEFAULT_OUTPUT_FILENAME:
        safe_hostname = target_hostname.replace(".", "-")
        args.output = f"site-scan-{safe_hostname}-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    safe_output_path = os.path.basename(args.output)
    try:
        with open(safe_output_path, "w", encoding="utf-8") as f:
            json.dump(master_report, f, indent=4)
        console.print(f"\n[bold green]✓[/bold green] Master report saved to [bold cyan]{safe_output_path}[/bold cyan]")
        if args.summary: print_summary(master_report)
    except Exception as e:
        console.print(f"[bold red]Error saving report:[/bold red] {e}")


if __name__ == "__main__":
    main()
