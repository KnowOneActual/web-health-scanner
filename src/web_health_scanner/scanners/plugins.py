import json
import os
import tempfile
from urllib.parse import urljoin, urlparse

import dns.resolver
import lxml.etree as ET
import requests
import webtech
from bs4 import BeautifulSoup

from web_health_scanner.scanners.base import BaseScanner
from web_health_scanner.utils import resolve_and_validate_target, run_subprocess


class TechStackScanner(BaseScanner):
    def __init__(self):
        super().__init__("tech_stack", "General Tech Stack")

    def run(self, target_url, **kwargs):
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
                    if "Detected technologies:" in clean_line:
                        capture = True
                        continue
                    if "Detected the following" in clean_line:
                        capture = False
                        continue
                    if capture and clean_line.startswith("-"):
                        tech_name = clean_line.lstrip("- ").strip()
                        if tech_name:
                            tech_names.append(tech_name)
                return {"status": "success", "technologies": tech_names}
            return {"status": "error", "details": "Invalid report object."}
        except Exception as e:
            return {"status": "error", "details": str(e)}


class PageSpeedScanner(BaseScanner):
    def __init__(self):
        super().__init__("pagespeed", "Google PageSpeed")

    def run(self, target_url, **kwargs):
        api_key = kwargs.get("api_key")
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

            if "lighthouseResult" not in data:
                return {
                    "status": "error",
                    "details": "PageSpeed response missing lighthouseResult.",
                }

            categories = data["lighthouseResult"]["categories"]

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
            return {"status": "error", "details": str(e)}


class SecurityHeadersScanner(BaseScanner):
    def __init__(self):
        super().__init__("security_headers", "Security Headers")

    def run(self, target_url, **kwargs):
        headers_to_check = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
            response.raise_for_status()
            response_headers = response.headers
            missing = [h for h in headers_to_check if h not in response_headers]
            found = [h for h in headers_to_check if h in response_headers]
            return {"status": "success", "found_headers": found, "missing_headers": missing}
        except Exception as e:
            return {"status": "error", "details": str(e)}


class LinkCheckerScanner(BaseScanner):
    def __init__(self):
        super().__init__("linkchecker", "Broken Links")

    def run(self, target_url, **kwargs):
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

            for link in links[:20]:
                href = link["href"]
                full_url = urljoin(target_url, href)
                if full_url.startswith(("mailto:", "tel:", "#")):
                    continue
                total_found += 1
                try:
                    l_res = requests.head(
                        full_url, headers=headers, timeout=5, allow_redirects=True
                    )
                    if l_res.status_code >= 400:
                        broken_links.append({"url": full_url, "status_code": l_res.status_code})
                except Exception:
                    broken_links.append({"url": full_url, "status_code": "Error"})

            return {
                "status": "success",
                "summary": {
                    "total_links_checked": total_found,
                    "broken_count": len(broken_links),
                },
                "broken_links": broken_links,
            }
        except Exception as e:
            return {"status": "error", "details": str(e)}


class DNSScanner(BaseScanner):
    def __init__(self):
        super().__init__("dns", "DNS Records")

    def run(self, target_url, **kwargs):
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
            cleaned_records = {k: v for k, v in results.items() if v}
            if not cleaned_records:
                return {"status": "error", "details": "No DNS data found."}
            return {"status": "success", "records": cleaned_records}
        except Exception as e:
            return {"status": "error", "details": str(e)}


class NmapScanner(BaseScanner):
    def __init__(self):
        super().__init__("nmap", "Network Ports", is_fast=False)

    def run(self, target_url, **kwargs):
        hostname = urlparse(target_url).hostname
        validation = resolve_and_validate_target(hostname)
        if validation["status"] != "success":
            return {"status": "error", "details": f"SSRF Blocked: {validation['details']}"}

        nmap_path = kwargs.get("nmap_path", "nmap")
        command = [nmap_path, "-F", "-sV", "-oX", "-", validation["ip_address"]]
        try:
            raw_output = run_subprocess(command, timeout=120)
            if not raw_output:
                return {"status": "error", "details": "nmap returned no output."}

            parser = ET.XMLParser(no_network=True, dtd_validation=False, resolve_entities=False)
            root = ET.fromstring(raw_output.encode("utf-8"), parser=parser)
            host = root.find("host")
            if host is None:
                return {"status": "error", "details": "No host information found."}

            host_status_elem = host.find("status")
            host_status = (
                host_status_elem.get("state") if host_status_elem is not None else "unknown"
            )
            open_ports = []
            for port in host.findall("ports/port"):
                if port.find("state").get("state") == "open":
                    service = port.find("service")
                    open_ports.append(
                        {
                            "portid": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": "open",
                            "service": service.get("name") if service is not None else "unknown",
                            "product": service.get("product") if service is not None else "",
                            "version": service.get("version") if service is not None else "",
                        }
                    )
            return {"status": "success", "host_status": host_status, "open_ports": open_ports}
        except Exception as e:
            return {"status": "error", "details": f"Nmap error: {str(e)}"}


class TestSSLScanner(BaseScanner):
    def __init__(self):
        super().__init__("testssl", "SSL/TLS Security", is_fast=False)

    def run(self, target_url, **kwargs):
        hostname = urlparse(target_url).hostname
        validation = resolve_and_validate_target(hostname)
        if validation["status"] != "success":
            return {"status": "error", "details": f"SSRF Blocked: {validation['details']}"}

        testssl_path = kwargs.get("testssl_path", "./testssl.sh/testssl.sh")
        try:
            with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json") as tmpfile:
                json_output_file = tmpfile.name
            command = [testssl_path, "--jsonfile", json_output_file, "-U", hostname]
            run_subprocess(command, timeout=600)
            if os.path.exists(json_output_file) and os.path.getsize(json_output_file) > 0:
                with open(json_output_file, encoding="utf-8") as f:
                    data = json.load(f)
                os.remove(json_output_file)
                return {"status": "success", "data": data}
            if os.path.exists(json_output_file):
                os.remove(json_output_file)
            return {"status": "error", "details": "testssl.sh failed or timed out."}
        except Exception as e:
            return {"status": "error", "details": str(e)}
