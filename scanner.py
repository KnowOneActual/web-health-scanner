import argparse
import json
import os
import subprocess
import sys
import requests
import dns.resolver
import tempfile 
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET
from datetime import datetime
from bs4 import BeautifulSoup
import webtech
from webtech.utils import ConnectionException

# --- Configuration ---
# Paths to local tools
# Assumes testssl.sh was cloned into the project directory
TESTSSL_PATH = "./testssl.sh/testssl.sh"
# Assumes nmap is in the system's PATH
NMAP_PATH = "nmap"


# --- Helper Functions ---

def run_subprocess(command, timeout=60):
    """Helper to run a subprocess, capture output, and handle errors."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', timeout=timeout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[Error] Command '{' '.join(command)}' failed with exit code {e.returncode}.", file=sys.stderr)
        print(f"        Stderr: {e.stderr.strip()}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"[Error] Command '{' '.join(command)}' timed out after {timeout} seconds.", file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"[Error] Command not found: '{command[0]}'. Is it installed and in your PATH?", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Error] An unexpected error occurred with subprocess: {e}", file=sys.stderr)
        return None

def parse_nmap_xml(xml_output):
    """Parses the raw Nmap XML to extract open ports and services."""
    try:
        # Pass through errors (e.g., if nmap failed or was skipped)
        if isinstance(xml_output, dict) and 'status' in xml_output:
            return xml_output

        root = ET.fromstring(xml_output)
        host = root.find('host')
        if host is None:
            return {"status": "error", "details": "No host information found in nmap output."}

        host_status_elem = host.find('status')
        host_status = host_status_elem.get('state') if host_status_elem is not None else "unknown"
        open_ports = []
        
        for port in host.findall('ports/port'):
            if port.find('state').get('state') == 'open':
                service = port.find('service')
                port_info = {
                    "portid": port.get('portid'),
                    "protocol": port.get('protocol'),
                    "state": "open",
                    "service": service.get('name') if service is not None else "unknown",
                    "product": service.get('product') if service is not None else "",
                    "version": service.get('version') if service is not None else ""
                }
                open_ports.append(port_info)
                
        return {
            "status": "success",
            "host_status": host_status,
            "open_ports": open_ports
        }
    except ET.ParseError as e:
        print(f"[Error] Failed to parse Nmap XML: {e}", file=sys.stderr)
        return {"status": "error", "details": f"Nmap XML ParseError: {str(e)}"}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in parse_nmap_xml: {e}", file=sys.stderr)
        return {"status": "error", "details": f"XML parsing error: {str(e)}"}

def parse_pagespeed(raw_data):
    """Parses the raw PageSpeed JSON to extract key scores."""
    try:
        # If the scan failed, it will have our custom 'status' key.
        if 'status' in raw_data and raw_data['status'] != 'success':
            return raw_data

        # Handle API errors that don't have our 'status' key
        if 'lighthouseResult' not in raw_data:
            if 'error' in raw_data:
                error_msg = raw_data.get("error", {}).get("message", "Unknown API Error")
                print(f"[Error] PageSpeed API failed: {error_msg}", file=sys.stderr)
                return {"status": "error", "details": f"API Error: {error_msg}"}
            return {"status": "error", "details": "PageSpeed response missing 'lighthouseResult'."}

        categories = raw_data['lighthouseResult']['categories']
        
        # Helper to safely get score, defaulting to 0 if 'score' is None
        def get_score(category_name):
            score = categories.get(category_name, {}).get('score')
            # Check if score is None before multiplying
            return int(score * 100) if score is not None else 0

        performance = get_score('performance')
        accessibility = get_score('accessibility')
        best_practices = get_score('best-practices')
        seo = get_score('seo')

        return {
            "status": "success",
            "scores": {
                "performance": performance,
                "accessibility": accessibility,
                "best_practices": best_practices,
                "seo": seo
            }
        }
    except (KeyError, TypeError, AttributeError) as e:
        # Check if it was an API error we already caught
        if 'status' in raw_data and raw_data['status'] == 'error':
            return raw_data
        print(f"[Error] Failed to parse PageSpeed JSON: {e}", file=sys.stderr)
        return {"status": "error", "details": f"Failed to parse PageSpeed JSON: {str(e)}"}

def parse_linkchecker(raw_data):
    """Parses the raw linkchecker output to extract a summary."""
    try:
        # Pass through errors or non-success statuses
        if 'status' not in raw_data or raw_data['status'] != 'success':
            return raw_data
        
        # Extract the key parts as defined in the roadmap
        summary = raw_data.get("summary", {})
        broken_links = raw_data.get("broken_links", [])
        
        return {
            "status": "success",
            "summary": summary,
            "broken_links": broken_links
        }
    except Exception as e:
        print(f"[Error] An unexpected error occurred in parse_linkchecker: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def parse_dns_records(raw_data):
    """Parses the raw DNS records to remove empty entries."""
    try:
        if 'status' not in raw_data or raw_data['status'] != 'success':
            return raw_data
        
        raw_records = raw_data.get("data", {})
        cleaned_records = {}
        
        if not raw_records:
             return {"status": "error", "details": "No DNS data found to parse."}

        for record_type, records in raw_records.items():
            # Only add the record type to the report if it has entries
            if records:
                cleaned_records[record_type] = records
        
        return {
            "status": "success",
            "records": cleaned_records
        }
    except Exception as e:
        print(f"[Error] An unexpected error occurred in parse_dns_records: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def print_summary(report):
    """Prints a human-readable summary of the scan results to the console."""
    print("\n" + "="*40)
    print(f"   SCAN SUMMARY: {report['scan_target']}")
    print("="*40 + "\n")

    # 1. PageSpeed
    print("--- Google PageSpeed ---")
    ps = report["reports"].get("pagespeed", {})
    if ps.get("status") == "success":
        scores = ps.get("scores", {})
        print(f"  Performance:    {scores.get('performance')}/100")
        print(f"  Accessibility:  {scores.get('accessibility')}/100")
        print(f"  Best Practices: {scores.get('best_practices')}/100")
        print(f"  SEO:            {scores.get('seo')}/100")
    else:
        print(f"  [!] Scan Failed/Skipped: {ps.get('details', 'Unknown error')}")

    # 2. Security Headers
    print("\n--- Security Headers ---")
    headers = report["reports"].get("security_headers", {})
    if headers.get("status") == "success":
        missing = headers.get("missing_headers", [])
        if not missing:
            print("  [+] All key headers found!")
        else:
            print(f"  [!] Missing {len(missing)} headers:")
            for h in missing:
                print(f"      - {h}")
    else:
        print(f"  [!] Scan Failed: {headers.get('details')}")

    # 3. Broken Links
    print("\n--- Broken Links ---")
    links = report["reports"].get("linkchecker", {})
    if links.get("status") == "success":
        broken = links.get("broken_links", [])
        count = links.get("summary", {}).get("broken_count", 0)
        if count == 0:
            print("  [+] No broken links found.")
        else:
            print(f"  [!] Found {count} broken links:")
            # Print first 3 only to keep summary clean
            for link in broken[:3]:
                 print(f"      - {link['status_code']}: {link['url']}")
            if count > 3:
                print(f"      ...and {count - 3} more (see JSON report).")
    else:
        print(f"  [!] Scan Failed: {links.get('details')}")

    # 4. Nmap (Ports)
    print("\n--- Open Ports (Nmap) ---")
    nmap = report["reports"].get("nmap", {})
    if nmap.get("status") == "success":
        ports = nmap.get("open_ports", [])
        if not ports:
            print("  [+] No open ports found (in top 100).")
        else:
            for p in ports:
                print(f"  - Port {p['portid']} ({p['service']}): {p['state']}")
    elif nmap.get("status") == "skipped":
         print("  [i] Skipped (Fast Mode)")
    else:
        print(f"  [!] Scan Failed: {nmap.get('details')}")

    # 5. TestSSL
    print("\n--- SSL/TLS Security ---")
    ssl = report["reports"].get("testssl", {})
    if ssl.get("status") == "success":
        # TestSSL output is huge, so just generic success message for now
        print("  [+] Scan complete. Check JSON report for deep analysis.")
    elif ssl.get("status") == "skipped":
        print("  [i] Skipped (Fast Mode)")
    else:
        print(f"  [!] Scan Failed/Skipped: {ssl.get('details')}")

    print("\n" + "="*40 + "\n")


# --- Scan Functions ---

def get_tech_stack(target_url):
    """Runs the webtech scan to identify site technologies."""
    print(f"[INFO] Running tech stack scan on {target_url}...")
    try:
        wt = webtech.WebTech()
        # Run the scan. This returns a dict with 'tech_names' and 'headers'
        report = wt.start_from_url(target_url, timeout=5) 
        
        # Check if the report is a dictionary
        if not isinstance(report, dict):
            print(f"[Error] webtech scan returned unexpected data type: {type(report)}", file=sys.stderr)
            return {"status": "error", "details": "Webtech scan did not return a valid report object."}

        # We only really care about the 'tech_names' list
        tech_names = report.get('tech_names', [])
        
        return {
            "status": "success",
            "technologies": tech_names
        }
    except ConnectionException:
        print(f"[Error] Tech stack scan failed: Connection error for {target_url}", file=sys.stderr)
        return {"status": "error", "details": "Connection error."}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_tech_stack: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_pagespeed(target_url, api_key):
    """Runs the Google PageSpeed Insights scan."""
    print(f"[INFO] Running PageSpeed scan on {target_url}...")
    
    # If no API key is provided, skip the scan.
    if not api_key:
        print("       [INFO] No PageSpeed API key provided. Skipping scan.")
        print("       [INFO] Get a key: https://developers.google.com/speed/docs/insights/v5/get-started")
        return {"status": "skipped", "details": "No API key provided."}

    # The Google PageSpeed API endpoint
    api_url = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
    
    # Parameters for the API
    params = {
        'url': target_url,
        'key': api_key,
        'strategy': 'DESKTOP',  # We can run 'MOBILE' as well, but let's start with one
        'category': ['PERFORMANCE', 'ACCESSIBILITY', 'BEST_PRACTICES', 'SEO']
    }
    
    try:
        response = requests.get(api_url, params=params, timeout=60)
        
        if response.status_code == 200:
            # Add a custom status key for our parser
            data = response.json()
            data['status'] = 'success'
            return data
        else:
            # Try to parse the error message from Google
            try:
                error_data = response.json()
                error_msg = error_data.get("error", {}).get("message", response.text)
                print(f"[Error] PageSpeed API failed: {error_msg}", file=sys.stderr)
                return {"status": "error", "details": f"API Error: {error_msg}"}
            except json.JSONDecodeError:
                print(f"[Error] PageSpeed API returned status {response.status_code}", file=sys.stderr)
                return {"status": "error", "details": f"API returned status {response.status_code}"}
                
    except requests.exceptions.RequestException as e:
        print(f"[Error] Could not connect to PageSpeed API: {e}", file=sys.stderr)
        return {"status": "error", "details": f"API request failed: {str(e)}"}

def analyze_security_headers(target_url):
    """Fetches headers using 'requests' and checks for key security headers."""
    print(f"[INFO] Running native security headers scan on {target_url}...")
    
    # List of key headers to check.
    HEADERS_TO_CHECK = [
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Referrer-Policy',
        'Permissions-Policy'
    ]

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'
        }
        # Use a GET request, as some servers don't respond to HEAD
        # Follow redirects to get the headers from the *final* destination
        response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
        
        # We need to check headers case-insensitively.
        # The 'requests' headers object already does this.
        response_headers = response.headers

        missing_headers = []
        found_headers = []

        for header in HEADERS_TO_CHECK:
            if header in response_headers:
                found_headers.append(header)
            else:
                missing_headers.append(header)
                
        return {
            "status": "success",
            "found_headers": found_headers,
            "missing_headers": missing_headers,
            "total_checked": len(HEADERS_TO_CHECK)
        }

    except requests.exceptions.RequestException as e:
        print(f"[Error] Failed to fetch headers for scan: {e}", file=sys.stderr)
        return {"status": "error", "details": f"Failed to fetch {target_url}: {str(e)}"}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in analyze_security_headers: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_testssl(target_url):
    """Runs the testssl.sh scan."""
    print(f"[INFO] Running testssl.sh scan on {target_url}... (this may take several minutes)...")
    hostname = urlparse(target_url).hostname
    
    # Create a temporary file to store the JSON output
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as tmpfile:
            json_output_file = tmpfile.name
        
        command = [TESTSSL_PATH, "--jsonfile", json_output_file, "-U", hostname]
        
        # Give this a long timeout
        run_subprocess(command, timeout=300)
        
        # Now, read the JSON output from the file
        if os.path.exists(json_output_file):
            with open(json_output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            os.remove(json_output_file) # Clean up
            
            # FIX: Wrap the list in a dict so it has a 'status' key
            return {
                "status": "success",
                "data": data
            }
        else:
            return {"status": "error", "details": "testssl.sh failed to produce an output file."}
            
    except json.JSONDecodeError:
        print("[Error] Failed to parse testssl.sh JSON output.", file=sys.stderr)
        return {"status": "error", "details": "Failed to parse testssl.sh JSON."}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_testssl: {e}", file=sys.stderr)
        # Clean up tmpfile if it still exists
        if 'json_output_file' in locals() and os.path.exists(json_output_file):
            os.remove(json_output_file)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_nmap(target_url):
    """Runs the nmap scan."""
    print(f"[INFO] Running nmap scan on {target_url}...")
    hostname = urlparse(target_url).hostname
    # -F is "Fast scan" (top 100 ports), -sV is "Version detection"
    # -oX - sends XML output to stdout
    command = [NMAP_PATH, "-F", "-sV", "-oX", "-", hostname]
    
    try:
        raw_output = run_subprocess(command, timeout=120)
        if raw_output:
            # We no longer parse here, just return the raw XML
            return {"status": "success", "xml_data": raw_output}
        return {"status": "error", "details": "nmap command failed or returned no output."}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_nmap: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_linkchecker(target_url):
    """Runs a simple link check on the target URL's homepage."""
    print(f"[INFO] Running link scan on {target_url}...")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'
        }
        response = requests.get(target_url, headers=headers, timeout=10)
        response.raise_for_status() # Raise an error for bad responses
        
        soup = BeautifulSoup(response.text, 'lxml')
        links = soup.find_all('a', href=True)
        
        all_links = []
        broken_links = []
        
        for link in links:
            href = link['href']
            
            # Resolve relative URLs
            full_url = urljoin(target_url, href)
            
            # Skip mailto, tel, and anchor links
            if full_url.startswith(('mailto:', 'tel:', '#')):
                continue
                
            link_info = {"url": full_url, "status_code": None, "status": "pending"}

            try:
                # Use a HEAD request for speed, but follow redirects
                link_response = requests.head(full_url, headers=headers, timeout=5, allow_redirects=True)
                link_info["status_code"] = link_response.status_code
                
                if link_response.status_code >= 400:
                    link_info["status"] = "broken"
                    broken_links.append(link_info)
                else:
                    link_info["status"] = "valid"
            except requests.exceptions.RequestException:
                link_info["status"] = "unreachable"
                broken_links.append(link_info)
            
            all_links.append(link_info)
            
        return {
            "status": "success",
            "summary": {
                "total_links_found": len(all_links),
                "broken_count": len(broken_links)
            },
            "all_links": all_links,
            "broken_links": broken_links
        }

    except requests.exceptions.RequestException as e:
        print(f"[Error] Failed to fetch target URL for link check: {e}", file=sys.stderr)
        return {"status": "error", "details": f"Failed to fetch {target_url}: {str(e)}"}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_linkchecker: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_dns_records(target_url):
    """Runs the dnspython scan."""
    print(f"[INFO] Running DNS scan on {target_url}...")
    hostname = urlparse(target_url).hostname
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
    results = {}
    
    try:
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(hostname, rtype)
                results[rtype] = [r.to_text() for r in answers]
            except dns.resolver.NoAnswer:
                results[rtype] = []
            except dns.resolver.NXDOMAIN:
                print(f"[Error] DNS scan failed: Domain not found (NXDOMAIN).", file=sys.stderr)
                return {"status": "error", "details": "Domain not found (NXDOMAIN)."}
            except Exception:
                # Catch other potential query errors but continue
                results[rtype] = ["Query failed"]
        return {"status": "success", "data": results}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_dns_records: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Run a full website health check.")
    parser.add_argument("url", type=str, help="The target URL to scan (e.g., https://example.com)")
    parser.add_argument("--output", type=str, default="report.json", help="The filename for the JSON output report.")
    parser.add_argument("--api-key", type=str, default=os.environ.get('PAGESPEED_API_KEY'), 
                        help="Google PageSpeed API key. Can also be set via PAGESPEED_API_KEY environment variable.")
    
    # v0.3: Added flags for summary and fast mode
    parser.add_argument("--summary", action="store_true", help="Print a human-readable summary of results to the terminal.")
    parser.add_argument("--fast", action="store_true", help="Skip slow scans (nmap and testssl.sh) for a quick check.")

    args = parser.parse_args()

    # Add 'https://' if no scheme is provided
    if not args.url.startswith(('http://', 'https://')):
        print(f"[INFO] No scheme provided, defaulting to https://")
        args.url = f"https://{args.url}"
    
    # Strip trailing junk
    args.url = args.url.rstrip(')/"')

    print(f"--- Starting full scan for {args.url} ---")
    if args.fast:
        print("[INFO] Fast mode enabled. Skipping Nmap and TestSSL.")

    # Initialize the master report structure
    master_report = {
        "scan_target": args.url,
        "scan_timestamp": "", 
        "reports": {
            "tech_stack": {},
            "pagespeed": {},
            "security_headers": {},
            "testssl": {},
            "nmap": {},
            "linkchecker": {},
            "dns": {}
        }
    }

    # Run each scan
    master_report["reports"]["tech_stack"] = get_tech_stack(args.url)
    
    # Run PageSpeed and parse it
    raw_pagespeed = get_pagespeed(args.url, args.api_key)
    master_report["reports"]["pagespeed"] = parse_pagespeed(raw_pagespeed)
    
    # Run native security headers scan
    master_report["reports"]["security_headers"] = analyze_security_headers(args.url)
    
    # --- testssl.sh scan ---
    if not args.fast:
        master_report["reports"]["testssl"] = get_testssl(args.url)
    else:
        master_report["reports"]["testssl"] = {"status": "skipped", "details": "Skipped due to --fast flag."}
    
    # Run nmap and parse it
    if not args.fast:
        raw_nmap = get_nmap(args.url)
        master_report["reports"]["nmap"] = parse_nmap_xml(raw_nmap.get("xml_data")) if raw_nmap.get("status") == "success" else raw_nmap
    else:
        master_report["reports"]["nmap"] = {"status": "skipped", "details": "Skipped due to --fast flag."}

    # Run linkchecker and parse it
    raw_linkcheck = get_linkchecker(args.url)
    master_report["reports"]["linkchecker"] = parse_linkchecker(raw_linkcheck)

    # Run DNS and parse it
    raw_dns = get_dns_records(args.url)
    master_report["reports"]["dns"] = parse_dns_records(raw_dns)

    # Set the timestamp
    master_report["scan_timestamp"] = datetime.now().isoformat()

    # Write the final report
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(master_report, f, indent=4)
        print(f"\n--- Scan Complete ---")
        print(f"[SUCCESS] Master report saved to {args.output}")
        
        # Print summary if requested
        if args.summary:
            print_summary(master_report)

    except IOError as e:
        print(f"\n--- Scan Complete ---", file=sys.stderr)
        print(f"[Error] Failed to write report file: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()