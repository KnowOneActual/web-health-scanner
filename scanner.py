import argparse
import json
import os
import subprocess
import sys
import requests
import dns.resolver
import tempfile 
from urllib.parse import urlparse, urljoin # Added urljoin
import xml.etree.ElementTree as ET
from datetime import datetime
from bs4 import BeautifulSoup # Added for new link checker
# REMOVED: linkcheck.checker and linkcheck.linkdb

# --- Configuration ---
# Paths to local tools
# Assumes testssl.sh was cloned into the project directory
TESTSSL_PATH = "./testssl.sh/testssl.sh"
# Assumes nmap is in the system's PATH
NMAP_PATH = "nmap"
# Assumes secheaders is installed via pip and in the system's PATH
SECHEADERS_PATH = "secheaders"
# REMOVED: LINKCHECKER_PATH is no longer needed

# --- Helper Functions ---

def run_subprocess(command, timeout=60):
    """A helper to run shell commands and return their output."""
    try:
        # We use 'capture_output=True' to get stdout/stderr
        # 'text=True' gives us strings instead of bytes
        # 'check=True' will raise an error if the command fails
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', timeout=timeout)
        
        # Handle commands that might output to stderr
        # If stdout is empty but stderr has content, return stderr
        if not result.stdout and result.stderr:
            return result.stderr.strip()
            
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[Error] Command '{' '.join(command)}' timed out after {timeout} seconds.", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        # This catches errors where the command itself fails (non-zero exit code)
        print(f"[Error] Command '{' '.join(e.cmd)}' failed with exit code {e.returncode}.", file=sys.stderr)
        print(f"       Stderr: {e.stderr.strip()}", file=sys.stderr)
        return None
    except FileNotFoundError:
        # This catches errors where the command isn't installed or not in PATH
        print(f"[Error] Command not found: {command[0]}.", file=sys.stderr)
        print(f"       Is it installed and in your system's PATH?", file=sys.stderr)
        print(f"       (e.g., for nmap: 'brew install nmap' or 'apt-get install nmap')", file=sys.stderr)
        # Removed blacklight-query error message
        return None
    except Exception as e:
        print(f"[Error] An unexpected error occurred with subprocess: {e}", file=sys.stderr)
        return None

def parse_nmap_xml(xml_output):
    """Parses nmap's XML output into a simpler dict."""
    try:
        root = ET.fromstring(xml_output)
        host = root.find('host')
        if host is None:
            return {"status": "error", "details": "No host information found in nmap output."}

        host_status = host.find('status').get('state', 'unknown')
        ports = []
        port_elements = host.findall('.//port')

        for port in port_elements:
            port_state = port.find('state')
            if port_state is not None and port_state.get('state') == 'open':
                service = port.find('service')
                port_info = {
                    "portid": port.get('portid'),
                    "protocol": port.get('protocol'),
                    "state": port_state.get('state'),
                    "service": service.get('name', 'unknown') if service is not None else 'unknown',
                    "product": service.get('product', '') if service is not None else '',
                    "version": service.get('version', '') if service is not None else ''
                }
                ports.append(port_info)
        
        return {
            "status": "success",
            "host_status": host_status,
            "open_ports": ports
        }

    except ET.ParseError:
        print("[Error] Failed to parse nmap XML output.", file=sys.stderr)
        return {"status": "error", "details": "Failed to parse nmap XML."}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in parse_nmap_xml: {e}", file=sys.stderr)
        return {"status": "error", "details": f"XML parsing error: {str(e)}"}

# --- Scan Functions ---

def get_web_check(target_url):
    """Fetches data from the web-check.xyz API."""
    print(f"[INFO] Running web-check scan on {target_url}...")
    
    try:
        parsed_url = urlparse(target_url)
        domain = parsed_url.hostname
        if not domain:
            return {"status": "error", "details": "Could not parse domain from URL."}
            
        api_url = f"https{':'}//api.web-check.xyz/api/scan?url={domain}"
        
        # UPDATED: Add a User-Agent header to look like a browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'
        }
        
        # Give a 30-second timeout for the API
        response = requests.get(api_url, headers=headers, timeout=30)
        
        # Check for a successful response
        if response.status_code == 200:
            try:
                # If we get a 200, but it's still the Cloudflare page, it's a "soft" block.
                text_response = response.text
                if "Just a moment..." in text_response or "Enable JavaScript and cookies" in text_response:
                    print(f"[Error] web-check API returned a 200 but is still Cloudflare blocked. Scan skipped.", file=sys.stderr)
                    return {"status": "error", "details": "API scan blocked by Cloudflare."}
                
                return json.loads(text_response)
            except json.JSONDecodeError:
                print(f"[Error] Failed to decode JSON from web-check API.", file=sys.stderr)
                return {"status": "error", "details": "Failed to decode API JSON response."}
        else:
            # Handle 403 Cloudflare errors
            if response.status_code == 403 and "Just a moment..." in response.text:
                print(f"[Error] web-check API returned a 403 (Cloudflare block). Scan skipped.", file=sys.stderr)
                return {"status": "error", "details": "API scan blocked by Cloudflare."}
            
            # Handle other API errors
            print(f"[Error] web-check API returned status code {response.status_code}", file=sys.stderr)
            return {"status": "error", "details": f"API returned status {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        print(f"[Error] Could not connect to web-check API: {e}", file=sys.stderr)
        return {"status": "error", "details": f"API request failed: {str(e)}"}

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
            return response.json()
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

# REMOVED: get_blacklight(target_url) function was here

def get_secheaders(target_url):
    """Runs the secheaders tool."""
    print(f"[INFO] Running security headers scan on {target_url}...")
    
    command = [SECHEADERS_PATH, '--json', target_url]
    
    # Give this a 30-second timeout
    raw_output = run_subprocess(command, timeout=30)
    
    if raw_output:
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            print(f"[Error] Failed to decode JSON from secheaders.", file=sys.stderr)
            return {"status": "error", "details": "Failed to decode secheaders JSON response."}
    
    return {"status": "error", "details": "secheaders command failed or returned no output."}

def get_testssl(target_url):
    """Runs the testssl.sh script."""
    # UPDATED: More informative print
    print(f"[INFO] Running testssl.sh scan on {target_url}... (this may take several minutes)...")
    
    # Check if the script exists first
    if not os.path.exists(TESTSSL_PATH):
        print(f"[Error] testssl.sh not found at {TESTSSL_PATH}", file=sys.stderr)
        print(f"       Please clone it: git clone https://github.com/testssl/testssl.sh.git", file=sys.stderr)
        return {"status": "error", "details": "testssl.sh script not found."}
        
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname
        if not hostname:
            return {"status": "error", "details": "Could not parse domain from URL."}

        # Create a temporary file to hold the JSON output
        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".json") as tmp_file:
            tmp_file_path = tmp_file.name
            
            # Build the command. --quiet suppresses the banner. -oJ writes JSON to our temp file
            command = [TESTSSL_PATH, "--quiet", "-oJ", tmp_file_path, hostname]
            
            # UPDATED: Give this a long timeout (300 seconds / 5 minutes)
            raw_output = run_subprocess(command, timeout=300)
            
            if raw_output is None:
                # This means the subprocess failed (timeout or other error)
                return {"status": "error", "details": "testssl.sh scan failed or timed out."}

            # If subprocess was successful, read the JSON output from the temp file
            with open(tmp_file_path, 'r', encoding='utf-8') as f:
                json_output = json.load(f)
            
            return json_output

    except json.JSONDecodeError:
        print(f"[Error] Failed to decode JSON from testssl.sh output file.", file=sys.stderr)
        return {"status": "error", "details": "Failed to decode testssl.sh JSON."}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_testssl: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_nmap(target_url):
    """Runs a basic nmap scan."""
    print(f"[INFO] Running nmap scan on {target_url}...")
    
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname
        if not hostname:
            return {"status": "error", "details": "Could not parse domain from URL."}

        # -F: Fast scan (top 100 ports)
        # -sV: Service version detection
        # -oX -: Output XML to stdout
        command = [NMAP_PATH, "-F", "-sV", "-oX", "-", hostname]
        
        # Give nmap 2 minutes (120 seconds)
        raw_output = run_subprocess(command, timeout=120)
        
        if raw_output:
            return parse_nmap_xml(raw_output)
        
        return {"status": "error", "details": "nmap command failed or returned no output."}

    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_nmap: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_linkchecker(target_url):
    """
    Finds and checks all links on the target_url page.
    This is a new implementation using requests and BeautifulSoup.
    """
    print(f"[INFO] Running link scan on {target_url}...")
    
    results = {
        "status": "pending",
        "summary": {},
        "all_links": [],
        "broken_links": []
    }
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'
    }

    try:
        # 1. Fetch the page
        response = requests.get(target_url, headers=headers, timeout=10)
        if response.status_code >= 400:
            return {"status": "error", "details": f"Target URL returned status {response.status_code}"}
        
        # 2. Parse the HTML
        soup = BeautifulSoup(response.text, 'lxml')
        
        # 3. Find all <a> tags with an href attribute
        links_found = soup.find_all('a', href=True)
        
        link_urls = set() # Use a set to avoid checking the same link multiple times
        
        for link in links_found:
            href = link['href']
            
            # Ignore anchors, mailto, etc.
            if not href or href.startswith(('#', 'mailto:', 'tel:')):
                continue
                
            # Make the URL absolute (e.g., /about -> https://example.com/about)
            absolute_url = urljoin(target_url, href)
            link_urls.add(absolute_url)

        results["summary"]["total_links_found"] = len(link_urls)
        
        # 4. Check each link
        for url in link_urls:
            link_status = {
                "url": url,
                "status_code": 0,
                "status": "pending"
            }
            try:
                # We use a HEAD request for speed - it just gets headers, not the whole page
                # We also set a short timeout
                head_response = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
                link_status["status_code"] = head_response.status_code
                
                if head_response.status_code >= 400:
                    link_status["status"] = "broken"
                    results["broken_links"].append(link_status)
                else:
                    link_status["status"] = "valid"
                    
            except requests.exceptions.Timeout:
                link_status["status"] = "broken"
                link_status["details"] = "Request timed out"
                results["broken_links"].append(link_status)
            except requests.exceptions.RequestException as e:
                # e.g., ConnectionError, TooManyRedirects
                link_status["status"] = "broken"
                link_status["details"] = str(e)
                results["broken_links"].append(link_status)
            
            results["all_links"].append(link_status)

        results["status"] = "success"
        results["summary"]["broken_count"] = len(results["broken_links"])
        return results

    except requests.exceptions.RequestException as e:
        print(f"[Error] Failed to fetch target URL for link check: {e}", file=sys.stderr)
        return {"status": "error", "details": f"Failed to fetch {target_url}: {str(e)}"}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_linkchecker: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_dns_records(target_url):
    """Runs dnspython queries."""
    print(f"[INFO] Running DNS scan on {target_url}...")
    
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname
        if not hostname:
            return {"status": "error", "details": "Could not parse domain from URL."}

        # List of common record types to check
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
        results = {}
        
        for rtype in record_types:
            try:
                # Query for the record type
                answers = dns.resolver.resolve(hostname, rtype)
                # Store the results as a list of strings
                results[rtype] = [rdata.to_text() for rdata in answers]
            except dns.resolver.NoAnswer:
                # This is normal, e.g., no MX records
                results[rtype] = []
            except dns.resolver.NXDOMAIN:
                # The domain doesn't exist at all
                print(f"[Error] DNS scan failed: Domain not found (NXDOMAIN).", file=sys.stderr)
                return {"status": "error", "details": "Domain not found (NXDOMAIN)."}
            except dns.exception.Timeout:
                print(f"[Error] DNS query timed out for {rtype} record.", file=sys.stderr)
                results[rtype] = ["Query timed out."]
            except Exception as e:
                # Catch other DNS errors
                print(f"Warning] DNS query for {rtype} failed: {e}", file=sys.stderr)
                results[rtype] = [f"Query failed: {str(e)}"]
                
        return {"status": "success", "data": results}

    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_dns_records: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Run a full website health check.")
    parser.add_argument("url", type=str, help="The target URL to scan (e.g., https://example.com)")
    parser.add_argument("--output", type=str, default="report.json", help="The filename for the JSON output report.")
    # Add the API key argument
    parser.add_argument("--api-key", type=str, default=os.environ.get('PAGESPEED_API_KEY'), 
                        help="Google PageSpeed API key. Can also be set via PAGESPEED_API_KEY environment variable.")
    args = parser.parse_args()

    # Add 'https://' if no scheme is provided
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
        print(f"[INFO] No scheme provided. Defaulting to HTTPS: {args.url}")

    print(f"--- Starting full scan for {args.url} ---")

    # Initialize the master report structure
    master_report = {
        "scan_target": args.url,
        "scan_timestamp": "", # We'll fill this in at the end
        "reports": {}
    }

    # Run each scan
    master_report["reports"]["web_check"] = get_web_check(args.url)
    # Pass the API key to the function
    master_report["reports"]["pagespeed"] = get_pagespeed(args.url, args.api_key)
    # REMOVED: Blacklight call
    # master_report["reports"]["blacklight"] = get_blacklight(args.url)
    master_report["reports"]["security_headers"] = get_secheaders(args.url)
    
    # --- Skipping long-running scan ---
    print("[INFO] Skipping testssl.sh scan for faster development.")
    master_report["reports"]["testssl"] = {"status": "skipped", "details": "Scan skipped by default in script."}
    # master_report["reports"]["testssl"] = get_testssl(args.url)
    
    master_report["reports"]["nmap"] = get_nmap(args.url)
    # UPDATED: Cleaned up this line
    master_report["reports"]["linkchecker"] = get_linkchecker(args.url)
    master_report["reports"]["dns"] = get_dns_records(args.url)

    # Set the timestamp
    master_report["scan_timestamp"] = datetime.now().isoformat()

    # Write the final report to a file
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(master_report, f, indent=4)
        print(f"\n--- Scan Complete ---")
        print(f"[SUCCESS] Master report saved to {args.output}")
    except IOError as e:
        print(f"\n[Error] Failed to write report file: {e}", file=sys.stderr)
    except Exception as e:
        print(f"\n[Error] An unexpected error occurred while writing report: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()