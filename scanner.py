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

# --- Configuration ---
# Paths to local tools
# Assumes testssl.sh was cloned into the project directory
TESTSSL_PATH = "./testssl.sh/testssl.sh"
# Assumes nmap is in the system's PATH
NMAP_PATH = "nmap"
# Assumes secheaders is installed via pip and in the system's PATH
SECHEADERS_PATH = "secheaders"


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
        root = ET.fromstring(xml_output)
        host = root.find('host')
        if host is None:
            return {"status": "error", "details": "No host information found in nmap output."}

        host_status = host.find('status').get('state')
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

def parse_secheaders(raw_data):
    """Parses the raw secheaders JSON to extract missing headers."""
    try:
        # Pass through errors
        if 'status' in raw_data and raw_data['status'] != 'success':
            return raw_data
        
        # The actual list of headers is in the 'data' key
        header_list = raw_data.get('data', [])
        if not header_list:
            return {"status": "error", "details": "No header data found in secheaders output."}

        missing_headers = []
        # Fix: Iterate over header_list, not raw_data
        for header_info in header_list:
            # A header is considered "missing" if it's not defined or if it's defined but has a warning
            if not header_info.get("defined") or header_info.get("warn"):
                missing_headers.append(header_info.get("name", "Unknown"))
        
        return {
            "status": "success",
            "missing_or_warn": missing_headers,
            "raw_count": len(header_list)
        }

    except (KeyError, TypeError, AttributeError) as e:
        print(f"[Error] Failed to parse secheaders JSON: {e}", file=sys.stderr)
        return {"status": "error", "details": f"Failed to parse secheaders JSON: {str(e)}"}

# --- Scan Functions ---

def get_web_check(target_url):
    """Runs the web-check.xyz scan."""
    print(f"[INFO] Running web-check scan on {target_url}...")
    hostname = urlparse(target_url).hostname
    api_url = f"https://web-check.xyz/api/scan?url={hostname}"
    
    # Add a User-Agent to mimic a browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            print("[Error] web-check API returned a 403 (Cloudflare block). Scan skipped.", file=sys.stderr)
            return {"status": "error", "details": "API scan blocked by Cloudflare."}
        else:
            print(f"[Error] web-check API returned status code {response.status_code}", file=sys.stderr)
            return {"status": "error", "details": f"API returned status code {response.status_code}"}
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

def get_secheaders(target_url):
    """Runs the secheaders scan."""
    print(f"[INFO] Running security headers scan on {target_url}...")
    command = [SECHEADERS_PATH, "--json", target_url]
    
    try:
        raw_output = run_subprocess(command, timeout=30)
        if raw_output:
            # Add a 'status' key for our parser
            data = json.loads(raw_output)
            return {"status": "success", "data": data}
        return {"status": "error", "details": "secheaders command failed or returned no output."}
    except json.JSONDecodeError:
        print("[Error] Failed to parse secheaders JSON output.", file=sys.stderr)
        return {"status": "error", "details": "Failed to parse secheaders JSON."}
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_secheaders: {e}", file=sys.stderr)
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
            return data
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
            return parse_nmap_xml(raw_output) # Parse the XML
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
    # Add the API key argument
    parser.add_argument("--api-key", type=str, default=os.environ.get('PAGESPEED_API_KEY'), 
                        help="Google PageSpeed API key. Can also be set via PAGESPEED_API_KEY environment variable.")
    args = parser.parse_args()

    # Add 'https://' if no scheme is provided
    if not args.url.startswith(('http://', 'https://')):
        print(f"[INFO] No scheme provided, defaulting to https://")
        args.url = f"https://{args.url}"
    
    # Strip trailing junk
    args.url = args.url.rstrip(')/"')

    print(f"--- Starting full scan for {args.url} ---")

    # Initialize the master report structure
    master_report = {
        "scan_target": args.url,
        "scan_timestamp": "", # Will be set at the end
        "reports": {
            "web_check": {},
            "pagespeed": {},
            "security_headers": {},
            "testssl": {},
            "nmap": {},
            "linkchecker": {},
            "dns": {}
        }
    }

    # Run each scan
    master_report["reports"]["web_check"] = get_web_check(args.url)
    
    # Run PageSpeed and parse it
    raw_pagespeed = get_pagespeed(args.url, args.api_key)
    master_report["reports"]["pagespeed"] = parse_pagespeed(raw_pagespeed)
    
    # Run secheaders and parse it
    raw_secheaders = get_secheaders(args.url)
    master_report["reports"]["security_headers"] = parse_secheaders(raw_secheaders)
    
    # --- testssl.sh scan ---
    # This scan is very slow, so we skip it by default.
    # To enable, uncomment the following line:
    print("[INFO] Skipping testssl.sh scan for faster development.")
    master_report["reports"]["testssl"] = {"status": "skipped", "details": "Scan skipped by default in script."}
    # master_report["reports"]["testssl"] = get_testssl(args.url)
    
    master_report["reports"]["nmap"] = get_nmap(args.url)
    master_report["reports"]["linkchecker"] = get_linkchecker(args.url)
    master_report["reports"]["dns"] = get_dns_records(args.url)

    # Set the timestamp
    master_report["scan_timestamp"] = datetime.now().isoformat()

    # Write the final report
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(master_report, f, indent=4)
        print(f"\n--- Scan Complete ---")
        print(f"[SUCCESS] Master report saved to {args.output}")
    except IOError as e:
        print(f"\n--- Scan Complete ---", file=sys.stderr)
        print(f"[Error] Failed to write report file: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()