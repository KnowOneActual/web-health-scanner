import argparse
import json
import os
import subprocess
import sys
import requests
import dns.resolver
import tempfile 
from urllib.parse import urlparse 

# --- Configuration ---
# We can move these to a config file later
TESTSSL_PATH = "./testssl.sh/testssl.sh"
BLACKLIGHT_PATH = "blacklight-query" # Assumes it's in the system PATH
NMAP_PATH = "nmap" # Assumes it's in the system PATH
LINKCHECKER_PATH = "linkchecker" # Assumes it's in the system PATH
SECHEADERS_PATH = "secheaders" # Assumes it's in the system PATH

# --- Helper Functions ---

def run_subprocess(command, timeout=60):
    """A helper to run shell commands and return their output."""
    try:
        # We use 'capture_output=True' to get stdout/stderr
        # 'text=True' gives us strings instead of bytes
        # 'check=True' will raise an error if the command fails
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', timeout=timeout)
        
        # Handle commands that might output to stderr
        if result.stderr and not result.stdout:
            print(f"[Warning] Command '{command[0]}' output to stderr: {result.stderr.strip()}", file=sys.stderr)
            return result.stderr.strip()
            
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[Error] Command '{' '.join(command)}' timed out after {timeout} seconds.", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        print(f"[Error] Command '{' '.join(e.cmd)}' failed with exit code {e.returncode}.", file=sys.stderr)
        print(f"Stdout: {e.stdout}", file=sys.stderr)
        print(f"Stderr: {e.stderr}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"[Error] Command not found: {command[0]}", file=sys.stderr)
        print("Please ensure it is installed and in your system's PATH.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Error] An unexpected error occurred with subprocess: {e}", file=sys.stderr)
        return None

# --- Scan Functions ---

def get_web_check(target_url):
    """Fetches data from the web-check.xyz API."""
    print(f"[INFO] Running web-check scan on {target_url}...")
    
    try:
        # Extract the domain (hostname) from the full URL
        parsed_url = urlparse(target_url)
        domain = parsed_url.hostname
        if not domain:
            return {"status": "error", "details": "Could not parse domain from URL."}

        api_url = f"https://web-check.xyz/api/scan?url={domain}"
        
        # Set a reasonable timeout
        response = requests.get(api_url, timeout=30)
        
        # Check for a successful response
        if response.status_code == 200:
            try:
                # Return the parsed JSON data
                return response.json()
            except json.JSONDecodeError:
                print(f"[Error] Failed to decode JSON from web-check API.", file=sys.stderr)
                return {"status": "error", "details": "Failed to decode API JSON response."}
        else:
            # UPDATED: Handle 403 Cloudflare errors cleanly
            if response.status_code == 403 and "Just a moment..." in response.text:
                print(f"[Error] web-check API returned a 403 (Cloudflare block). Scan skipped.", file=sys.stderr)
                return {"status": "error", "details": "API scan blocked by Cloudflare."}
            
            # Handle other API errors
            print(f"[Error] web-check API returned status code {response.status_code}", file=sys.stderr)
            return {"status": "error", "details": f"API returned status {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        # Handle network or request errors
        print(f"[Error] Network error during web-check scan: {e}", file=sys.stderr)
        return {"status": "error", "details": str(e)}
    except Exception as e:
        # Handle any other unexpected errors
        print(f"[Error] An unexpected error occurred in get_web_check: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}

def get_pagespeed(target_url):
    """Fetches data from the Google PageSpeed Insights API."""
    print(f"[INFO] Running PageSpeed scan on {target_url}...")
    # This requires an API key, which we'll handle later.
    return {"status": "pending", "details": "PageSpeed scan not yet implemented."}

def get_blacklight(target_url):
    """Runs the Blacklight query tool."""
    print(f"[INFO] Running Blacklight scan on {target_url}...")
    return {"status": "pending", "details": "Blacklight scan not yet implemented."}

def get_secheaders(target_url):
    """Runs the secheaders tool."""
    print(f"[INFO] Running security headers scan on {target_url}...")
    
    command = [SECHEADERS_PATH, '--json', target_url]
    
    # Give this a 30-second timeout
    raw_output = run_subprocess(command, timeout=30)
    
    if raw_output:
        try:
            # The --json flag returns a JSON object
            return json.loads(raw_output)
        except json.JSONDecodeError:
            print(f"[Error] Failed to decode JSON from secheaders.", file=sys.stderr)
            return {"status": "error", "details": "Failed to decode secheaders JSON output."}
    else:
        # run_subprocess already printed the error
        return {"status": "error", "details": "secheaders command failed or returned no output."}

def get_testssl(target_url):
    """Runs the testssl.sh script."""
    # UPDATED: More informative print
    print(f"[INFO] Running testssl.sh scan on {target_url}... (this may take several minutes)...")
    
    # Check if the script exists first
    if not os.path.isfile(TESTSSL_PATH):
        print(f"[Error] testssl.sh not found at: {TESTSSL_PATH}", file=sys.stderr)
        print("Please clone it from GitHub into the correct directory (e.g., 'git clone https://github.com/testssl/testssl.sh.git').", file=sys.stderr)
        return {"status": "error", "details": "testssl.sh script not found."}

    tmp_file_path = None
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname
        if not hostname:
            return {"status": "error", "details": "Could not parse domain from URL."}

        # Create a temporary file to store the JSON output
        # We set delete=False so we can read it after the subprocess runs.
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as tmp_file:
            tmp_file_path = tmp_file.name
        
        # Build the command. --quiet suppresses the banner. -oJ writes JSON to our temp file
        command = [TESTSSL_PATH, "--quiet", "-oJ", tmp_file_path, hostname]
        
        # UPDATED: Give this a long timeout (300 seconds / 5 minutes)
        raw_output = run_subprocess(command, timeout=300)
        
        if raw_output is None:
             # run_subprocess failed and already printed an error
             return {"status": "error", "details": "testssl.sh command failed."}

        # Now, read the JSON data from the temporary file
        try:
            with open(tmp_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
            
        except json.JSONDecodeError:
            print(f"[Error] Failed to decode JSON from testssl.sh output file.", file=sys.stderr)
            return {"status": "error", "details": "Failed to decode testssl.sh JSON output."}
        except FileNotFoundError:
            print(f"[Error] testssl.sh did not create an output file at {tmp_file_path}", file=sys.stderr)
            return {"status": "error", "details": "testssl.sh did not create an output file."}
            
    except Exception as e:
        print(f"[Error] An unexpected error occurred in get_testssl: {e}", file=sys.stderr)
        return {"status": "error", "details": f"An unexpected error occurred: {str(e)}"}
    finally:
        # Ensure we always clean up the temporary file
        if tmp_file_path and os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)

def get_nmap(target_url):
    """Runs nmap."""
    print(f"[INFO] Running nmap scan on {target_url}...")
    # We must strip https:// from the URL for nmap
    # We will need to add logic for this.
    return {"status": "pending", "details": "nmap scan not yet implemented."}

def get_linkchecker(target_url):
    """Runs linkchecker."""
    print(f"[INFO] Running linkchecker scan on {target_url}...")
    return {"status": "pending", "details": "linkchecker scan not yet implemented."}

def get_dns_records(target_url):
    """Runs dnspython queries."""
    print(f"[INFO] Running DNS scan on {target_url}...")
    # We must strip https:// from the URL for dnspython
    # We will need to add logic for this.
    return {"status": "pending", "details": "dnspython scan not yet implemented."}

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Run a comprehensive health check on a website.")
    parser.add_argument("url", help="The full URL to scan (e.g., https://example.com)")
    parser.add_argument("-o", "--output", default="report.json", help="The name of the output JSON file (default: report.json)")
    args = parser.parse_args()

    # Ensure URL starts with http:// or https://
    if not (args.url.startswith("http://") or args.url.startswith("https://")):
        print(f"[Error] Invalid URL: '{args.url}'. Please include http:// or https://")
        sys.exit(1)

    print(f"--- Starting full scan for {args.url} ---")

    # This will be our master report
    master_report = {
        "scan_target": args.url,
        "scan_timestamp": "", # We'll add this
        "reports": {}
    }

    # Run each scan and add its output to the master report
    master_report["reports"]["web_check"] = get_web_check(args.url)
    master_report["reports"]["pagespeed"] = get_pagespeed(args.url)
    master_report["reports"]["blacklight"] = get_blacklight(args.url)
    master_report["reports"]["security_headers"] = get_secheaders(args.url)
    master_report["reports"]["testssl"] = get_testssl(args.url)
    master_report["reports"]["nmap"] = get_nmap(args.url)
    master_report["reports"]["linkchecker"] = get_linkchecker(args.url)
    master_report["reports"]["dns"] = get_dns_records(args.url)

    # Save the master report to the specified file
    try:
        with open(args.output, "w", encoding='utf-8') as f:
            json.dump(master_report, f, indent=4)
        print(f"\n--- Scan Complete ---")
        print(f"[SUCCESS] Master report saved to {args.output}")
    except Exception as e:
        print(f"\n[Error] Failed to write report to {args.output}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()