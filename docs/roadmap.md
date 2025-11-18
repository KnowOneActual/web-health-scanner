# Project Mission & Roadmap


## 🎯 Mission Statement

To provide developers, hobbyists, and site owners with a single, free, and open-source command-line tool that aggregates comprehensive data on a website's performance, security, and technical health, eliminating the need to use multiple, separate, or paid services.


## 🗺️ Roadmap

This roadmap outlines the planned stages for building the site-checkup tool.


### v0.1: Core Data Collection (Complete)

**Goal:** Get the main script to successfully call every tool and API and capture its raw output.

* [X] **Setup:** Create scanner.py with argparse to accept a URL and an output file.
* [X] **Setup:** Create requirements.txt with initial libraries.
* [X] **API Call:** Implement Google PageSpeed Insights API call.
* [X] **Subprocess:** Implement `secheaders` call. (Removed in v0.2)
* [X] **Subprocess:** Implement `nmap` call and capture XML.
* [X] **Library:** Implement `dnspython` to get all major DNS records.
* [X] **Library:** Implement custom link checker using `requests` and `BeautifulSoup`.
* [X] **Subprocess:** Implement `testssl.sh` call.
* [X] **API Call:** Implement `web-check.xyz` API call. (Blocked by Cloudflare, abandoned in v0.2).


### v0.2: Data Consolidation & Parsing (Complete)

**Goal:** Take all the raw data from v0.1 and parse it into a single, clean JSON report.

**Completed Parsers:**

* [X] Parse PageSpeed JSON (`parse_pagespeed`).
* [X] Parse nmap XML output (`parse_nmap_xml`).
* [X] Parse link checker output (`parse_linkchecker`).
* [X] Parse DNS records (`parse_dns_records`).

**Key Changes & Fixes:**

* [X] **Replaced Buggy Tools:** Removed the external `secheaders` dependency.
* [X] **New Native Scan:** Wrote `analyze_security_headers` function to check headers directly with `requests`, which works perfectly.
* [X] **Replaced Blocked API:** Replaced the `web-check.xyz` API with the `webtech` library.
* [X] **Robust Error Handling:** Added error checking to the `webtech` scan to prevent crashes when it fails, allowing other scans to complete.
* [X] **Bug Fixes:** Resolved all environment variable, URL, and typo issues.


### v0.3: Human-Readable Summary (Complete)

**Goal:** Make the tool useful for a quick glance, not just for data nerds.

* [X] **Add `--summary` flag:** Add an argument to print a summary to the terminal.
* [X] **Create Formatter:** Write a `print_summary` function to output a clean report.
* [ ] **(Optional) Add Color:** Integrate a library like `rich` or `colorama`. (Skipped for now).
* [X] **Add `--fast` flag:** Implemented a flag to skip slow scans (`nmap`, `testssl.sh`) for quick checks.


### v1.0: Polish & Release (Complete)

**Goal:** Make the tool robust and ready for public use.

* [X] **Dependency Checks:** Added code to gracefully check if `nmap` and `testssl.sh` are available on the user's system.
* [X] **Error Handling:** Added robust `try...except` blocks for all API calls and subprocesses.
* [X] **Documentation:** Finalized the `README.md` and added detailed examples to the `--help` output.
* [X] **License:** License file is present and correct.
* [X] **(Future) GitHub Actions:** Create a simple CI workflow to run tests (e.g., run `black` code formatter).