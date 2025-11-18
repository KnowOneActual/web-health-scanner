# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- v1.0 Polish (Dependency checks, detailed README).

## [0.3.0] - 2025-11-18

### Added
- `--summary` flag to print a human-readable report of key metrics to the terminal.
- `--fast` flag to optionally skip slow scans (`nmap` and `testssl.sh`).
- `print_summary` function to format JSON data for the console.

### Changed
- Enabled `testssl.sh` scan by default (unless `--fast` is used).
- Enabled `nmap` scan by default (unless `--fast` is used).

### Fixed
- Fixed a crash where `testssl` output was a list instead of a dict, which broke the report parser.

## [0.2.0] - 2025-11-17

### Added
- `parse_pagespeed` function to extract key Lighthouse scores from raw JSON.
- `parse_nmap_xml` function to extract open ports from raw Nmap XML.
- `parse_linkchecker` function to summarize total links and broken link details.
- `parse_dns_records` function to clean up DNS results and remove empty records.
- `analyze_security_headers` function to check headers natively using `requests`.
- `get_tech_stack` function using the `webtech` library to identify site technologies.

### Changed
- The `main` function now calls parser functions for each scan to create a clean report.
- Replaced the external `secheaders` tool with the native `analyze_security_headers` function.
- Replaced the non-functional `get_web_check` (API) with the new `get_tech_stack` (library).
- Updated `master_report` structure to use `tech_stack` key instead of `web_check`.
- Updated `requirements.txt` to add `webtech` and remove `secheaders`.

### Fixed
- Fixed multiple typos in `main()` function calls and output messages.
- Corrected the PageSpeed API URL to include `https://`.
- Ensured the script correctly adds `https://` to URLs that are missing a scheme.
- Added robust error handling to `get_tech_stack` to catch non-dict (e.g., string) return values and prevent crashes.

### Removed
- Removed the buggy and unreliable external `secheaders` dependency.
- Removed `get_secheaders` and `parse_secheaders` functions.
- Removed the `get_web_check` function.

## [0.1.0] - 2025-11-17

### Added
- Initial project setup.
- `argparse` to accept a target `url` and `--output` file.
- `run_subprocess` helper function to run external command-line tools.
- Core data collection functions:
  - `get_pagespeed` (PageSpeed Insights API)
  - `get_nmap` (nmap subprocess)
  - `get_linkchecker` (requests/BeautifulSoup)
  - `get_dns_records` (dnspython library)
  - `get_testssl` (testssl.sh subprocess)
- `main` function to orchestrate all scans and save the raw data to a `report.json` file.