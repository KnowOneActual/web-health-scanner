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
* [X] **Subprocess:** Implement secheaders call and capture JSON.
* [X] **Subprocess:** Implement nmap call and capture XML.
* [X] **Library:** Implement dnspython to get all major DNS records.
* [X] **Library:** Implement custom link checker.
* [ ] **Subprocess:** Implement testssl.sh call. (Implemented, but skipped in main() for speed).
* [ ] **API Call:** Implement web-check.xyz API call. (Blocked by Cloudflare, needs alternative).


### v0.2: Data Consolidation & Parsing (In Progress)

**Goal:** Take all the raw data from v0.1 and parse it into a single, clean JSON report.

**Completed Parsers:**



* [X] Parse PageSpeed JSON (parse_pagespeed).
* [X] Parse nmap XML output (parse_nmap_xml).

**In Progress / To-Do:**



* [ ] **Fix Buggy Parsers:**
    * [ ] parse_secheaders: This parser is buggy and failing. It needs to be made more robust to handle different data types (lists, dicts, strings) from the get_secheaders function.
* [ ] **Write New Parsers:**
    * [ ] parse_linkchecker: Create a parser to summarize the link check report (e.g., return summary and broken_links).
    * [ ] parse_dns_records: Create a parser to clean up the dnspython output (e.g., remove empty [] arrays).
    * [ ] parse_testssl: Write a parser for the testssl.sh JSON output.


### v0.3: Human-Readable Summary

**Goal:** Make the tool useful for a quick glance, not just for data nerds.



* [ ] **Add --summary flag:** Add an argument to print a summary to the terminal.
* [To-Do] **Create Formatter:** Write a function to print a clean summary (e.g., "Performance Score: 85/100", "Missing Headers: 3", "Broken Links: 5").
* [To-Do] **(Optional) Add Color:** Integrate a library like rich or colorama to color-code the summary (red for bad, green for good).


### v1.0: Polish & Release

**Goal:** Make the tool robust and ready for public use.



* [ ] **Dependency Checks:** Add code to gracefully check if nmap, testssl.sh, etc., are available on the user's system and provide helpful error messages if not.
* [ ] **Error Handling:** Add robust try...except blocks for all API calls and subprocesses.
* [ ] **Documentation:** Finalize the README.md with complete installation and usage instructions.
* [ ] **License:** Add an MIT LICENSE.txt file.
* [ ] **(Future) GitHub Actions:** Create a simple CI workflow to run tests (e.g., run black code formatter).