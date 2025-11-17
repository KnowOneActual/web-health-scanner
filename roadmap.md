# Project Mission & Roadmap

## 🎯 Mission Statement

To provide developers, hobbyists, and site owners with a single, free, and open-source command-line tool that aggregates comprehensive data on a website's performance, security, and technical health, eliminating the need to use multiple, separate, or paid services.

## 🗺️ Roadmap

This roadmap outlines the planned stages for building the site-checkup tool.

### v0.1: Core Data Collection

**Goal:** Get the main script to successfully call every tool and API and capture its raw output.

- [ ] **Setup:** Create scanner.py with argparse to accept a URL and an output file.
- [ ] **Setup:** Create requirements.txt with initial libraries (requests, dnspython, LinkChecker, secheaders).
- [ ] **API Call:** Implement web-check.xyz API call.
- [ ] **API Call:** Implement Google PageSpeed Insights API call.
- [ ] **Subprocess:** Implement secheaders call and capture JSON.
- [ ] **Subprocess:** Implement testssl.sh call and capture JSON.
- [ ] **Subprocess:** Implement nmap call and capture XML.
- [ ] **Subprocess:** Implement blacklight-query call and capture JSON.
- [ ] **Library:** Implement dnspython to get all major DNS records.
- [ ] **Library:** Implement LinkChecker basics to crawl a site.

### v0.2: Data Consolidation & Parsing

**Goal:** Take all the raw data from v0.1 and parse it into a single, clean JSON report.

- [ ] **Define Structure:** Design the master report.json structure (e.g., keys for performance, security, dns, etc.).
- [ ] **Write Parsers:** Create helper functions to parse the raw output from each tool.
  - [ ] Parse PageSpeed JSON.
  - [ ] Parse web-check JSON.
  - [ ] Parse secheaders JSON.
  - [ ] Parse testssl.sh JSON.
  - [ ] Parse nmap XML output.
  - [ ] Parse blacklight-query JSON.
  - [ ] Format dnspython results.
  - [ ] Format LinkChecker results.
- [ ] **File Output:** Save the consolidated data into the user-specified output file.

### v0.3: Human-Readable Summary

**Goal:** Make the tool useful for a quick glance, not just for data nerds.

- [ ] **Add --summary flag:** Add an argument to print a summary to the terminal.
- [ ] **Create Formatter:** Write a function to print a clean summary (e.g., "Performance Score: 85/100", "Missing Headers: 3", "Broken Links: 5").
- [ ] **(Optional) Add Color:** Integrate a library like rich or colorama to color-code the summary (red for bad, green for good).

### v1.0: Polish & Release

**Goal:** Make the tool robust and ready for public use.

- [ ] **Dependency Checks:** Add code to gracefully check if nmap, testssl.sh, etc., are available on the user's system and provide helpful error messages if not.
- [ ] **Error Handling:** Add robust try...except blocks for all API calls and subprocesses.
- [ ] **Documentation:** Finalize the README.md with complete installation and usage instructions.
- [ ] **License:** Add an MIT LICENSE.txt file.
- [ ] **(Future) GitHub Actions:** Create a simple CI workflow to run tests (e.g., run black code formatter).
