# 🌐 Site-Checkup

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/YOUR_USERNAME/YOUR_REPONAME/actions)


The Big Idea: A simple, command-line tool to run a comprehensive health check and audit on any website.


## About The Project

This tool bundles multiple free APIs and open-source tools to give you a "360-degree" view of a website's health. It's designed to be run as a single command, collecting and organizing reports on performance, security, SEO, and network configuration.

The goal is to create a simple, free tool that anyone can use to get a deep-level analysis of their site without needing multiple paid accounts or running many different manual tests.


## Features (Checks Performed)

* **Performance:** Full Google Lighthouse audit via PageSpeed Insights.
* **General Tech Stack:** Identifies server tech and client technologies.
* **Broken Links:** Crawls the site's homepage to find 404s and other broken links.
* **Security Headers:** Analyzes HTTP security headers for missing or misconfigured settings (Native scan).
* **Network & Ports:** Scans for open ports and services (Skipped in `--fast` mode).
* **SSL/TLS Config:** Runs a deep analysis of the SSL/TLS certificate and server configuration (Skipped in `--fast` mode).
* **DNS Records:** Dumps all major DNS records (MX, TXT, SPF, etc.).


## Core Toolset

This project is a "meta-tool" that couldn't exist without these amazing free services and open-source projects.


<table>
  <tr>
   <td><strong>Tool</strong>
   </td>
   <td><strong>Purpose</strong>
   </td>
   <td><strong>Type</strong>
   </td>
  </tr>
  <tr>
   <td><a href="https://developers.google.com/speed/docs/insights/v5/get-started">Google PageSpeed Insights</a>
   </td>
   <td>Performance (Lighthouse)
   </td>
   <td>API
   </td>
  </tr>
  <tr>
   <td>webtech library
   </td>
   <td>General Tech Stack
   </td>
   <td>Python Library
   </td>
  </tr>
  <tr>
   <td>Native Requests/Python
   </td>
   <td>Security Headers & Link Checker
   </td>
   <td>Native Code
   </td>
  </tr>
  <tr>
   <td><a href="https://github.com/testssl/testssl.sh">testssl.sh</a>
   </td>
   <td>SSL/TLS Config
   </td>
   <td>Local Tool (Bash)
   </td>
  </tr>
  <tr>
   <td>nmap
   </td>
   <td>Network & Port Scan
   </td>
   <td>Local Tool (System)
   </td>
  </tr>
  <tr>
   <td>dnspython
   </td>
   <td>DNS Records
   </td>
   <td>Python Library
   </td>
  </tr>
</table>


## 🚀 Getting Started


### Prerequisites

You will need to have Python 3.9+ installed, as well as the following command-line tools:

* **nmap** (Must be in your system PATH)
* **git** (to clone this repo and testssl.sh)


### Installation

1.  **Clone this repo:**
```bash
git clone https://github.com/KnowOneActual/web-health-scanner.git
cd web-health-scanner 
````

2.  **Clone testssl.sh:** This must be cloned into the main directory for the scanner to find it. (--depth flag 1 to make the download faster and smaller).

```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
```

3.  **Install Python requirements:**

```bash
pip install -r requirements.txt
```

4.  Get a PageSpeed API Key (Optional but Recommended):
    The PageSpeed (Lighthouse) scan will be skipped unless you provide an API key.



  * Go to the [Google Cloud credentials page](https://console.cloud.google.com/apis/credentials).
  * Create an API key and ensure the **PageSpeed Insights API** is enabled for your project.

## Usage

Run the scanner. All scans are run by default unless you use the `--fast` flag.

### Method 1: Environment Variable (Recommended & Secure)

You can set the key as an environment variable to avoid it being saved in your shell history.

```bash
export PAGESPEED_API_KEY="YOUR_API_KEY_HERE"
python scanner.py https://example.com --summary
```

### Method 2: Command-Line Flag (Less Secure) **Please exercise caution with your API; in this method, your Key is recorded in the command history.**


```bash
python scanner.py https://example.com --output report.json --api-key "YOUR_API_KEY_HERE"
```

### Options

| Flag | Description |
| :--- | :--- |
| `--summary` | Prints a clean, human-readable summary to the terminal after saving the full JSON report. |
| `--fast` | Skips the two slow scans (`nmap` and `testssl.sh`) for a rapid health check. |

## License

Distributed under the MIT License. See `LICENSE` for more information.