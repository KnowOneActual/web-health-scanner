# 🌐 Site-Checkup

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/YOUR_USERNAME/YOUR_REPONAME/actions)


# **Under Development**

The Big Idea: A simple, command-line tool to run a comprehensive health check and audit on any website.


## About The Project

This tool bundles multiple free APIs and open-source tools to give you a "360-degree" view of a website's health. It's designed to be run as a single command, collecting and organizing reports on performance, security, SEO, and network configuration.

The goal is to create a simple, free tool that anyone can use to get a deep-level analysis of their site without needing multiple paid accounts or running many different manual tests.


## Features (Checks Performed)



* **Performance:** Full Google Lighthouse audit via PageSpeed Insights.
* **Privacy & Trackers:** Scans for ad trackers, cookies, and fingerprinting tech.
* **General Tech Stack:** Identifies server tech, cookies, redirects, and more.
* **Broken Links:** Crawls the site to find 404s and other broken links.
* **Security Headers:** Analyzes HTTP security headers for missing or misconfigured settings.
* **Network & Ports:** Scans for open ports and services.
* **SSL/TLS Config:** Runs a deep analysis of the SSL/TLS certificate and server configuration.
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
   <td><a href="https://web-check.xyz/web-check-api">web-check.xyz</a>
   </td>
   <td>General Tech Stack & Trackers
   </td>
   <td>API
   </td>
  </tr>
  <tr>
   <td><a href="https://github.com/juerkkil/secheaders">secheaders</a>
   </td>
   <td>Security Headers
   </td>
   <td>Local Tool
   </td>
  </tr>
  <tr>
   <td><a href="https://github.com/testssl/testssl.sh">testssl.sh</a>
   </td>
   <td>SSL/TLS Config
   </td>
   <td>Local Tool
   </td>
  </tr>
  <tr>
   <td>nmap
   </td>
   <td>Network & Port Scan
   </td>
   <td>Local Tool
   </td>
  </tr>
  <tr>
   <td>LinkChecker
   </td>
   <td>Broken Links
   </td>
   <td>Python Library
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



* nmap
* git (to clone this repo and testssl.sh)


### Installation



1. **Clone this repo:** 
```bash
git clone https://github.com/KnowOneActual/web-health-scanner.git)
cd web-health-scanner 
```

2. **Clone testssl.sh:** 
```bash
git clone https://github.com/testssl/testssl.sh.git
```
3. **Install Python requirements:**
```bash
pip install -r requirements.txt
```

4. Get a PageSpeed API Key (Optional but Recommended):
The PageSpeed (Lighthouse) scan will be skipped unless you provide an API key.
    * Go to the [Google Cloud credentials page](https://console.cloud.google.com/apis/credentials).
    * Create a new project (or select an existing one).
    * Click "Create Credentials" -> "API key".
    * Copy the generated key.
    * You must also [enable the PageSpeed Insights API](https://www.google.com/search?q=httpsD://console.cloud.google.com/apis/library/pagespeedonline.googleapis.com) for your project.


## Usage

Run the scanner.


### Method 1: Environment Variable (Recommended & Secure)

You can set the key as an environment variable to avoid it being saved in your shell history.
```bash
export PAGESPEED_API_KEY="YOUR_API_KEY_HERE"
python scanner.py https://example.com
```


### Method 2: Command-Line Flag (Less Secure)

You can also pass the key as a flag, but be aware that it will be saved in your shell's history. (Be please exercise caution with your API keys!)

```bash
python scanner.py [https://example.com](https://example.com) --output report.json --api-key "YOUR_API_KEY_HERE"
```



## License

Distributed under the MIT License. See LICENSE.txt for more information.