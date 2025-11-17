# 🌐 Site-Checkup

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/YOUR_USERNAME/YOUR_REPONAME/actions)

** Under Development **

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

| Tool | Purpose | Type |

| Google PageSpeed Insights | Performance (Lighthouse) | API |

| web-check.xyz | General Tech Stack & Trackers | API |

| secheaders | Security Headers | Local Tool |

| testssl.sh | SSL/TLS Config | Local Tool |

| nmap | Network & Port Scan | Local Tool |

| LinkChecker | Broken Links | Python Library |

| dnspython | DNS Records | Python Library |


## 🚀 Getting Started


### Prerequisites

You will need to have Python 3.9+ installed, as well as the following command-line tools:



* nmap
* git (to clone this repo and testssl.sh)


### Installation



1. **Clone this repo:**
```bash
git clone https://github.com/KnowOneActual/web-health-scanner
cd YOUR_REPONAME
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
    * You must also [enable the PageSpeed Insights API](https://www.google.com/search?q=https://console.cloud.google.com/apis/library/pagespeedonline.googleapis.com) for your project.


## Usage

Run the scanner with your API key:

python scanner.py [https://example.com](https://example.com) --output report.json --api-key "YOUR_API_KEY_HERE" \


Alternatively, you can set the key as an environment variable to avoid typing it:

export PAGESPEED_API_KEY="YOUR_API_KEY_HERE" \
python scanner.py [https://example.com](https://example.com) \



## License

Distributed under the MIT License. See LICENSE.txt for more information.
