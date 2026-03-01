<p align="center">
<img src="assets/img/web-health-scanner_logo_color.webp" alt="alt text" width="150">
</p>

# 🌐 Website-Checkup

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/YOUR_USERNAME/YOUR_REPONAME/actions)


The Big Idea: A simple, command-line tool to run a comprehensive health check and audit on any website.


## About The Project

This tool bundles multiple free APIs and open-source tools to give you a "**360-degree**" view of a website's health. It's designed to be run as a single command, collecting and organizing reports on performance, security, SEO, and network configuration.

The goal is to create a simple, free tool that anyone can use to get a deep-level analysis of their site without needing multiple paid accounts or running many different manual tests.

***

## 💡 Project Philosophy: The Evolution of a Scanner

The development of Website-Checkup is a perfect example of why **technical flexibility** is vital in building good software. The project started small, focusing on simple **web scraping** to gather data. However, that original design proved insufficient for creating a reliable and secure tool.

It became clear that relying on fragile custom scraping and brittle subprocess calls presented three major, unavoidable challenges:

* **Instability:** Scraping logic breaks easily whenever a target website's HTML changes.
* **Incompleteness:** I couldn't gather deep, validated metrics (like Lighthouse scores) without moving to official **APIs**.
* **Security Risk:** Heavy reliance on external command-line tools and unchecked user input created high-severity **vulnerabilities**.

To make the project better and more reliable, a **strategic pivot** was necessary. I realized that a truly robust tool needed to prioritize stability and security over the initial design. This journey confirmed that I needed to be able to pivot and be flexible from the original design to make something ultimately better.

### Key Learnings & Improvements

This pivot resulted in significant architectural upgrades, leading to the stable **v1.1.0** release:

* **From Scraping to Libraries/APIs:** I replaced fragile custom parsing with calls to stable APIs (Google PageSpeed) and robust Python libraries (`webtech`, `dnspython`, `requests`, `BeautifulSoup`) to gather data.
* **Best Security Practices:** The code underwent a comprehensive audit to implement defenses against critical vulnerabilities:
    * **Server-Side Request Forgery (SSRF) Mitigation:** I implemented host resolution validation to block the scanner from being used to attack internal/private networks.
    * **Path Traversal (PT) Mitigation:** I secured user-supplied file names to prevent arbitrary file writing.
    * **Insecure XML Parsing:** I adopted the secure `lxml` library to prevent XML External Entity (XXE) and Denial of Service attacks.
* **Prioritizing Stability:** After the security fixes, I focused on resolving critical runtime bugs, such as XML parsing errors and SSL timeouts on CDN targets, confirming that all components now run reliably.
* **Modernized UI & Speed:** Version 1.2.0 introduced parallel scanning for massive performance gains and a beautiful, modern CLI interface using the `rich` library.
* **Architecture & Efficiency (v2.0):** The project was completely refactored into a modular plugin-based architecture for easy extensibility. We also switched to **Ruff** for linting and formatting, providing near-instantaneous code quality checks and significantly improved development efficiency.

***

## Features (Checks Performed)

* **Performance:** Full Google Lighthouse audit via PageSpeed Insights.
* **General Tech Stack:** Identifies server tech and client technologies.
* **Broken Links:** Crawls the site's homepage to find 404s and other broken links (optimized for speed).
* **Security Headers:** Analyzes HTTP security headers for missing or misconfigured settings (Native scan).
* **Network & Ports:** Scans for open ports and services (Skipped in `--fast` mode).
* **SSL/TLS Config:** Runs a deep analysis of the SSL/TLS certificate and server configuration (Skipped in `--fast` mode).
* **DNS Records:** Dumps all major DNS records (MX, TXT, SPF, etc.).

## Core Toolset

This project is a "meta-tool" that couldn't exist without these amazing free services and open-source projects.

| Tool | Purpose | Type |
| :--- | :--- | :--- |
| [Google PageSpeed Insights](https://developers.google.com/speed/docs/insights/v5/get-started) | Performance (Lighthouse) | API |
| webtech library | General Tech Stack | Python Library |
| Native Requests/Python | Security Headers & Link Checker | Native Code |
| [testssl.sh](https://github.com/testssl/testssl.sh) | SSL/TLS Config | Local Tool (Bash) |
| nmap | Network & Port Scan | Local Tool (System) |
| dnspython | DNS Records | Python Library |
| [Rich](https://github.com/Textualize/rich) | Beautiful Terminal UI | Python Library |

***

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
    ```

2.  **Clone testssl.sh:** This must be cloned into the main directory for the scanner to find it. (--depth 1 flag speeds up and reduces the size of the download).
    ```bash
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git
    ```

3.  **Install Python requirements:**
    ```bash
    pip install -e .
    ```

4.  Get a PageSpeed API Key (Optional but Recommended): The PageSpeed (Lighthouse) scan will be skipped unless you provide an API key.

    * Go to the [Google Cloud credentials page](https://console.cloud.google.com/apis/credentials).
    * Create an API key and ensure the **PageSpeed Insights API** is enabled for your project.

## Usage

Run the scanner. All scans are run by default unless you use the `--fast` flag.

### Method 1: Interactive Mode (Easiest)
Just run the command, and it will prompt you for the URL.
```bash
whs
```

### Method 2: Configuration File (Recommended)
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Add your `PAGESPEED_API_KEY` to the `.env` file.
3. Run the scanner on any URL:
   ```bash
   whs https://example.com
   ```

### Method 3: Command-Line Flags
You can still provide everything via flags.

```bash
whs https://example.com --api-key "YOUR_API_KEY_HERE"
```

### Options

| Flag | Description |
| :--- | :--- |
| `--no-summary` | Disables the human-readable summary (only saves JSON). |
| `--fast` | Skips the two slow scans (`nmap` and `testssl.sh`) for a rapid health check. |
| `--output` | Specify a custom filename for the JSON report. |

-----

## License

Distributed under the MIT License. See `LICENSE` for more information
