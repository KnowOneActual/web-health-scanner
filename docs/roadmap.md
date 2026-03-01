# Project Mission & Roadmap

## 🎯 Mission Statement

To provide developers, hobbyists, and site owners with a single, free, and open-source command-line tool that aggregates comprehensive data on a website's performance, security, and technical health, eliminating the need to use multiple, separate, or paid services.

## 🗺️ Roadmap

### ✅ Completed Milestones

#### [v1.2] Concurrency & Modern UI (Latest)
- **Parallel Scanning:** Implemented `ThreadPoolExecutor` to run all independent scans simultaneously, reducing execution time by ~70%.
- **Rich Terminal UI:** Integrated the `rich` library for real-time progress bars, beautiful tables, and panels.
- **Optimized Scanning:** Refined the link checker to focus on homepage health for faster reporting.

#### [v1.1] Reorganization & Modernization
- **Project Structure:** Migrated to a standard `src/` layout with a proper Python package.
- **Professional Packaging:** Added `pyproject.toml` and package entry points.
- **Testing Foundation:** Initialized `tests/` with automated CLI verification.

#### [v1.0] Polish & Stability
- **Security Audit:** Implemented SSRF and Path Traversal mitigations.
- **Dependency Guard:** Added startup checks for `nmap` and `testssl.sh`.
- **Error Handling:** Added robust `try...except` blocks for all external integrations.

---

### 🚀 Future Goals

#### v2.0: Architecture & Extensibility
*   [ ] **Plugin System:** Refactor scanners into a class-based registry to make adding new checks (e.g., WordPress-specific, SEO-deep-dive) trivial.
*   [ ] **Configuration:** Add support for a `config.yaml` to allow users to define custom scan profiles and API keys permanently.
*   [ ] **One-Command Setup:** Implement a `web-health-scanner --setup` command to automatically download and configure `testssl.sh` and other local tools.

#### v3.0: Visual Reporting & Integrations
*   [ ] **HTML/PDF Export:** Use Jinja2 templates to generate beautiful, standalone visual reports with charts.
*   [ ] **Webhooks:** Add native support for Slack, Discord, or Teams webhooks for automated monitoring results.
*   [ ] **Interactive Mode:** An optional interactive TUI (Terminal User Interface) using `Textual` for deep-diving into report details without leaving the terminal.

#### v4.0: Portability & Distribution
*   [ ] **Docker Support:** Provide an official Docker image that bundles all dependencies (`nmap`, `testssl.sh`) for zero-config execution.
*   [ ] **GitHub Action:** Release as a first-class GitHub Action for automated site health checks in CI/CD pipelines.
*   [ ] **The Rust Exploration:** Investigate a core rewrite in Rust for even faster execution, zero-dependency distribution, and improved memory safety.
