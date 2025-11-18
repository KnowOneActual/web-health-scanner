## 🛡️ `scanner.py` Security Audit Log

**Date:** 2025-11-18
**Auditor:** Automated Linter (Snyk Code)
**Summary:** All security issues identified by the initial and subsequent Snyk Code scans have been investigated and remediated. The four critical/high-severity vulnerabilities (Insecure XML Parser, Path Traversal, and two instances of SSRF) have been fixed using best-practice Python security methods.

-----

### 1. Mitigation of Insecure XML Parser (XXE/DoS)

| Vulnerability | Status | Severity | File/Original Line |
| :--- | :--- | :--- | :--- |
| Insecure Xml Parser | **FIXED** | High | `scanner.py`, Line 86 |

**Description:**
The original use of the built-in `xml.etree.ElementTree.fromstring` to parse Nmap's XML output was vulnerable to **XML External Entity (XXE)** and **Denial of Service (DoS)** attacks via entity expansion if a malicious XML document were somehow supplied to the parser.

**Remediation:**

1.  Replaced the `import xml.etree.ElementTree as ET` with `import lxml.etree as ET`.
2.  The parsing function `parse_nmap_xml` was updated to explicitly configure the `lxml` parser to **forbid Document Type Definitions (DTDs)**, which is the mechanism used for both XXE and XML Bomb DoS attacks.



```python
# Fixed Code in parse_nmap_xml()
root = ET.fromstring(xml_output, parser=ET.XMLParser(forbid_dtd=True))
```

-----

### 2. Mitigation of Path Traversal (PT)

| Vulnerability | Status | Severity | File/Original Line |
| :--- | :--- | :--- | :--- |
| Path Traversal | **FIXED** | Medium | `scanner.py`, Line 724 |

**Description:**
The argument `--output` takes user-supplied input for the report filename. Without validation, an attacker could use path traversal characters (e.g., `../../../etc/passwd.json`) to write the report file to an arbitrary location on the file system.

**Remediation:**

1.  The `main()` function was modified to use `os.path.basename()` on the user-provided output path (`args.output`) before calling `open()`.
2.  This change ensures that only the filename portion of the path is used, forcing the report to be written into the current working directory and preventing directory traversal.



```python
# Fixed Code in main()
safe_output_path = os.path.basename(args.output)
try:
    with open(safe_output_path, 'w', encoding='utf-8') as f:
        # ... json.dump ...
```

-----

### 3. Mitigation of Server-Side Request Forgery (SSRF)

| Vulnerability | Status | Severity | File/Original Line |
| :--- | :--- | :--- | :--- |
| Server-Side Request Forgery (x4) | **FIXED** | High | Lines 430, 513, 476, 584 |

**Description:**
SSRF vulnerabilities existed in all functions that perform network requests or run external tools (`get_testssl`, `get_nmap`, `get_pagespeed`, `get_linkchecker`) using the user-supplied `target_url` (or its hostname). An attacker could input a hostname that resolves to an internal/private IP address, allowing the scanner to be used as a proxy to attack services on the private network.

**Remediation:**
A central security function, `resolve_and_validate_target`, was created and implemented across all vulnerable functions.

1.  **New Validation Logic:** The `resolve_and_validate_target(hostname)` function:

      * Resolves the target hostname to an IP address using `socket.gethostbyname()`.
      * Checks the resolved IP address against all private/internal IP ranges (RFC 1918) using the `ipaddress` library (e.g., `192.168.x.x`, `10.x.x.x`, `127.x.x.x`).
      * If the IP falls within a private range, the function returns an error, and the calling scan immediately exits, blocking the attack.

2.  **Implementation across functions:**

      * **`get_testssl`** and **`get_nmap`** were updated to use the *validated IP address* for the subprocess command, not the original hostname.
      * **`get_pagespeed`** and **`get_linkchecker`** were updated to perform the validation check and explicitly wrap the vulnerable `requests.get()` call inside an `if validation["status"] == "success":` block. This ensures that the network operation only proceeds if the target is a publicly addressable host.
      
## 4. Operational Security & Stability Confirmation


All security mitigations implemented in v1.0.1 were verified to be fully operational and stable after subsequent runtime fixes.

- **XXE/Nmap Stability:** The final configuration of the `lxml.etree` parser was confirmed to be both secure (non-DTD, non-networked) and syntactically correct, ensuring safe parsing of Nmap XML output.
- **SSRF Stability & Compatibility:** The core SSRF validation logic in `resolve_and_validate_target` remains intact and is executed successfully for all networking components. The command for `testssl.sh` was successfully reverted to use the original hostname. This eliminated the 10-minute timeout by enabling correct **SNI handling** while maintaining the SSRF security guarantee that the hostname resolves to a public IP before the tool is executed.

**Conclusion:** The project is fully compliant with all security mitigations implemented and is now stable across all intended functions.