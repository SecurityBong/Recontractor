# Recontractor
🚜 ReconTractor: A "Self-Healing" automated WAF detection and advanced reconnaissance suite. Features intelligent dependency management, auto-virtualization for Kali Linux, and a high-signal secret-hunting engine.

# 🚜 ReconTractor (v1.0)
### Automated WAF Detection & Reconnaissance Suite For Sensitive Data
**Created By:** Rahul A.K.A SecurityBong

![Status](https://img.shields.io/badge/Status-Stable-success) ![OS](https://img.shields.io/badge/OS-Linux%20|%20Windows-blue) ![License](https://img.shields.io/badge/License-MIT-green)

ReconTractor is a robust, "Self-Healing" cybersecurity automation suite designed to orchestrate complex reconnaissance pipelines while ensuring 100% uptime through intelligent dependency management and native fallbacks.

---

## ⚡ What Makes It Unique?

### 1. 🛡️ Self-Healing Virtualization
ReconTractor detects restricted system environments (like modern Kali Linux/Debian) that block global `pip` installs. It automatically creates a dedicated `recon_env`, installs necessary components, and **re-executes itself** inside the safe environment using process replacement (`os.execv`).

### 2. 🧠 Smart Tool Manager (Path-Aware)
It doesn't just guess where your tools are. It queries the Go environment (`go env GOPATH`) to locate binaries like `httpx` or `nuclei`. If a tool is missing, it attempts a one-time background installation.

### 3. 🐍 Turbo Fallback Engine
If external binaries fail or are missing, the script activates a **Native Python Liveness Engine** capable of handling 50 concurrent threads to ensure your recon never stops.

### 4. 🤫 Zero-Spam Incremental Monitoring
ReconTractor features an **Incremental Delay Status Monitor**. Instead of spamming your terminal, it provides status updates at increasing intervals (30s, 45s, 60s...), keeping the screen clean for real vulnerability findings.

---

## 🛠️ The Tech Stack

ReconTractor orchestrates the industry's most powerful Go-based tools:

| Tool | Purpose | Status Mapping |
| :--- | :--- | :--- |
| **Katana** | Advanced Crawling & JS Parsing | `[TOOL]` |
| **Gau** | Archive URL Extraction (Wayback, etc.) | `[TOOL]` |
| **Httpx** | Live Asset Filtering | `[TOOL]` |
| **Nuclei** | Vulnerability Scanning (XSS, SQLi, CVEs) | `[PLUS RESULT]` |
| **Custom Grep**| High-Signal Secret & Juicy File Hunt | `[CORE EXTRACTION]` |



---

## 🚀 Installation & Usage

### Prerequisites
* **Python 3.10+**
* **Go (Golang)**

### Quick Start
```bash
# Clone the repository
git clone [https://github.com/YourUsername/ReconTractor.git](https://github.com/YourUsername/ReconTractor.git)
cd ReconTractor

# Run the script (Auto-Venv and tool checks will handle the rest)
python3 recontractor.py

Operation Modes
WAF Detect: Analyzes headers (Cloudflare, AWS, etc.) and performs behavioral blocking tests using benign payloads.

Full Recon: - Crawls and archives URLs.

Deduplicates and cleans the URL list.

Filters for alive endpoints.

Smart Grep: Scans for over 80 high-signal secret patterns (AWS keys, API tokens, DB credentials).

Nuclei Scan: Runs critical/high/medium templates in real-time.

📂 Output
All data is organized in a domain-specific workspace:
recon_example_com/

raw_urls.txt: All discovered endpoints.

alive.txt: Verified live URLs.

🛡️ Safe Exit Mechanism
Accidentally hit Ctrl+C? ReconTractor catches the interrupt signal and asks for confirmation before killing your scan, preventing the loss of hours of progress.

⚠️ Disclaimer
This tool is for educational and authorized security testing only. The creator, Rahul A.K.A SecurityBong, is not responsible for any misuse. Always obtain permission before scanning.

