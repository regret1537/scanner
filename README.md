# Vulnerability Scanner

This is a simple web application designed to scan for common vulnerabilities like SQL Injection and XSS (Cross-Site Scripting) in websites. It uses Python's Flask framework to provide a user-friendly interface, and various proof-of-concept (PoC) scripts to detect potential security issues in target URLs.

## Features

- **SQL Injection**: Scans for potential SQL Injection vulnerabilities by injecting common payloads into URL parameters.
- **XSS (Cross-Site Scripting)**: Checks for reflected XSS vulnerabilities by injecting a simple JavaScript payload into URL parameters.
- **Flask Web Application**: Provides an easy-to-use web interface to test URLs for vulnerabilities.
  
### Additional Features
- **Subdomain Enumeration**: Uses sublist3r to discover subdomains of the target domain.
- **Port Scanning**: Uses nmap to scan ports 1-10000 on discovered subdomains.
- **CSRF (Cross-Site Request Forgery)**: Tests for weak or missing CSRF protections by submitting fake tokens.
- **RCE (Remote Code Execution)**: Performs simple command injection tests by injecting payloads into common parameters.
- **EXP PoC**: Dynamically loads and executes proof-of-concept (PoC) scripts from the `scanners/exp` directory.

## Prerequisites

Before you begin, ensure that you have met the following requirements:

- Python 3.6 or later
- Git
- A virtual environment tool (e.g., `venv` or `virtualenv`)
- sublist3r (install via `pip install sublist3r`)
- nmap (install via your OS package manager, e.g., `apt install nmap`)

## Installation

### Step 1: Clone the Repository

Clone this repository to your local machine using the following command:

```bash
git clone https://github.com/regret1537/scanner.git
cd scanner
```

### Step 2: (Optional) Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

1. Run the Flask application:

   ```bash
   python app.py
   ```

2. Open your browser and navigate to `http://localhost:5000`.

3. Step 1: 在首頁輸入目標 URL，點選 **列出子域名**，系統將使用 sublist3r 枚舉子域名。

4. Step 2: 在子域名選擇頁面，可勾選要進行端口掃描的子域名，並在下方勾選其他漏洞檢測項目（SQLi、XSS、CSRF、RCE、EXP PoC），然後點選 **開始掃描**。

5. 系統將依序對所選子域名執行 nmap 端口掃描，並對原始目標 URL 執行所選的漏洞檢測，最後顯示 JSON 格式的掃描結果。

6. 點選 **回到首頁** 可重新執行新的掃描。
## PoC & CVE Automation
本專案提供一個自動化腳本，可定期同步多個 PoC 專案、更新 CVE 資料，並整合到掃描器中。
### 前置設定
1. 設定 Vulners API 憑證環境變數：
   ```bash
   export VULNERS_API_ID="your_api_id"
   export VULNERS_API_KEY="your_api_key"
   ```
2. 確保系統已安裝 Git、Python3 及相關依賴（`requests` 已包含於 `requirements.txt`）。

### 使用方式
於專案根目錄執行：
```bash
./scripts/update_pocs.py
```
此腳本將：
- 克隆或更新以下專案到 `~/PoC-repos`（可透過環境變數 `POC_REPO_DIR` 調整）：
  - swisskyrepo/PayloadsAllTheThings
  - projectdiscovery/nuclei-templates
  - 0xInfection/Awesome-PoCs
- 同步各專案中的 `.py` PoC 腳本到 `scanners/exp` 目錄
- 同步 Nuclei `.yaml` 模板到 `scanners/nuclei_templates` 目錄
- 從 Vulners API 抓取 CVE & PoC 資料，輸出至 `data/vulners_cve.json`

### 排程 (cron)
每週自動更新範例：
```cron
0 0 * * 0 cd /path/to/scanner && ./scripts/update_pocs.py >> cron_update_pocs.log 2>&1
```
