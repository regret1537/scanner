# 網站漏洞掃描器

這是一個簡易的 Web 應用漏洞掃描器，可檢測常見的網站漏洞，如 SQL 注入 (SQL Injection) 與跨站腳本 (XSS)。採用 Python 的 Flask 框架提供使用者友好的介面，並透過各種 PoC 腳本對目標 URL 執行漏洞檢測。

## 功能

- **SQL 注入**：對 URL 參數注入常見 payload，以檢測可能的 SQL 注入漏洞。
- **跨站腳本 (XSS)**：在 URL 參數注入簡易 JavaScript payload，以檢查反射型 XSS 漏洞。
- **Web 應用介面**：利用 Flask 提供圖形化介面，無需命令列即可進行掃描。
  
### 進階功能
- **子域名枚舉**：使用 sublist3r 探索目標網域的子域名。
- **端口掃描**：透過 nmap 掃描所發現子域名的 1-10000 埠號。
- **跨站請求偽造 (CSRF)**：測試 CSRF 保護弱點。
- **遠程代碼執行 (RCE)**：對常見參數執行命令注入測試。
- **EXP PoC**：動態載入並執行 `scanners/exp` 目錄下的 PoC 腳本。

## 環境需求


- Python 3.6 或更新版本
- Git
- 虛擬環境工具（例如 `venv` 或 `virtualenv`）
- sublist3r（`pip install sublist3r`）
- nmap（透過系統套件管理工具安裝，例如 `apt install nmap`）

## 安裝

### Windows 環境

```powershell
git clone https://github.com/regret1537/scanner.git
cd scanner

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
```

### macOS 環境

```bash
git clone https://github.com/regret1537/scanner.git
cd scanner

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## 使用方式

1. 執行 Flask 應用：

   ```bash
   python app.py
   ```

2. 開啟瀏覽器並前往 `http://localhost:5000`。

3. 在首頁輸入目標 URL，點選 **列出子域名**。

4. 在子域名列表頁面：
   - 勾選要掃描的子域名。
   - （選填）如需掃描需登入後才可訪問的頁面，於「認證 Cookie」欄位輸入對應的 Cookie 值。
   - 選擇要執行的漏洞檢測項目（SQL 注入、XSS、CSRF、RCE、EXP PoC）。
   - 點選 **開始掃描**。

5. 系統將依序對選定子域名執行 nmap 端口掃描，並對原始目標 URL 執行所選漏洞檢測，最終顯示 JSON 格式的掃描結果。

6. 點選 **回到首頁** 可重新執行新的掃描。
## PoC 與 CVE 自動化
本專案提供自動化腳本，可分別同步 PoC 倉庫及更新 CVE 資料。

### 前置設定
系統需安裝 Git、Python3 與相關相依套件（requests 已包含於 `requirements.txt`）。若要抓取 CVE 資料，請先設定 Vulners API 憑證環境變數：
```bash
export VULNERS_API_ID="your_api_id"
export VULNERS_API_KEY="your_api_key"
```

### 同步 PoC
於專案根目錄執行：
```bash
./scripts/update_pocs.py
```
此腳本將會：
- 克隆或更新以下 PoC 倉庫至 `~/PoC-repos`（可透過 `POC_REPO_DIR` 環境變數調整）：
  - swisskyrepo/PayloadsAllTheThings
  - projectdiscovery/nuclei-templates
- 同步上述專案中的 `.py` PoC 腳本至 `scanners/exp` 目錄
- 同步 Nuclei `.yaml` 模板至 `scanners/nuclei_templates` 目錄

### 更新 CVE 資料
於專案根目錄執行：
```bash
./scripts/fetch_vulners_cve.py
```
此腳本將：
- 從 Vulners API 抓取 CVE 與 PoC 資料，並輸出至 `data/vulners_cve.json`

### 排程運行範例
使用 cron 每週自動更新 PoC 倉庫及 CVE 資料：
```cron
0 0 * * 0 cd /path/to/scanner && ./scripts/update_pocs.py >> cron_update_pocs.log 2>&1
0 1 * * 0 cd /path/to/scanner && ./scripts/fetch_vulners_cve.py >> cron_fetch_vulners.log 2>&1
``` 

## 插件化目錄結構
所有掃描器與 PoC 腳本都放在 `scanners/plugins/` 下，分門別類：
```
scanners/plugins/
├─ subdomain/scan_subdomains.py
├─ portscan/scan_ports.py
├─ sql_injection/scan_sql_injection.py
├─ xss/scan_xss.py
├─ csrf/scan_csrf.py
├─ rce/scan_rce.py
└─ exp/
   ├─ scan_exp.py
   └─ pocs/…  # 各 PoC 腳本
```

## 測試 (pytest)
安裝測試依賴並執行：
```bash
pip install -r requirements.txt pytest
pytest tests/
```
已經提供對所有 EXP PoC 的自動加載和執行測試 `tests/test_exp_pocs.py`，可擴充其他模組的測試。

## 任務隊列 (RQ Worker)
掃描任務非同步執行，使用 RQ + Redis：
1. 啟動 Redis：`docker-compose up -d redis` 或本機安裝並執行
2. 執行 RQ Worker：
   ```bash
   ./scripts/start_worker.sh
   ```
3. 在 Web UI 提交掃描後，即可在 `/api/scan_status/<task_id>` 查詢進度。

## Docker Compose 部署
一鍵啟動 Redis 與 Web 應用：
```bash
docker-compose up --build
```
服務將啟動於 `http://localhost:5000`，並自動連接內部 Redis。
