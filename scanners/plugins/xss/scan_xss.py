import requests

def scan_xss(url, params=None):
    """
    對 URL 的每個參數送入 <script>alert()</script>，
    如果回傳中含有該 payload，就標記可能有反射型 XSS。
    """
    if params is None:
        params = ['q']    # 預設測試參數
    payload = '<script>alert("XSS")</script>'
    findings = {}
    for p in params:
        r = requests.get(url, params={p: payload}, timeout=5)
        findings[p] = {
            'payload': payload,
            'reflected': payload in r.text
        }
    return findings
