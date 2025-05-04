import requests

def scan_csrf(url, params=None):
    """
    检测 CSRF 漏洞。
    """
    if params is None:
        params = ['csrf']  # 默认测试参数
    payload = 'dummy_token'  # 伪造的 CSRF token
    findings = {}
    for p in params:
        r = requests.get(url, params={p: payload}, timeout=5)
        findings[p] = {
            'payload': payload,
            'csrf_possible': payload in r.text
        }
    return findings
