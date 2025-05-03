import requests

def scan_rce(url, params=None):
    """
    Simple RCE scan: injects a payload into URL parameters to test for command injection.
    """
    if params is None:
        params = ['cmd']
    findings = {}
    for p in params:
        try:
            # Normal request
            r1 = requests.get(url, params={p: '1'}, timeout=5)
            # Payload that echoes a unique string
            payload = '1;echo RCE_TEST'
            r2 = requests.get(url, params={p: payload}, timeout=5)
            text1 = r1.text or ''
            text2 = r2.text or ''
            echo_found = 'RCE_TEST' in text2
            findings[p] = {
                'normal_length': len(text1),
                'injected_length': len(text2),
                'rce_echo_found': echo_found,
                'possible_rce': echo_found or len(text1) != len(text2)
            }
        except Exception as e:
            findings[p] = {'error': str(e)}
    return findings
