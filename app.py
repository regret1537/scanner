from flask import Flask, render_template, request
from scanners.sql_injection import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf import scan_csrf
from scanners.rce import scan_rce
from scanners.exp_scanner import scan_exp
from scanners.subdomain import scan_subdomains
from scanners.portscan import scan_ports

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Multi-step: first enumerate subdomains, then scan
    if request.method == 'POST':
        stage = request.form.get('stage')
        # Step 1: enumerate subdomains and select hosts
        if stage == 'enum':
            target = request.form.get('url').strip()
            subdomains = scan_subdomains(target)
            # include root domain
            from urllib.parse import urlparse
            parsed = urlparse(target)
            root = parsed.netloc
            if root.startswith('www.'):
                root = root[4:]
            hosts = []
            if isinstance(subdomains, list):
                hosts = [root] + subdomains
            else:
                hosts = [root]
            return render_template('select_hosts.html', target=target, hosts=hosts)
        # Step 2: perform scans on selected hosts and vulnerabilities
        elif stage == 'scan':
            target = request.form.get('target')
            hosts = request.form.getlist('hosts')
            scans = request.form.getlist('scans')
            results = {}
            # Subdomains list
            results['Subdomains'] = hosts
            # Port scanning on selected hosts
            results['Port Scan'] = scan_ports(hosts)
            # Vulnerability scans on original target
            if 'sqli' in scans:
                results['SQL Injection'] = scan_sql_injection(target)
            if 'xss' in scans:
                results['XSS'] = scan_xss(target)
            if 'csrf' in scans:
                results['CSRF'] = scan_csrf(target)
            if 'rce' in scans:
                results['RCE'] = scan_rce(target)
            if 'exp' in scans:
                results['EXP'] = scan_exp(target)
            return render_template('result.html', target=target, results=results)
    # GET or fallback: initial enumeration form
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
