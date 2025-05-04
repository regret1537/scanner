from flask import Flask, render_template, request
import os
import pkgutil
import importlib

# Dynamic loading of scanner functions
def load_scans():
    scans = {}
    scanners_dir = os.path.join(os.path.dirname(__file__), 'scanners')
    for finder, module_name, ispkg in pkgutil.iter_modules([scanners_dir]):
        module = importlib.import_module(f'scanners.{module_name}')
        for attr in dir(module):
            if attr.startswith('scan_') and callable(getattr(module, attr)):
                scans[attr[5:]] = getattr(module, attr)
    return scans

ALL_SCANS = load_scans()
# Separate enumeration and port scan from vulnerability scans
subdomain_scan = ALL_SCANS.pop('subdomains', None)
port_scan = ALL_SCANS.pop('ports', None)
vuln_scans = ALL_SCANS

# Default scans to check on UI
DEFAULT_SCANS = ['sql_injection', 'xss']
# Pretty names for display
PRETTY_NAMES = {
    'sql_injection': 'SQL Injection',
    'xss': 'XSS',
    'csrf': 'CSRF',
    'rce': 'RCE',
    'exp': 'EXP PoC'
}
def pretty_name(key):
    return PRETTY_NAMES.get(key, key.replace('_', ' ').title())

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Multi-step: first enumerate subdomains, then scan
    if request.method == 'POST':
        stage = request.form.get('stage')
        # Step 1: enumerate subdomains and select hosts
        if stage == 'enum':
            # Step 1: enumerate subdomains and select hosts
            target = request.form.get('url').strip()
            subdomains = subdomain_scan(target) if subdomain_scan else []
            # include root domain
            from urllib.parse import urlparse
            parsed = urlparse(target)
            root = parsed.netloc
            if root.startswith('www.'):
                root = root[4:]
            hosts = [root]
            if isinstance(subdomains, list):
                hosts += subdomains
            # Provide vulnerability scan options to template
            scans_info = [(key, pretty_name(key)) for key in vuln_scans.keys()]
            return render_template('select_hosts.html', target=target, hosts=hosts,
                                   scans_info=scans_info, default_scans=DEFAULT_SCANS)
        # Step 2: perform scans on selected hosts and vulnerabilities
        elif stage == 'scan':
            # Step 2: run port scans and selected vulnerability scans
            target = request.form.get('target')
            hosts = request.form.getlist('hosts')
            selected = request.form.getlist('scans')
            results = {}
            # Subdomains list
            results['Subdomains'] = hosts
            # Port scanning on selected hosts
            results['Port Scan'] = port_scan(hosts) if port_scan else {}
            # Vulnerability scans on original target
            for key in selected:
                scan_fun = vuln_scans.get(key)
                if scan_fun:
                    results[pretty_name(key)] = scan_fun(target)
            return render_template('result.html', target=target, results=results)
    # GET or fallback: initial enumeration form
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
