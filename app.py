from flask import Flask, render_template, request
import os
import pkgutil
import importlib
import yaml  # for loading configuration

# Dynamic loading of scanner functions
def load_scans():
    """
    Load scan functions from plugins directory.
    Each plugin category under scanners/plugins contains modules with scan_ functions.
    """
    scans = {}
    base = os.path.dirname(__file__)
    plugins_dir = os.path.join(base, 'scanners', 'plugins')
    if not os.path.isdir(plugins_dir):
        return scans
    for category in os.listdir(plugins_dir):
        cat_path = os.path.join(plugins_dir, category)
        if not os.path.isdir(cat_path):
            continue
        for finder, module_name, ispkg in pkgutil.iter_modules([cat_path]):
            module = importlib.import_module(f'scanners.plugins.{category}.{module_name}')
            for attr in dir(module):
                if attr.startswith('scan_') and callable(getattr(module, attr)):
                    key = attr[5:]
                    scans[key] = getattr(module, attr)
    return scans

ALL_SCANS = load_scans()
# Separate enumeration and port scan from vulnerability scans
subdomain_scan = ALL_SCANS.pop('subdomains', None)
port_scan = ALL_SCANS.pop('ports', None)
vuln_scans = ALL_SCANS
# Load global configuration from config.yaml
CONFIG = {}
config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
if os.path.isfile(config_path):
    with open(config_path) as cf:
        CONFIG = yaml.safe_load(cf)

# Default scans to check on UI (override via config.yaml)
DEFAULT_SCANS = CONFIG.get('default_scans', ['sql_injection', 'xss'])
# Default PoC modules to check on UI (override via config.yaml)
DEFAULT_POC = CONFIG.get('default_pocs', [])
  
# Configure global HTTP client with timeout, retries, and concurrency limits
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_timeout = CONFIG.get('timeout', 5)
_retry_total = CONFIG.get('retry', 2)
_concurrency = CONFIG.get('concurrency', 10)

_session = requests.Session()
_retry = Retry(total=_retry_total, backoff_factor=0.5,
               status_forcelist=[500, 502, 503, 504])
_adapter = HTTPAdapter(max_retries=_retry, pool_maxsize=_concurrency)
_session.mount('http://', _adapter)
_session.mount('https://', _adapter)

def _global_get(url, *args, timeout=None, **kwargs):
    return _session.get(url, timeout=timeout or _timeout, **kwargs)
def _global_post(url, *args, timeout=None, **kwargs):
    return _session.post(url, timeout=timeout or _timeout, **kwargs)

# Override requests methods so scanner modules use configured session
requests.Session = lambda *args, **kwargs: _session
requests.get = _global_get
requests.post = _global_post
# Pretty names for display
PRETTY_NAMES = {
    'sql_injection': 'SQL 注入',
    'xss': '跨站腳本 (XSS)',
    'csrf': 'CSRF (跨站請求偽造)',
    'rce': '遠程命令執行 (RCE)',
    'exp': 'EXP PoC'
}
def pretty_name(key):
    return PRETTY_NAMES.get(key, key.replace('_', ' ').title())

app = Flask(__name__)

# Initialize Redis client for storing task status and progress
import json
import redis
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
redis_client = redis.Redis.from_url(redis_url)

# Asynchronous task executor and storage
import uuid
from concurrent.futures import ThreadPoolExecutor
from flask import jsonify, abort

# Thread pool for background scans
executor = ThreadPoolExecutor(max_workers=4)
# Task state and progress now managed via Redis

@app.route('/', methods=['GET', 'POST'])
def index():
    # Multi-step: first enumerate subdomains, then scan
    if request.method == 'POST':
        stage = request.form.get('stage')
        # Step 1: enumerate subdomains and select hosts
        if stage == 'enum':
            # Step 1: enumerate subdomains and select hosts
            target = request.form.get('url').strip()
            # load subdomain options from config
            sd_opts = CONFIG.get('subdomain_opts', {})
            subdomains = subdomain_scan(target, sd_opts) if subdomain_scan else []
            # include root domain
            from urllib.parse import urlparse
            parsed = urlparse(target)
            root = parsed.netloc
            if root.startswith('www.'):
                root = root[4:]
            hosts = [root]
            if isinstance(subdomains, list):
                hosts += subdomains
            # Provide vulnerability scan options to template (exclude PoC group)
            scans_info = [(key, pretty_name(key)) for key in vuln_scans.keys() if key != 'exp']
            # Dynamically list available PoC modules
            exp_dir = os.path.join(os.path.dirname(__file__), 'scanners', 'exp')
            pocs = []
            if os.path.isdir(exp_dir):
                for fname in os.listdir(exp_dir):
                    if fname.endswith('.py'):
                        pocs.append(fname[:-3])
            pocs.sort()
            # Pretty names for PoC modules
            pocs_info = [(p, p.replace('_', ' ').replace('-', ' ').title()) for p in pocs]
            return render_template(
                'select_hosts.html', target=target, hosts=hosts,
                scans_info=scans_info, default_scans=DEFAULT_SCANS,
                pocs_info=pocs_info, default_pocs=DEFAULT_POC
            )
        # Step 2: perform scans on selected hosts and vulnerabilities
        elif stage == 'scan':
            # Step 2: run port scans, selected vulnerability scans, and PoC modules
            target = request.form.get('target')
            hosts = request.form.getlist('hosts')
            selected = request.form.getlist('scans')
            # selected PoC modules
            selected_pocs = request.form.getlist('pocs')
            # Optional authentication via Cookie header
            cookie_header = request.form.get('cookie', '').strip()
            # Prepare to detect login requirements
            login_required = False
            # Monkey-patch requests to include cookie and detect redirects to login
            import requests as _requests
            session = _requests.Session()
            if cookie_header:
                session.headers.update({'Cookie': cookie_header})
            # Save originals
            orig_get = _requests.get
            orig_post = _requests.post
            def patched_get(*args, **kwargs):
                nonlocal login_required
                resp = session.get(*args, **kwargs)
                if resp.status_code in (401, 403) or '/login' in resp.url.lower():
                    login_required = True
                return resp
            def patched_post(*args, **kwargs):
                nonlocal login_required
                resp = session.post(*args, **kwargs)
                if resp.status_code in (401, 403) or '/login' in resp.url.lower():
                    login_required = True
                return resp
            _requests.get = patched_get
            _requests.post = patched_post
            # Perform scans
            results = {}
            results['Subdomains'] = hosts
            # Port scan with configured range
            pr = CONFIG.get('port_range')
            results['Port Scan'] = port_scan(hosts, pr) if port_scan else {}
            # run selected vulnerability scans
            for key in selected:
                scan_fun = vuln_scans.get(key)
                if scan_fun:
                    results[pretty_name(key)] = scan_fun(target)
            # run selected PoC modules if any
            if selected_pocs:
                scan_exp_fun = vuln_scans.get('exp')
                if scan_exp_fun:
                    results[pretty_name('exp')] = scan_exp_fun(target, pocs=selected_pocs)
            # Restore original request methods
            _requests.get = orig_get
            _requests.post = orig_post
            # Render results, include login flag
            return render_template('result.html', target=target,
                                   results=results,
                                   login_required=login_required)
    # GET or fallback: initial enumeration form
    return render_template('index.html')


def run_scan_task(task_id, target, hosts, selected, selected_pocs, cookie_header):
    """
    Worker function to perform scans in background and track progress.
    """
    # Mark task as running in Redis
    redis_client.set(f"scan:{task_id}:status", 'running')
    login_required = False
    # prepare request session with cookie and login detection
    import requests as _requests
    session = _requests.Session()
    if cookie_header:
        session.headers.update({'Cookie': cookie_header})
    orig_get, orig_post = _requests.get, _requests.post
    def patched_get(*args, **kwargs):
        nonlocal login_required
        resp = session.get(*args, **kwargs)
        if resp.status_code in (401, 403) or '/login' in resp.url.lower():
            login_required = True
        return resp
    def patched_post(*args, **kwargs):
        nonlocal login_required
        resp = session.post(*args, **kwargs)
        if resp.status_code in (401, 403) or '/login' in resp.url.lower():
            login_required = True
        return resp
    _requests.get, _requests.post = patched_get, patched_post
    # Progress total is initialized in api_start_scan; increment as steps complete
    # run scans
    results = {}
    results['Subdomains'] = hosts
    # port scan step
    # Port scan with configured range
    pr = CONFIG.get('port_range')
    results['Port Scan'] = port_scan(hosts, pr) if port_scan else {}
    redis_client.hincrby(f"scan:{task_id}:progress", 'done', 1)
    # vulnerability scans
    for key in selected:
        scan_fun = vuln_scans.get(key)
        if scan_fun:
            results[pretty_name(key)] = scan_fun(target)
        redis_client.hincrby(f"scan:{task_id}:progress", 'done', 1)
    # PoC scans
    if selected_pocs:
        scan_exp_fun = vuln_scans.get('exp')
        if scan_exp_fun:
            results[pretty_name('exp')] = scan_exp_fun(target, pocs=selected_pocs)
        redis_client.hincrby(f"scan:{task_id}:progress", 'done', 1)
    # restore requests
    _requests.get, _requests.post = orig_get, orig_post
    # Save results and mark done
    redis_client.set(f"scan:{task_id}:results", json.dumps({
        'results': results,
        'login_required': login_required,
        'target': target
    }))
    redis_client.set(f"scan:{task_id}:status", 'done')


@app.route('/api/start_scan', methods=['POST'])
def api_start_scan():
    # enqueue scanning task
    target = request.form.get('target')
    hosts = request.form.getlist('hosts')
    selected = request.form.getlist('scans')
    selected_pocs = request.form.getlist('pocs')
    cookie_header = request.form.get('cookie', '').strip()
    task_id = uuid.uuid4().hex
    # initialize task status and progress in Redis
    total_steps = 1 + len(selected) + (1 if selected_pocs else 0)
    redis_client.set(f"scan:{task_id}:status", 'pending')
    redis_client.hset(f"scan:{task_id}:progress", mapping={'done': 0, 'total': total_steps})
    # store target for rendering results
    redis_client.set(f"scan:{task_id}:target", target)
    # submit background task
    executor.submit(run_scan_task, task_id, target, hosts, selected, selected_pocs, cookie_header)
    return jsonify({'task_id': task_id})

@app.route('/api/scan_status/<task_id>', methods=['GET'])
def api_scan_status(task_id):
    # Retrieve task status from Redis
    status = redis_client.get(f"scan:{task_id}:status")
    if status is None:
        abort(404)
    status = status.decode()
    # Retrieve progress
    progress_raw = redis_client.hgetall(f"scan:{task_id}:progress")
    progress = {}
    if progress_raw:
        done = progress_raw.get(b'done')
        total = progress_raw.get(b'total')
        progress = {
            'done': int(done) if done else 0,
            'total': int(total) if total else 0
        }
    response = {'status': status, 'progress': progress}
    # Include results if done
    if status == 'done':
        data_json = redis_client.get(f"scan:{task_id}:results")
        data = json.loads(data_json) if data_json else {}
        response['results'] = data.get('results')
        response['login_required'] = data.get('login_required')
    return jsonify(response)

@app.route('/results/<task_id>')
def show_results(task_id):
    # Retrieve target stored at task start
    target_bytes = redis_client.get(f"scan:{task_id}:target")
    target = target_bytes.decode() if target_bytes else None
    # Retrieve results from Redis
    data_json = redis_client.get(f"scan:{task_id}:results")
    if not data_json:
        abort(404)
    data = json.loads(data_json)
    # use target from results if available, else fallback to stored target
    target = data.get('target') or target
    return render_template(
        'result.html',
        target=target,
        results=data.get('results'),
        login_required=data.get('login_required')
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
