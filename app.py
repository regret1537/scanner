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
    'exp': 'EXP PoC',
    'crawler': '爬蟲 (Crawler)'
}
__all__ = []

# 中文漏洞說明
VULN_DESCRIPTIONS = {
    'SQL 注入': 'SQL 注入是一種通過在輸入中插入惡意 SQL 語句改變查詢結構，可能導致未授權的數據訪問或破壞。',
    '跨站腳本 (XSS)': 'XSS 攻擊允許攻擊者在受害者的瀏覽器中執行惡意腳本，可盜取 Cookie 或進行網頁劫持。',
    'CSRF (跨站請求偽造)': 'CSRF 攻擊利用受害者已驗證的身份發送未經授權的請求，可能導致敏感操作被濫用。',
    '遠程命令執行 (RCE)': 'RCE 允許攻擊者在目標服務器上執行任意系統命令，可能導致完全控制。',
    'EXP PoC': 'EXP 模組可執行已知漏洞的 PoC 測試以驗證漏洞利用的可行性。',
    '爬蟲 (Crawler)': '爬蟲模組會抓取網站頁面以便對每個頁面進行漏洞掃描。'
}
def pretty_name(key):
    return PRETTY_NAMES.get(key, key.replace('_', ' ').title())

app = Flask(__name__)
# Configure Jinja2 JSON filter to preserve non-ASCII characters by default
app.jinja_env.policies['json.dumps_kwargs'].update({'ensure_ascii': False})

# Initialize Redis client for storing task status and progress
import json
import redis
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
redis_client = redis.Redis.from_url(redis_url)

# Asynchronous task executor and storage
import uuid
# Asynchronous task executor and storage
from concurrent.futures import ThreadPoolExecutor
from flask import jsonify, abort
# Utilities for login form parsing and URL handling
import re
import base64
from bs4 import BeautifulSoup
from urllib.parse import urljoin

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
            # Dynamically list available PoC modules from plugins/exp/pocs directory
            exp_dir = os.path.join(os.path.dirname(__file__), 'scanners', 'plugins', 'exp', 'pocs')
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
            # Handle authentication mode
            auth_mode = request.form.get('auth_mode', 'cookie')
            cookie_header = ''
            skip_login = False
            login_required = False
            import requests as _requests
            session = _requests.Session()
            if auth_mode in ('cookie', 'credentials'):
                cookie_header = request.form.get('cookie', '').strip()
                if cookie_header:
                    session.headers.update({'Cookie': cookie_header})
            elif auth_mode == 'skip':
                skip_login = True
            # Save original request methods
            orig_get = _requests.get
            orig_post = _requests.post
            # Monkey-patch requests to include cookie and detect login requirements if not skipping
            if not skip_login:
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
            # run selected vulnerability scans, including crawler with nested page scans
            for key in selected:
                scan_fun = vuln_scans.get(key)
                if not scan_fun:
                    continue
                # special handling for crawler: crawl and scan each found URL
                if key == 'crawler':
                    pages_map = scan_fun(target)
                    crawler_results = {}
                    # other scans to apply on crawled pages
                    vuln_keys = [k for k in selected if k != 'crawler']
                    for host, pages in (pages_map or {}).items():
                        host_entries = []
                        for page in pages:
                            page_res = {}
                            for vk in vuln_keys:
                                vf = vuln_scans.get(vk)
                                if vf:
                                    try:
                                        page_res[pretty_name(vk)] = vf(page)
                                    except Exception as e:
                                        page_res[pretty_name(vk)] = {'error': str(e)}
                            host_entries.append({'url': page, 'vulnerabilities': page_res})
                        crawler_results[host] = host_entries
                    results[pretty_name(key)] = crawler_results
                else:
                    results[pretty_name(key)] = scan_fun(target)
            # run selected PoC modules if any
            if selected_pocs:
                scan_exp_fun = vuln_scans.get('exp')
                if scan_exp_fun:
                    results[pretty_name('exp')] = scan_exp_fun(target, pocs=selected_pocs)
            # Restore original request methods if patched
            if not skip_login:
                _requests.get = orig_get
                _requests.post = orig_post
            # Render results, include login flag
            return render_template('result.html',
                                   target=target,
                                   results=results,
                                   login_required=login_required,
                                   vuln_descriptions=VULN_DESCRIPTIONS)
    # GET or fallback: initial enumeration form
    return render_template('index.html')


def run_scan_task(task_id, target, hosts, selected, selected_pocs, cookie_header, skip_login):
    """
    Worker function to perform scans in background and track progress.
    """
    # Mark task as running in Redis
    redis_client.set(f"scan:{task_id}:status", 'running')
    login_required = False
    # prepare request session with cookie and optional login detection
    import requests as _requests
    session = _requests.Session()
    if cookie_header:
        session.headers.update({'Cookie': cookie_header})
    orig_get, orig_post = _requests.get, _requests.post
    # Monkey-patch if not skipping login detection
    if not skip_login:
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
    # Progress total is initialized in api_start_scan; increment as steps complete
    # run scans
    results = {}
    results['Subdomains'] = hosts
    # port scan step
    # Port scan with configured range
    pr = CONFIG.get('port_range')
    results['Port Scan'] = port_scan(hosts, pr) if port_scan else {}
    redis_client.hincrby(f"scan:{task_id}:progress", 'done', 1)
    # vulnerability scans, including crawler with nested page scans
    for key in selected:
        scan_fun = vuln_scans.get(key)
        if not scan_fun:
            redis_client.hincrby(f"scan:{task_id}:progress", 'done', 1)
            continue
        if key == 'crawler':
            pages_map = scan_fun(target)
            crawler_results = {}
            vuln_keys = [k for k in selected if k != 'crawler']
            for host, pages in (pages_map or {}).items():
                host_entries = []
                for page in pages:
                    page_res = {}
                    for vk in vuln_keys:
                        vf = vuln_scans.get(vk)
                        if vf:
                            try:
                                page_res[pretty_name(vk)] = vf(page)
                            except Exception as e:
                                page_res[pretty_name(vk)] = {'error': str(e)}
                    host_entries.append({'url': page, 'vulnerabilities': page_res})
                crawler_results[host] = host_entries
            results[pretty_name(key)] = crawler_results
        else:
            results[pretty_name(key)] = scan_fun(target)
        redis_client.hincrby(f"scan:{task_id}:progress", 'done', 1)
    # PoC scans
    if selected_pocs:
        scan_exp_fun = vuln_scans.get('exp')
        if scan_exp_fun:
            results[pretty_name('exp')] = scan_exp_fun(target, pocs=selected_pocs)
        redis_client.hincrby(f"scan:{task_id}:progress", 'done', 1)
    # restore requests if patched
    if not skip_login:
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
    # Determine authentication mode and extract cookie or skip login
    auth_mode = request.form.get('auth_mode', 'cookie')
    cookie_header = ''
    skip_login = False
    if auth_mode in ('cookie', 'credentials'):
        cookie_header = request.form.get('cookie', '').strip()
    elif auth_mode == 'skip':
        skip_login = True
    task_id = uuid.uuid4().hex
    # initialize task status and progress in Redis
    total_steps = 1 + len(selected) + (1 if selected_pocs else 0)
    redis_client.set(f"scan:{task_id}:status", 'pending')
    redis_client.hset(f"scan:{task_id}:progress", mapping={'done': 0, 'total': total_steps})
    # store target for rendering results
    redis_client.set(f"scan:{task_id}:target", target)
    # submit background task (pass skip_login flag)
    executor.submit(run_scan_task, task_id, target, hosts, selected, selected_pocs, cookie_header, skip_login)
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
        login_required=data.get('login_required'),
        vuln_descriptions=VULN_DESCRIPTIONS
    )
 
@app.route('/login_setup', methods=['GET', 'POST'])
def login_setup():
    # Fetch and parse login form or perform login to retrieve cookies
    if request.method == 'GET':
        target = request.args.get('target', '').strip()
        if not target:
            return jsonify({'error': 'Missing target parameter'}), 400
        try:
            resp = requests.get(target)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        soup = BeautifulSoup(resp.text, 'html.parser')
        # Find first form with password input
        form = None
        for f in soup.find_all('form'):
            if f.find('input', {'type': 'password'}):
                form = f
                break
        if not form:
            return jsonify({'error': 'Login form not found'}), 404
        # Determine form action URL
        action = form.get('action') or target
        login_url = urljoin(resp.url, action)
        # Detect username field
        username_field = None
        for inp in form.find_all('input'):
            name = inp.get('name')
            t = inp.get('type', 'text')
            if name and t in ('text', 'email'):
                if re.search('user|email|phone|id', name, re.I):
                    username_field = name
                    break
                if not username_field:
                    username_field = name
        # Detect password field
        password_field = None
        for inp in form.find_all('input', {'type': 'password'}):
            name = inp.get('name')
            if name:
                password_field = name
                break
        # Detect captcha field and image
        captcha_field = None
        captcha_image = None
        for inp in form.find_all('input'):
            name = inp.get('name')
            if name and re.search('captcha', name, re.I):
                captcha_field = name
                break
        if not captcha_field:
            for img in form.find_all('img'):
                src = img.get('src')
                if src and re.search('captcha', src, re.I):
                    c_url = urljoin(resp.url, src)
                    try:
                        img_resp = requests.get(c_url)
                        b64 = base64.b64encode(img_resp.content).decode()
                        captcha_image = f'data:image/png;base64,{b64}'
                    except Exception:
                        captcha_image = None
                    # find associated input
                    for sibling in img.parent.find_all('input'):
                        nm = sibling.get('name')
                        if nm:
                            captcha_field = nm
                            break
                    break
        return jsonify({
            'login_url': login_url,
            'username_field': username_field,
            'password_field': password_field,
            'captcha_field': captcha_field,
            'captcha_image': captcha_image
        })
    # POST: perform login
    login_url = request.form.get('login_url')
    username_field = request.form.get('username_field')
    password_field = request.form.get('password_field')
    captcha_field = request.form.get('captcha_field')
    username = request.form.get('username')
    password = request.form.get('password')
    captcha = request.form.get('captcha') if captcha_field else None
    if not login_url or not username_field or not password_field:
        return jsonify({'error': 'Missing login parameters'}), 400
    session = requests.Session()
    data = {username_field: username, password_field: password}
    if captcha_field and captcha:
        data[captcha_field] = captcha
    try:
        resp = session.post(login_url, data=data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    # Extract cookies
    cookie_header = '; '.join([f"{c.name}={c.value}" for c in session.cookies])
    return jsonify({'cookie': cookie_header})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
