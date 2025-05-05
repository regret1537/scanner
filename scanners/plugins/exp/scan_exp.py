import os
import importlib.util
import threading
import yaml
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def scan_exp(url, pocs=None):
    """
    Dynamically load and execute PoC scripts in scanners/exp.
    If pocs is provided, only execute modules with base filenames in the pocs list.
    Captures findings via security_info calls.
    """
    # Load config for HTTP settings
    conf = {}
    conf_path = os.path.join(os.path.dirname(__file__), '..', 'config.yaml')
    if os.path.isfile(conf_path):
        with open(conf_path) as cf:
            conf = yaml.safe_load(cf)
    timeout = conf.get('timeout', 5)
    retry_total = conf.get('retry', 2)
    concurrency = conf.get('concurrency', 10)
    # Prepare HTTP session with retry and connection pool limits
    session = requests.Session()
    retries = Retry(total=retry_total, backoff_factor=0.5,
                   status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_maxsize=concurrency)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    # Semaphore to limit concurrent requests
    sem = threading.BoundedSemaphore(concurrency)
    findings = []
    # Directory containing PoC scripts
    exp_dir = os.path.join(os.path.dirname(__file__), 'pocs')
    if not os.path.isdir(exp_dir):
        return findings
    for filename in os.listdir(exp_dir):
        if not filename.endswith('.py'):
            continue
        # filter by selected pocs if provided
        filename_base = filename[:-3]
        if pocs and filename_base not in pocs:
            continue
        filepath = os.path.join(exp_dir, filename)
        mod_name = filename[:-3].replace('-', '_')
        try:
            spec = importlib.util.spec_from_file_location(mod_name, filepath)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            # Inject customized curl with timeout, retries, and concurrency control
            def _curl(u, to=None):
                """Perform HTTP GET with configured timeout and concurrency limit"""
                t = to or timeout
                sem.acquire()
                try:
                    r = session.get(u, timeout=t)
                    return None, None, r.text, None, None
                except Exception:
                    return None, None, '', None, None
                finally:
                    sem.release()
            mod.__dict__['curl'] = type('C', (), {'curl': staticmethod(_curl)})
            # Capture security_info calls
            def _security_info(info, poc=filename):
                findings.append({'poc': poc, 'info': info})
            mod.__dict__['security_info'] = _security_info
            # Execute audit if present
            if hasattr(mod, 'audit'):
                try:
                    mod.audit(url)
                except Exception as e:
                    findings.append({'poc': filename, 'error': str(e)})
        except Exception as e:
            findings.append({'poc': filename, 'error': f'Import error: {e}'})
    return findings