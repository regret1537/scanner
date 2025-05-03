import os
import importlib.util
import requests

def scan_exp(url):
    """
    Dynamically load and execute all PoC scripts in scanners/exp.
    Captures findings via security_info calls.
    """
    findings = []
    exp_dir = os.path.join(os.path.dirname(__file__), 'exp')
    if not os.path.isdir(exp_dir):
        return findings
    for filename in os.listdir(exp_dir):
        if not filename.endswith('.py'):
            continue
        filepath = os.path.join(exp_dir, filename)
        mod_name = filename[:-3].replace('-', '_')
        try:
            spec = importlib.util.spec_from_file_location(mod_name, filepath)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            # Inject dummy curl
            def _curl(u, timeout=5):
                try:
                    r = requests.get(u, timeout=timeout)
                    return None, None, r.text, None, None
                except Exception:
                    return None, None, '', None, None
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