import subprocess
import tempfile
import os
from urllib.parse import urlparse

def scan_subdomains(url):
    """
    Use sublist3r to enumerate subdomains of the target domain.
    Returns a list of discovered subdomains or an error dict.
    """
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    findings = []
    try:
        # Output file for sublist3r
        with tempfile.NamedTemporaryFile(delete=False, mode='w+') as tf:
            tmpfile = tf.name
        cmd = ['sublist3r', '-d', domain, '-o', tmpfile]
        # Suppress sublist3r stdout/stderr
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        # Read results
        with open(tmpfile) as f:
            for line in f:
                sub = line.strip()
                if sub:
                    findings.append(sub)
        os.unlink(tmpfile)
    except Exception as e:
        return {'error': str(e)}
    return findings