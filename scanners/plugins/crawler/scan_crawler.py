import requests
from urllib.parse import urlparse, urljoin
from collections import deque
from bs4 import BeautifulSoup

from scanners.plugins.subdomain.scan_subdomains import scan_subdomains

def scan_crawler(url, opts=None):
    """
    Crawl each subdomain of the given URL up to a specified depth and max pages.
    opts: dict of options: depth (int), max_pages (int), timeout (int), https (bool)
    Returns a dict mapping host -> list of crawled URLs.
    """
    if opts is None:
        opts = {}
    depth = opts.get('depth', 2)
    max_pages = opts.get('max_pages', 20)
    timeout = opts.get('timeout', 5)
    use_https = opts.get('https', True)

    findings = {}
    # enumerate subdomains
    try:
        subs = scan_subdomains(url, opts)
        if not isinstance(subs, list):
            subs = []
    except Exception:
        subs = []
    # include root domain
    parsed = urlparse(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    hosts = [host] + subs

    for h in hosts:
        scheme = 'https://' if use_https else 'http://'
        start_url = f"{scheme}{h}"
        visited = set()
        queue = deque([(start_url, 0)])
        pages = []
        while queue and len(visited) < max_pages:
            current, d = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            pages.append(current)
            if d >= depth:
                continue
            try:
                resp = requests.get(current, timeout=timeout)
                content = resp.text or ''
            except Exception:
                continue
            soup = BeautifulSoup(content, 'html.parser')
            for tag in soup.find_all('a', href=True):
                href = tag['href']
                joined = urljoin(current, href)
                parsed2 = urlparse(joined)
                if parsed2.netloc == h:
                    # strip fragment and trailing slash
                    url_no_fragment = joined.split('#')[0].rstrip('/')
                    if url_no_fragment not in visited:
                        queue.append((url_no_fragment, d+1))
        findings[h] = pages
    return findings