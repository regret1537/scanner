#!/usr/bin/env python3
"""
fetch_vulners_cve: Fetch CVE and PoC data from Vulners API and save to data/vulners_cve.json.
"""
import os
import sys
import requests
import json

# Determine project root assuming this script is in scripts/
SCRIPT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
VULNERS_CVE_FILE = os.path.join(DATA_DIR, 'vulners_cve.json')

def fetch_vulners_cve():
    api_id = os.environ.get('VULNERS_API_ID')
    api_key = os.environ.get('VULNERS_API_KEY')
    if not api_id or not api_key:
        print('VULNERS_API_ID or VULNERS_API_KEY not set; skipping CVE fetch')
        sys.exit(1)
    os.makedirs(DATA_DIR, exist_ok=True)
    url = 'https://vulners.com/api/v3/search/lucene/'
    payload = {'query': 'type:exploit OR type:Poc'}
    try:
        resp = requests.post(url, json=payload, auth=(api_id, api_key), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        with open(VULNERS_CVE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f'Saved Vulners CVE data to {VULNERS_CVE_FILE}')
    except Exception as e:
        print(f'Error fetching Vulners CVE data: {e}', file=sys.stderr)
        sys.exit(1)

def main():
    fetch_vulners_cve()

if __name__ == '__main__':
    main()