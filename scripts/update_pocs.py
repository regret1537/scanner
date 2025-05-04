#!/usr/bin/env python3
"""
sync_pocs: Automatically sync PoC repositories, update CVE data, and integrate into scanners.
"""
import os
import sys
import subprocess
import shutil
import requests
import json

# Configuration
REPOS = [
    "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
    "https://github.com/projectdiscovery/nuclei-templates.git",
    "https://github.com/0xInfection/Awesome-PoCs.git",
]
# Directory where PoC repos will be cloned or updated
POC_DIR = os.path.abspath(os.path.expanduser(os.environ.get('POC_REPO_DIR', '~/PoC-repos')))
# Project root (assumes this script is in scripts/)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
# Scanners integration directories
SCANNERS_DIR = os.path.join(PROJECT_ROOT, 'scanners')
EXP_DIR = os.path.join(SCANNERS_DIR, 'exp')
NUCLEI_DIR = os.path.join(SCANNERS_DIR, 'nuclei_templates')
# Data directory for CVE and PoC metadata
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
VULNERS_CVE_FILE = os.path.join(DATA_DIR, 'vulners_cve.json')

def git_clone_or_pull(repo_url, dest_dir):
    if os.path.isdir(os.path.join(dest_dir, '.git')):
        print(f"Updating {dest_dir}")
        subprocess.run(['git', '-C', dest_dir, 'pull', '--quiet'], check=True)
    else:
        print(f"Cloning {repo_url} into {dest_dir}")
        subprocess.run(['git', 'clone', '--quiet', repo_url, dest_dir], check=True)

def sync_repos():
    os.makedirs(POC_DIR, exist_ok=True)
    for repo in REPOS:
        name = os.path.basename(repo).rstrip('.git')
        dest = os.path.join(POC_DIR, name)
        git_clone_or_pull(repo, dest)

def sync_python_pocs():
    # Copy all .py files from PoC repos into scanners/exp
    os.makedirs(EXP_DIR, exist_ok=True)
    # Clear existing PoCs
    for f in os.listdir(EXP_DIR):
        path = os.path.join(EXP_DIR, f)
        if os.path.isfile(path):
            os.unlink(path)
    # Re-populate
    for repo_name in ('PayloadsAllTheThings', 'Awesome-PoCs'):
        src_root = os.path.join(POC_DIR, repo_name)
        if os.path.isdir(src_root):
            for root, _, files in os.walk(src_root):
                for file in files:
                    if file.endswith('.py'):
                        src_file = os.path.join(root, file)
                        dst_file = os.path.join(EXP_DIR, file)
                        try:
                            shutil.copy2(src_file, dst_file)
                        except Exception:
                            pass

def sync_nuclei_templates():
    # Sync nuclei-templates to scanners/nuclei_templates
    os.makedirs(NUCLEI_DIR, exist_ok=True)
    src = os.path.join(POC_DIR, 'nuclei-templates')
    if os.path.isdir(src):
        # Remove old templates
        for entry in os.listdir(NUCLEI_DIR):
            path = os.path.join(NUCLEI_DIR, entry)
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        # Copy new templates
        shutil.copytree(src, NUCLEI_DIR, dirs_exist_ok=True)

def fetch_vulners_cve():
    api_id = os.environ.get('VULNERS_API_ID')
    api_key = os.environ.get('VULNERS_API_KEY')
    if not api_id or not api_key:
        print('VULNERS_API_ID or VULNERS_API_KEY not set; skipping CVE fetch')
        return
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

def main():
    sync_repos()
    sync_python_pocs()
    sync_nuclei_templates()
    fetch_vulners_cve()

if __name__ == '__main__':
    main()