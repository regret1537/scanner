#!/usr/bin/env python3
"""
sync_pocs: Automatically sync PoC repositories and integrate into scanners.
"""
import os
import subprocess
import shutil

# Configuration
REPOS = [
    "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
    "https://github.com/projectdiscovery/nuclei-templates.git",
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
    for repo_name in ('PayloadsAllTheThings',):
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


def main():
    sync_repos()
    sync_python_pocs()
    sync_nuclei_templates()

if __name__ == '__main__':
    main()