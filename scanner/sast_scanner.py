#!/usr/bin/env python3
import os
import hashlib
import subprocess
import json
import re
from pathlib import Path
from analyze_vulnerabilities import main as New

# Detect repository language
def detect_language(project_dir):
    extensions = {
        'Python': ['.py'],
        'JavaScript': ['.js'],
        'Java': ['.java'],
        'Go': ['.go'],
        'Ruby': ['.rb'],
        'PHP': ['.php'],
        'C++': ['.cpp', '.hpp'],
        'C#': ['.cs'],
    }
    lang_count = {lang: 0 for lang in extensions.keys()}
    for root, _, files in os.walk(project_dir):
        for file in files:
            ext = Path(file).suffix
            for lang, exts in extensions.items():
                if ext in exts:
                    lang_count[lang] += 1
    return max(lang_count, key=lang_count.get)


# Generate a unique hash for the repository
def create_project_hash(project_dir):
    hasher = hashlib.md5()
    for root, _, files in os.walk(project_dir):
        for file in files:
            with open(os.path.join(root, file), 'rb') as f:
                buf = f.read()
                hasher.update(buf)
    return hasher.hexdigest()

def run_bearer_scan(project_dir):
    result = {}
    try:
        process = subprocess.run(["bearer", "scan", "--json", "--output", "bearer_output.json", "--silent", project_dir], capture_output=True, text=True)
        result['sast_output'] = process.stdout
    except Exception as e:
        result['sast_error'] = str(e)
    return result

# Execute Semgrep
def run_semgrep_scan(project_dir):
    result = {}
    try:
        process = subprocess.run(["semgrep", "--config=auto", "--json", "--output", "semgrep_output.json", project_dir], capture_output=True, text=True)
        result['semgrep_output'] = process.stdout
    except Exception as e:
        result['semgrep_error'] = str(e)
    return result

# Execute Trivy FS
def run_trivy_scan(project_dir):
    result = {}
    try:
        process = subprocess.run(["trivy", "fs", "--format json", "-o", "trivy_output.json", project_dir], capture_output=True, text=True)
        result['trivy_output'] = process.stdout
    except Exception as e:
        result['trivy_error'] = str(e)
    return result

def main():
    project_dir = os.getcwd()

    if not os.path.isdir(project_dir):
        print("Invalid directory path.")
        return

    language = detect_language(project_dir)
    project_hash = create_project_hash(project_dir)

    bearer_results = run_bearer_scan(project_dir)
    semgrep_results = run_semgrep_scan(project_dir)
    trivy_results = run_trivy_scan(project_dir)

    report = {
        "project": {
            "language": language,
            "project_hash": project_hash
        },
        "sast_results": bearer_results,
        "semgrep_results": semgrep_results,
        "trivy_results": trivy_results
    }

    print(json.dumps(report, indent=4))
    New()


if __name__ == "__main__":
    main()
