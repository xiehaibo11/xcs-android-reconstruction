#!/usr/bin/env python3
"""Audit existing reverse-engineering proof files; never executes target code."""

from _paths import app_root, workspace_root
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

APP = app_root()
ANALYSIS = APP / 'analysis'
OUT = ANALYSIS / 'completeness_audit/evidence'
VERIFIERS = ['verify_deep_extract.py', 'verify_protocol_reconstruction.py',
             'verify_ws_result_reconstruction.py', 'verify_runtime_reconstruction.py',
             'verify_connection_preview_closure.py', 'verify_reconnect_preview_failure.py']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference_audit():
    cache, missing, mismatches, inputs = {}, [], [], []
    checks = 0

    def resolve(value, base):
        path = Path(value)
        if path.is_absolute():
            return path
        for candidate in [APP / path, base / path, ANALYSIS / path, APP.parent / path,
                          APP / 'unpacked/lib/arm64-v8a' / path]:
            if candidate.is_file():
                return candidate
        return APP / path

    def walk(node, base, document):
        nonlocal checks
        if isinstance(node, list):
            for value in node:
                walk(value, base, document)
        elif isinstance(node, dict):
            pairs = []
            if isinstance(node.get('sha256'), str):
                pairs.extend((key, 'sha256') for key in ['file', 'path']
                             if isinstance(node.get(key), str))
            pairs.extend((key, key + '_sha256') for key in
                         ['source', 'snippet', 'complete_excerpt', 'elf_file', 'library', 'llvm_file', 'binary']
                         if isinstance(node.get(key), str) and isinstance(node.get(key + '_sha256'), str))
            if isinstance(node.get('copied_complete_ghidra_body'), str) and isinstance(node.get('copied_sha256'), str):
                pairs.append(('copied_complete_ghidra_body', 'copied_sha256'))
            for file_key, hash_key in pairs:
                expected = node[hash_key]
                if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
                    continue
                if '://' in node[file_key]:
                    continue
                path = resolve(node[file_key], base)
                checks += 1
                record = {'document': str(document.relative_to(APP)), 'key': file_key, 'file': str(path)}
                if not path.is_file():
                    missing.append(record)
                    continue
                if path not in cache:
                    cache[path] = digest(path)
                if cache[path] != expected:
                    mismatches.append({**record, 'expected_sha256': expected, 'current_sha256': cache[path]})
            for value in node.values():
                walk(value, base, document)

    for path in sorted(ANALYSIS.rglob('*.json')):
        if 'completeness_audit' in path.parts:
            continue
        try:
            node = json.loads(path.read_text())
        except Exception as error:
            mismatches.append({'document': str(path.relative_to(APP)), 'parse_error': type(error).__name__})
            continue
        inputs.append({'file': str(path), 'sha256': digest(path)})
        walk(node, path.parent, path)
    result = {'existing_json_documents': len(inputs), 'hash_reference_checks': checks,
              'unique_files_hashed': len(cache), 'missing_references': missing,
              'mismatched_references': mismatches, 'inputs': inputs,
              'scope': 'Existing analysis JSON path+SHA references only; semantic coverage is audited separately.'}
    (OUT / 'existing_reference_audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'reference_audit': 'PASS' if not missing and not mismatches else 'FINDINGS',
                      'documents': len(inputs), 'references': checks,
                      'missing': len(missing), 'mismatches': len(mismatches)}, ensure_ascii=False), flush=True)
    return result


def rerun_verifiers():
    results = []
    for name in VERIFIERS:
        script = APP / 'scripts' / name
        command = [sys.executable, str(script)]
        process = subprocess.run(command, cwd=APP, capture_output=True, text=True)
        log = OUT / (script.stem + '.log.txt')
        log.write_text(process.stdout + process.stderr)
        results.append({'script': str(script), 'script_sha256': digest(script),
                        'exit_code': process.returncode, 'passed': process.returncode == 0,
                        'log': str(log), 'log_sha256': digest(log),
                        'target_code_executed': False})
        print(json.dumps({'script': name, 'exit_code': process.returncode}, ensure_ascii=False), flush=True)
    result = {'all_verifiers_passed': all(item['passed'] for item in results),
              'verifiers': results, 'target_code_executed': False, 'business_server_contacted': False}
    (OUT / 'verifier_rerun.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--rerun-verifiers', action='store_true')
    options = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if options.rerun_verifiers:
        rerun_verifiers()
    reference_audit()
