#!/usr/bin/env python3
"""Check recovered evidence against original files and native instructions."""

from _paths import app_root, workspace_root
import hashlib
import json
from pathlib import Path

ROOT = app_root()
expected_apk = '8fd060966759990ab5ef90639e3376a2b6aea209f3f545d768a2fdc668dfeaa9'
original = ROOT.parent / 'app_xcs(新).apk.1.1'
assert hashlib.sha256(original.read_bytes()).hexdigest() == expected_apk
source_cache = {}
line_checks = 0
hash_checks = 0
json_files = []

def source(path):
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    if p not in source_cache:
        source_cache[p] = (p.read_bytes(), p.read_text().splitlines())
    return source_cache[p]

def walk(node):
    global line_checks, hash_checks
    if isinstance(node, dict):
        if isinstance(node.get('file'), str) and isinstance(node.get('line'), int) and 'excerpt' in node:
            _, lines = source(node['file'])
            assert lines[node['line'] - 1].strip() == node['excerpt'].strip(), node
            line_checks += 1
        if isinstance(node.get('file'), str) and isinstance(node.get('sha256'), str):
            p = Path(node['file'])
            if not p.is_absolute(): p = ROOT / p
            if p.exists():
                assert hashlib.sha256(p.read_bytes()).hexdigest() == node['sha256'], str(p)
                hash_checks += 1
        for value in node.values(): walk(value)
    elif isinstance(node, list):
        for value in node: walk(value)

for folder in ['login_flow', 'http_contract', 'message_semantics', 'aot_runtime']:
    for p in sorted((ROOT / 'analysis' / folder).glob('*.json')):
        node = json.loads(p.read_text())
        walk(node)
        json_files.append({'file': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()})

# HTTP excerpts retain exact source ranges, plus three metadata header lines.
http_manifest = json.loads((ROOT / 'analysis/http_contract/evidence_manifest.json').read_text())
http_range_lines = 0
for entry in http_manifest:
    contents = Path(entry['snippet']).read_bytes()
    assert hashlib.sha256(contents).hexdigest() == entry['snippet_sha256']
    _, lines = source(entry['source'])
    selected = lines[entry['source_start_line']-1:entry['source_end_line']]
    expected = f"Source: {entry['source']}\nLines: {entry['source_start_line']}-{entry['source_end_line']}\n\n" + '\n'.join(selected) + '\n'
    assert contents.decode() == expected, entry['snippet']
    http_range_lines += len(selected)
    hash_checks += 1

all_http = ROOT / 'analysis/http_endpoints_all.json'
node = json.loads(all_http.read_text())
assert node['counts']['fixed_endpoint_templates'] == 22
assert node['counts']['GET'] == 11 and node['counts']['POST'] == 11
json_files.append({'file': str(all_http.relative_to(ROOT)), 'sha256': hashlib.sha256(all_http.read_bytes()).hexdigest()})

# The login evidence retains exact lines and per-line hashes separately.
login = json.loads((ROOT / 'analysis/login_flow/dart_login_evidence.json').read_text())
for group in login.values():
    contents, lines = source(group['file'])
    assert hashlib.sha256(contents).hexdigest() == group['source_sha256']
    hash_checks += 1
    for excerpt in group['excerpts']:
        for item in excerpt['lines']:
            actual = lines[item['line'] - 1]
            assert actual == item['text']
            assert hashlib.sha256(actual.encode()).hexdigest() == item['sha256']
            line_checks += 1

mapping = json.loads((ROOT / 'analysis/message_semantics/msg_type_mapping.json').read_text())
libapp = ROOT / 'unpacked/lib/arm64-v8a/libapp.so'
contents = libapp.read_bytes()
assert hashlib.sha256(contents).hexdigest() == mapping['library']['sha256']
for entry in mapping['entries']:
    raw = entry['raw_elf_comparison']
    offset = int(raw['file_offset'], 16)
    actual = contents[offset:offset+4]
    assert actual.hex() == raw['bytes_hex']
    # CMP W0,#imm is the SUBS WZR,W0,#imm alias; immediates contain tagged Smi.
    expected = 0x7100001f | ((entry['msg_type'] * 2) << 10)
    assert int.from_bytes(actual, 'little') == expected
assert sorted(e['msg_type'] for e in mapping['entries']) == [101, 102, 113, 114, 115, 116, 117]
direct = json.loads((ROOT / 'analysis/aot_runtime/direct_call_verification.json').read_text())
assert direct['checked_direct_calls'] == 5642 and not direct['failed']

required = ['analysis/login_flow/native_login_flow.json',
            'analysis/http_contract/endpoint_contracts.json',
            'analysis/message_semantics/reconstructed_dispatch.dart',
            '登录与业务协议还原报告.txt']
missing = [p for p in required if not (ROOT / p).exists()]
result = {'original_apk_sha256': expected_apk, 'original_apk_unchanged': True,
          'new_json_files': len(json_files), 'evidence_lines_checked': line_checks,
          'source_hashes_checked': hash_checks, 'raw_msg_type_comparisons_checked': 7,
          'http_evidence_ranges_checked': len(http_manifest), 'http_source_lines_checked': http_range_lines,
          'raw_business_direct_calls_checked': direct['checked_direct_calls'],
          'missing_required_outputs': missing, 'artifacts': json_files,
          'target_app_executed': False, 'business_server_requests_performed': False,
          'limits': 'Evidence consistency and static instructions checked; no live server contract or complete source/build verified.'}
(ROOT / 'analysis/protocol_reconstruction_verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k:v for k,v in result.items() if k != 'artifacts'}, ensure_ascii=False, indent=2))
if missing:
    raise SystemExit('Required outputs missing')
