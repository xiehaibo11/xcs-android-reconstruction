#!/usr/bin/env python3
"""Verify exported static HTTP artifacts against the local immutable AOT dump."""

from _paths import app_root, workspace_root
from pathlib import Path
import hashlib
import json

ROOT = app_root()
OUT = ROOT / 'analysis/http_contract'
manifest = json.loads((OUT / 'evidence_manifest.json').read_text())
contracts = json.loads((OUT / 'endpoint_contracts.json').read_text())
schemas = json.loads((OUT / 'parameter_schemas.json').read_text())
coverage = json.loads((OUT / 'candidate_coverage.json').read_text())
checks = []
for entry in manifest:
    source = Path(entry['source'])
    snippet = Path(entry['snippet'])
    begin, end = entry['source_start_line'], entry['source_end_line']
    source_lines = source.read_text().splitlines()
    expected = '\n'.join(source_lines[begin - 1:end]) + '\n'
    actual = snippet.read_text().partition('\n\n')[2]
    assert actual == expected, entry['address']
    assert hashlib.sha256(snippet.read_bytes()).hexdigest() == entry['snippet_sha256'], entry['address']
    assert source_lines[begin - 1].strip() == entry['method_header'], entry['address']
    assert '// ** addr: ' + entry['address'] + ',' in expected, entry['address']
    checks.append(dict(address=entry['address'], source=str(source), begin=begin, end=end,
                       source_range_matches=True, snippet_sha256_matches=True))

assert len({entry['address'] for entry in manifest}) == 68
assert len(contracts['endpoints']) == 20
assert sum(e['http_method'] == 'GET' for e in contracts['endpoints']) == 11
assert sum(e['http_method'] == 'POST' for e in contracts['endpoints']) == 9
assert len(contracts['dynamic_url_helpers']) == 2
assert contracts['transport']['response_interceptor']['condition_operator'] == 'AND'
assert len(schemas['$defs']) == 8
assert coverage['unresolved'] == 0

result = dict(verification='passed', execution_scope='local file reads only; no APK/native-library execution or requests',
              verified_snippets=len(checks), endpoints=20, query_or_body_fields=39,
              dynamic_helpers=2, parameter_schema_defs=8,
              manifest_field_semantics=dict(source_start_line='inclusive, one-based method header',
                                            source_end_line='inclusive, one-based closing brace',
                                            snippet_sha256='hash of complete evidence file including Source/Lines metadata'),
              checks=checks,
              limitations=['Validates exported provenance/counts, not the truth of all manually reviewed semantic annotations.',
                           'Backend requirements/defaults/full response schemas and runtime behavior are not verified.'])
(OUT / 'verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('checks','manifest_field_semantics')}, ensure_ascii=False))
