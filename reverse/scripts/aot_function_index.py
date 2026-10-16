#!/usr/bin/env python3
"""Index Blutter business methods and verify direct calls against ELF bytes.

This reads snapshots and generated assembly; it never runs APK code or contacts
the app's servers. Numeric comments may contain tagged Smi values, so this script
does not infer business integers from those comments.
"""

from _paths import app_root, workspace_root
import hashlib
import json
import re
from pathlib import Path

ROOT = app_root()
DUMP = ROOT / 'analysis/aot_dump'
OUT = ROOT / 'analysis/aot_runtime'
OUT.mkdir(parents=True, exist_ok=True)
functions = []
for path in sorted((DUMP / 'asm/distinguish').rglob('*.dart')):
    lines = path.read_text().splitlines()
    current_class = '::'
    current_method = None
    for i, line in enumerate(lines):
        match = re.match(r'(?:abstract )?class (\S+)', line)
        if match:
            current_class = match[1]
        if line.startswith('  ') and not line.startswith('    ') and line.rstrip().endswith('{'):
            current_method = line.strip()
        match = re.search(r'\*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)', line)
        if match:
            functions.append({'path': str(path.relative_to(ROOT)), 'class': current_class,
                'signature': current_method, 'address': match[1], 'size': match[2],
                'line': i + 1, 'direct_calls': []})
        match = re.match(r'    //     (0x[0-9a-f]+): bl\s+#(0x[0-9a-f]+)\s*;\s*(.*)', line)
        if match and functions and functions[-1]['path'] == str(path.relative_to(ROOT)):
            functions[-1]['direct_calls'].append({'address': match[1], 'target': match[2],
                'label': match[3], 'line': i + 1})

index = {'scope': 'package:distinguish business assembly, not original Dart source',
         'file_count': len(list((DUMP / 'asm/distinguish').rglob('*.dart'))),
         'function_count': len(functions), 'functions': functions}
(OUT / 'function_index.json').write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n')

# Validate every annotated direct BL in the application's own libraries.
from elftools.elf.elffile import ELFFile
elf_path = ROOT / 'unpacked/lib/arm64-v8a/libapp.so'
with elf_path.open('rb') as stream:
    elf = ELFFile(stream)
    sections = [(s['sh_addr'], s['sh_offset'], s['sh_size']) for s in elf.iter_sections()
                if s['sh_type'] != 'SHT_NOBITS']
    contents = elf_path.read_bytes()
checks = []
for function in functions:
    for call in function['direct_calls']:
        address, target = int(call['address'], 16), int(call['target'], 16)
        section = next((s for s in sections if s[0] <= address and address + 4 <= s[0] + s[2]), None)
        if section is None:
            raise ValueError(f'No ELF section for {address:#x}')
        offset = section[1] + address - section[0]
        opcode = int.from_bytes(contents[offset:offset+4], 'little')
        imm = opcode & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        actual_target = address + (imm << 2)
        ok = (opcode & 0xfc000000) == 0x94000000 and actual_target == target
        checks.append({'address': call['address'], 'target': call['target'], 'file_offset': hex(offset),
                       'opcode': hex(opcode), 'ok': ok})
verification = {'libapp_sha256': hashlib.sha256(contents).hexdigest(),
                'checked_direct_calls': len(checks), 'failed': [c for c in checks if not c['ok']],
                'method': 'Decode AArch64 BL imm26 from original ELF and compare with Blutter target',
                'checks': checks}
(OUT / 'direct_call_verification.json').write_text(json.dumps(verification, indent=2) + '\n')
if verification['failed']:
    raise SystemExit('Direct-call verification failed')
print(json.dumps({'files': index['file_count'], 'functions': len(functions),
                  'verified_direct_calls': len(checks), 'failed': 0}))
