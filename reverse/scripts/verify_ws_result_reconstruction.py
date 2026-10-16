#!/usr/bin/env python3
"""Verify static evidence files, source excerpts and original ARM64 instructions.

This validates the provenance of the reconstruction, not live server behavior.
No application/native library execution or network access is performed.
"""

from _paths import app_root, workspace_root
import hashlib
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile

APP = app_root()
FOLDERS = ['ws_protocol', 'ws_heartbeat', 'result_pipeline', 'ws_result_integration']
EXPECTED_APK = '8fd060966759990ab5ef90639e3376a2b6aea209f3f545d768a2fdc668dfeaa9'
EXPECTED_LIBRARIES = {
    'libapp.so': '40d890193daa716defe2eec6cd2959bdbf7f7cf8345f8213b1747e54863a5a55',
    'librust_lib_distinguish.so': '0af3f1f12e57e9b5f2d409343421c1fa21b0bcffe7860a30cf972a1265399847',
}
apk = APP.parent / 'app_xcs(新).apk.1.1'
assert hashlib.sha256(apk.read_bytes()).hexdigest() == EXPECTED_APK
for name, expected in EXPECTED_LIBRARIES.items():
    assert hashlib.sha256((APP / 'unpacked/lib/arm64-v8a' / name).read_bytes()).hexdigest() == expected
cache, elf_cache, artifacts = {}, {}, []
relocation_cache = {}
hashed_files, source_locations, raw_locations = set(), set(), set()
checks = {'file_hashes': 0, 'source_lines': 0, 'source_ranges': 0,
          'source_range_lines': 0, 'raw_instruction_records': 0,
          'direct_bl_targets': 0, 'llvm_instruction_words': 0,
          'synthetic_wire_roundtrips': 0, 'synthetic_nested_json': 0,
          'native_relocation_bindings': 0, 'native_direct_b_targets': 0,
          'native_log_literal_parts': 0}


def resolve(path, base=None):
    path = Path(path)
    if not path.is_absolute():
        candidate = APP / path
        path = candidate if candidate.is_file() or base is None else base / path
    assert path.is_file(), f'Missing evidence: {path}'
    return path


def read(path, base=None):
    path = resolve(path, base)
    if path not in cache:
        data = path.read_bytes()
        cache[path] = (data, data.decode('utf-8', errors='replace').splitlines())
    return cache[path]


def elf_read(path, address, length=4):
    path = Path(path)
    if path not in elf_cache:
        with path.open('rb') as stream:
            elf = ELFFile(stream)
            sections = [(s['sh_addr'], s['sh_offset'], s['sh_size'])
                        for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']
        elf_cache[path] = (path.read_bytes(), sections)
    data, sections = elf_cache[path]
    section = next(s for s in sections if s[0] <= address and address + length <= s[0] + s[2])
    offset = section[1] + address - section[0]
    return data[offset:offset + length], offset


def branch_check(library, address, expected_hex, target, link):
    actual, _ = elf_read(library, address)
    assert actual.hex() == expected_hex
    opcode = int.from_bytes(actual, 'little')
    assert opcode & 0xfc000000 == (0x94000000 if link else 0x14000000)
    imm = opcode & 0x3ffffff
    if imm & 0x2000000:
        imm -= 0x4000000
    assert address + (imm << 2) == target
    checks['raw_instruction_records'] += 1
    checks['direct_bl_targets' if link else 'native_direct_b_targets'] += 1
    raw_locations.add((str(library), address))


def heartbeat_checks(node, base):
    library = Path(node['library'])
    assert hashlib.sha256(library.read_bytes()).hexdigest() == node['library_sha256']
    for evidence in node['instruction_evidence']:
        contents = read(evidence['file'], base)[0].decode()
        for instruction in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+', contents, re.M):
            address = int(instruction.group(1), 16)
            actual, _ = elf_read(library, address)
            assert int.from_bytes(actual, 'little') == int(instruction.group(2), 16)
            checks['llvm_instruction_words'] += 1
            raw_locations.add((str(library), address))
    for instruction in node['critical_instruction_byte_checks']:
        address = int(instruction['elf_va'], 16)
        actual, _ = elf_read(library, address)
        assert actual.hex() == instruction['hex']
        checks['raw_instruction_records'] += 1
        raw_locations.add((str(library), address))
    if library not in relocation_cache:
        with library.open('rb') as stream:
            elf = ELFFile(stream)
            relocation_cache[library] = {
                r['r_offset']: r['r_addend'] for section in elf.iter_sections()
                if hasattr(section, 'iter_relocations')
                for r in section.iter_relocations() if r.is_RELA()}
    for binding in node['async_bindings']:
        wrapper = int(binding['wrapper_elf_va'], 16)
        for branch in binding['branches']:
            vt, thunk = int(branch['vtable_elf_va'], 16), int(branch['relocation_addend'], 16)
            assert relocation_cache[library][vt] == thunk
            checks['native_relocation_bindings'] += 1
            branch_check(library, thunk, branch['thunk_instruction_hex'],
                         int(branch['worker_elf_va'], 16), False)
            branch_check(library, int(branch['worker_call_elf_va'], 16),
                         branch['worker_call_hex'], wrapper, True)
        branch_check(library, int(binding['poll_call_elf_va'], 16),
                     binding['poll_call_hex'], int(binding['poll_ghidra'], 16) - 0x100000, True)
    for literal in node['selected_log_literals']:
        for part in literal['parts']:
            actual, _ = elf_read(library, int(part['pointer_elf_va'], 16), part['length'])
            assert actual.decode('utf8') == part['text']
            checks['native_log_literal_parts'] += 1


def walk(node, base):
    if isinstance(node, list):
        for value in node:
            walk(value, base)
        return
    if not isinstance(node, dict):
        return
    if isinstance(node.get('file'), str):
        if isinstance(node.get('sha256'), str):
            data, _ = read(node['file'], base)
            assert hashlib.sha256(data).hexdigest() == node['sha256'], node['file']
            checks['file_hashes'] += 1
            hashed_files.add(str(resolve(node['file'], base)))
        if isinstance(node.get('line'), int) and isinstance(node.get('excerpt'), str):
            _, lines = read(node['file'], base)
            if 'excerpt_start' in node or '\n' in node['excerpt']:
                excerpt = node['excerpt'].split('\n')
                if 'excerpt_start' in node:
                    start = node['excerpt_start'] - 1
                    assert lines[start:node['excerpt_end']] == excerpt, node
                else:
                    possible = range(max(0, node['line'] - len(excerpt)), node['line'])
                    start = next((i for i in possible if lines[i:i + len(excerpt)] == excerpt), None)
                    assert start is not None, node
                checks['source_ranges'] += 1
                checks['source_range_lines'] += len(excerpt)
                source_locations.update((node['file'], i + 1) for i in range(start, start + len(excerpt)))
            else:
                assert lines[node['line'] - 1].strip() == node['excerpt'].strip(), node
                checks['source_lines'] += 1
                source_locations.add((node['file'], node['line']))
        if {'source_start_line', 'source_end_line', 'snippet', 'snippet_sha256'} <= node.keys():
            _, lines = read(node['file'], base)
            selected = lines[node['source_start_line'] - 1:node['source_end_line']]
            snippet, _ = read(node['snippet'], base)
            assert hashlib.sha256(snippet).hexdigest() == node['snippet_sha256']
            assert snippet.decode() == '\n'.join(selected) + '\n', node['snippet']
            checks['source_ranges'] += 1
            checks['source_range_lines'] += len(selected)
    # The result pipeline manifest uses source/start_line/end_line and snippets
    # relative to its artifact directory rather than APP.
    if {'source', 'source_sha256', 'start_line', 'end_line', 'snippet', 'snippet_sha256'} <= node.keys():
        data, lines = read(node['source'], base)
        assert hashlib.sha256(data).hexdigest() == node['source_sha256'], node['source']
        selected = lines[node['start_line'] - 1:node['end_line']]
        snippet, _ = read(node['snippet'], base)
        assert hashlib.sha256(snippet).hexdigest() == node['snippet_sha256'], node['snippet']
        assert snippet.decode() == '\n'.join(selected) + '\n', node['snippet']
        checks['file_hashes'] += 1
        hashed_files.add(str(resolve(node['source'], base)))
        checks['source_ranges'] += 1
        checks['source_range_lines'] += len(selected)
    if {'extraction_script', 'script_sha256'} <= node.keys():
        script, _ = read(node['extraction_script'], base)
        assert hashlib.sha256(script).hexdigest() == node['script_sha256']
        checks['file_hashes'] += 1
        hashed_files.add(str(resolve(node['extraction_script'], base)))
    if isinstance(node.get('source'), str) and isinstance(node.get('source_sha256'), str):
        data, lines = read(node['source'], base)
        assert hashlib.sha256(data).hexdigest() == node['source_sha256'], node['source']
        checks['file_hashes'] += 1
        hashed_files.add(str(resolve(node['source'], base)))
        if isinstance(node.get('line'), int) and isinstance(node.get('text'), str):
            assert lines[node['line'] - 1].strip() == node['text'].strip(), node
            checks['source_lines'] += 1
            source_locations.add((node['source'], node['line']))
    if isinstance(node.get('source'), str) and isinstance(node.get('line'), int) and isinstance(node.get('context'), str):
        _, lines = read(node['source'], base)
        context = node['context'].splitlines()
        assert lines[node['line'] - 1:node['line'] - 1 + len(context)] == context, node
        checks['source_ranges'] += 1
        checks['source_range_lines'] += len(context)
    if {'library', 'elf_virtual_address', 'bytes_hex', 'file_offset'} <= node.keys():
        library = Path(node['library'])
        address = int(node['elf_virtual_address'], 16)
        actual, offset = elf_read(library, address)
        assert offset == int(node['file_offset'], 16)
        assert actual.hex() == node['bytes_hex'], node
        if 'opcode' in node:
            assert int.from_bytes(actual, 'little') == int(node['opcode'], 16)
        checks['raw_instruction_records'] += 1
        raw_locations.add((str(library), address))
        if 'target' in node:
            opcode = int.from_bytes(actual, 'little')
            assert opcode & 0xfc000000 == 0x94000000
            imm = opcode & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            assert address + (imm << 2) == int(node['target'], 16)
            checks['direct_bl_targets'] += 1
    for value in node.values():
        walk(value, base)


for folder in FOLDERS:
    directory = APP / 'analysis' / folder
    assert directory.is_dir(), f'Missing extraction directory: {directory}'
    for path in sorted(directory.rglob('*.json')):
        node = json.loads(path.read_text())
        walk(node, path.parent)
        if 'critical_instruction_byte_checks' in node and 'async_bindings' in node:
            heartbeat_checks(node, path.parent)
        artifacts.append({'file': str(path.relative_to(APP)),
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    # LLVM output contains original bytes, allowing independent opcode checks.
    for path in sorted(set(directory.rglob('*.llvm.txt')) | set(directory.rglob('*.asm.txt'))):
        contents = path.read_text()
        match = re.search(r'^(.+\.so):\s*file format', contents, re.M)
        if not match:
            continue
        library = Path(match.group(1))
        if not library.is_absolute():
            library = APP.parent / library
        for instruction in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+', contents, re.M):
            actual, _ = elf_read(library, int(instruction.group(1), 16))
            assert int.from_bytes(actual, 'little') == int(instruction.group(2), 16), str(path)
            checks['llvm_instruction_words'] += 1
            raw_locations.add((str(library), int(instruction.group(1), 16)))

examples = json.loads((APP / 'analysis/ws_protocol/synthetic_examples.json').read_text())
for example in examples['examples']:
    assert example['synthetic'] is True
    message = example['message']
    assert json.loads(example['wire_json_text']) == message
    if 'types' in message:
        assert type(message['types']) is int and -2147483648 <= message['types'] <= 2147483647
    if 'qos' in message:
        assert type(message['qos']) is bool
    for field in ('data_content', 'from', 'to', 'fp'):
        if field in message:
            assert isinstance(message[field], str)
    checks['synthetic_wire_roundtrips'] += 1
    if 'decoded_data_content' in example:
        assert json.loads(message['data_content']) == example['decoded_data_content']
        checks['synthetic_nested_json'] += 1

required = ['WebSocket与识别上传流程还原报告.txt',
            'analysis/ws_result_integration/cross_layer_flow.json']
missing = [name for name in required if not (APP / name).is_file()]
result = {'original_apk_unchanged': True, 'original_apk_sha256': EXPECTED_APK,
          'original_library_hashes_valid': True, 'original_library_sha256': EXPECTED_LIBRARIES,
          'extraction_directories': FOLDERS, 'json_artifacts_checked': len(artifacts),
          'evidence_checks': checks, 'missing_required_outputs': missing,
          'unique_hashed_evidence_files': len(hashed_files),
          'unique_exact_source_lines': len(source_locations),
          'unique_original_instruction_addresses': len(raw_locations),
          'artifacts': artifacts, 'target_code_executed': False,
          'business_server_contacted': False,
          'limits': 'Evidence consistency and static instruction targets only; no captured traffic or server-side semantics verified.'}
(APP / 'analysis/ws_result_reconstruction_verification.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k != 'artifacts'}, ensure_ascii=False, indent=2))
if missing:
    raise SystemExit('Required outputs missing')
