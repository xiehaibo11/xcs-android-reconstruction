#!/usr/bin/env python3
"""Recheck closure evidence against unchanged original ARM64 binaries.

Only analysis code executes. Hashes and disassembly do not validate a server.
"""

from _paths import app_root, workspace_root
import hashlib
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile

APP = app_root()
OUT = APP / 'analysis/reconnect_preview_failure'
LIBS = APP / 'unpacked/lib/arm64-v8a'
EXPECTED = {'libapp.so': '40d890193daa716defe2eec6cd2959bdbf7f7cf8345f8213b1747e54863a5a55',
            'librust_lib_distinguish.so': '0af3f1f12e57e9b5f2d409343421c1fa21b0bcffe7860a30cf972a1265399847'}
APK_SHA = '8fd060966759990ab5ef90639e3376a2b6aea209f3f545d768a2fdc668dfeaa9'
COUNTS = dict(file_hashes=0, exact_source_lines=0, source_ranges=0,
              source_range_lines=0, raw_instruction_records=0,
              direct_bl_targets=0, direct_b_targets=0,
              llvm_instruction_words=0, relocation_bindings=0,
              raw_data_bytes=0, complete_body_copies=0,
              native_executable_words_scanned=0, native_rela_entries_scanned=0)
FILE_CACHE, ELF_CACHE, HASHED, RAW_SEEN, SOURCE_SEEN = {}, {}, set(), set(), set()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def path_of(value, base=APP):
    path = Path(value)
    if path.is_absolute():
        assert path.is_file(), path
        return path
    for candidate in [APP / path, base / path, LIBS / path, APP.parent / path]:
        if candidate.is_file():
            return candidate
    raise AssertionError(f'Missing evidence: {value}')


def read(value, base=APP):
    path = path_of(value, base)
    if path not in FILE_CACHE:
        raw = path.read_bytes()
        FILE_CACHE[path] = (raw, raw.decode('utf-8', errors='replace').splitlines())
    return FILE_CACHE[path]


def hash_check(value, expected, base):
    path = path_of(value, base)
    assert sha(read(path)[0]) == expected, path
    COUNTS['file_hashes'] += 1
    HASHED.add(str(path))


def as_int(value):
    return int(value, 16) if isinstance(value, str) else value


def elf_read(library, address, length=4):
    library = path_of(library)
    if library not in ELF_CACHE:
        with library.open('rb') as stream:
            elf = ELFFile(stream)
            sections = [(s['sh_addr'], s['sh_offset'], s['sh_size'])
                        for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']
            relas = {r['r_offset']: (r['r_info_type'], r['r_addend'])
                     for s in elf.iter_sections() if hasattr(s, 'iter_relocations')
                     for r in s.iter_relocations() if r.is_RELA()}
        ELF_CACHE[library] = (library.read_bytes(), sections, relas)
    raw, sections, _ = ELF_CACHE[library]
    start, offset, size = next(s for s in sections
                             if s[0] <= address and address + length <= s[0] + s[2])
    offset += address - start
    return raw[offset:offset + length], offset


def branch_check(actual, address, target):
    word = int.from_bytes(actual, 'little')
    opcode = word & 0xfc000000
    assert opcode in (0x94000000, 0x14000000), (hex(address), hex(word), hex(target))
    imm = word & 0x3ffffff
    if imm & 0x2000000:
        imm -= 0x4000000
    assert address + 4 * imm == target, (hex(address), hex(target))
    COUNTS['direct_bl_targets' if opcode == 0x94000000 else 'direct_b_targets'] += 1


def source_range(path, start, end, expected, base):
    lines = read(path, base)[1]
    assert 1 <= start <= end <= len(lines), (path, start, end, len(lines))
    selected = lines[start - 1:end]
    joined = '\n'.join(selected)
    assert expected in (joined, joined + '\n'), (path, start, end)
    COUNTS['source_ranges'] += 1
    COUNTS['source_range_lines'] += len(selected)
    SOURCE_SEEN.update((str(path_of(path, base)), i) for i in range(start, end + 1))


def llvm_check(path, library, start=None, end=None, base=APP):
    raw, _ = read(path, base)
    seen = set()
    for match in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+([^\n]+)', raw.decode(), re.M):
        address, expected = (int(v, 16) for v in match.groups()[:2])
        if start is not None:
            assert start <= address < end
        actual, _ = elf_read(library, address)
        assert int.from_bytes(actual, 'little') == expected, (path, hex(address))
        branch = re.match(r'\s*(b|bl)\s+#?(0x[0-9a-f]+)\b', match.group(3))
        if branch:
            assert (expected & 0xfc000000) == (0x94000000 if branch.group(1) == 'bl' else 0x14000000)
            branch_check(actual, address, int(branch.group(2), 16))
        seen.add(address)
        RAW_SEEN.add((str(path_of(library)), address))
        COUNTS['llvm_instruction_words'] += 1
    if start is not None:
        assert len(seen) == (end - start) // 4, path
    return len(seen)


def walk(node, base, library):
    if isinstance(node, list):
        for item in node:
            walk(item, base, library)
        return
    if not isinstance(node, dict):
        return
    for key in ['binary', 'library', 'elf_file']:
        if isinstance(node.get(key), str) and node[key].endswith('.so'):
            library = path_of(node[key], base)
    for key in ['file', 'path']:
        if isinstance(node.get(key), str) and isinstance(node.get('sha256'), str):
            hash_check(node[key], node['sha256'], base)
    if isinstance(node.get('source'), str) and isinstance(node.get('source_sha256'), str):
        hash_check(node['source'], node['source_sha256'], base)
    if {'elf_file', 'elf_sha256'} <= node.keys():
        hash_check(node['elf_file'], node['elf_sha256'], base)
    if {'library', 'library_sha256'} <= node.keys():
        hash_check(node['library'], node['library_sha256'], base)
    if {'file', 'copied_complete_ghidra_body', 'copied_sha256'} <= node.keys():
        hash_check(node['copied_complete_ghidra_body'], node['copied_sha256'], base)
        assert read(node['file'], base)[0] == read(node['copied_complete_ghidra_body'], base)[0]
        if 'line_count' in node:
            assert len(read(node['file'], base)[1]) == node['line_count']
        COUNTS['complete_body_copies'] += 1
    if {'file', 'start_line', 'end_line', 'excerpt'} <= node.keys():
        source_range(node['file'], node['start_line'], node['end_line'], node['excerpt'], base)
    if {'source', 'start_line', 'end_line', 'snippet', 'snippet_sha256'} <= node.keys():
        hash_check(node['snippet'], node['snippet_sha256'], base)
        source_range(node['source'], node['start_line'], node['end_line'],
                     read(node['snippet'], base)[0].decode(), base)
        if {'address', 'size'} <= node.keys():
            snippet = read(node['snippet'], base)[0].decode()
            header = re.search(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)', snippet)
            assert header, node
            address, size = map(as_int, header.groups())
            assert address == as_int(node['address']) and size == as_int(node['size'])
            addresses = {as_int(v) for v in re.findall(r'//\s+(0x[0-9a-f]+):', snippet)}
            assert addresses == set(range(address, address + size, 4)), node
            if 'method_declaration' in node:
                assert snippet.splitlines()[0].strip() == node['method_declaration'].strip()
    if {'source', 'source_start_line', 'complete_excerpt', 'complete_excerpt_sha256'} <= node.keys():
        hash_check(node['complete_excerpt'], node['complete_excerpt_sha256'], base)
        snippet = read(node['complete_excerpt'], base)[0].decode()
        # This agent's excerpt begins with the declaration preceding the header.
        start = node['source_start_line'] - 1
        source_range(node['source'], start, start + len(snippet.splitlines()) - 1, snippet, base)
    for key, text_key in [('file', 'excerpt'), ('source', 'text')]:
        if isinstance(node.get(key), str) and isinstance(node.get('line'), int) and isinstance(node.get(text_key), str):
            path, line, excerpt = node[key], node['line'], node[text_key]
            assert read(path, base)[1][line - 1].strip() == excerpt.strip(), node
            COUNTS['exact_source_lines'] += 1
            SOURCE_SEEN.add((str(path_of(path, base)), line))
    formats = [('elf_va', 'bytes_le', 'word_hex', 'target_elf'),
               ('elf_virtual_address', 'raw_bytes_hex', 'instruction_word_hex', 'bl_target'),
               ('elf_virtual_address', 'bytes_hex', 'opcode', 'target')]
    for addr_key, bytes_key, word_key, target_key in formats:
        if addr_key not in node or bytes_key not in node:
            continue
        address = as_int(node[addr_key])
        byte_length = len(bytes.fromhex(node[bytes_key]))
        actual, offset = elf_read(library, address, byte_length)
        if 'size' in node:
            assert as_int(node['size']) == byte_length
        assert actual.hex() == node[bytes_key], node
        if 'file_offset' in node:
            assert offset == as_int(node['file_offset'])
        if word_key in node:
            assert int.from_bytes(actual, 'little') == as_int(node[word_key])
        if node.get(target_key) is not None:
            assert byte_length == 4
            branch_check(actual, address, as_int(node[target_key]))
        if byte_length != 4:
            COUNTS['raw_data_bytes'] += byte_length
            if 'qword_hex' in node:
                assert [f'{int.from_bytes(actual[i:i + 8], "little"):016x}'
                        for i in range(0, byte_length, 8)] == node['qword_hex']
        COUNTS['raw_instruction_records'] += 1
        RAW_SEEN.add((str(library), address))
    if {'relocation_offset_elf', 'addend_target_elf'} <= node.keys():
        elf_read(library, 0) if path_of(library) not in ELF_CACHE else None
        record = ELF_CACHE[path_of(library)][2][as_int(node['relocation_offset_elf'])]
        assert record == (1027, as_int(node['addend_target_elf'])), node
        if 'thunk_branch_target_elf' in node:
            address = as_int(node['addend_target_elf'])
            actual, _ = elf_read(library, address)
            branch_check(actual, address, as_int(node['thunk_branch_target_elf']))
        COUNTS['relocation_bindings'] += 1
    if {'binary', 'elf_start', 'elf_end_exclusive', 'raw_bytes_sha256', 'file'} <= node.keys():
        start, end = as_int(node['elf_start']), as_int(node['elf_end_exclusive'])
        actual, _ = elf_read(library, start, end - start)
        assert sha(actual) == node['raw_bytes_sha256']
        llvm_check(node['file'], library, start, end, base)
    if {'binary', 'elf_start', 'elf_end_exclusive', 'raw_bytes_sha256', 'llvm_file'} <= node.keys():
        start, end = as_int(node['elf_start']), as_int(node['elf_end_exclusive'])
        actual, offset = elf_read(library, start, end - start)
        assert sha(actual) == node['raw_bytes_sha256']
        assert actual.hex() == node['bytes_le']
        assert offset == as_int(node['file_offset'])
        hash_check(node['llvm_file'], node['llvm_sha256'], base)
        llvm_check(node['llvm_file'], library, start, end, base)
    if {'binary', 'elf_start', 'elf_end_exclusive', 'raw_sha256', 'llvm_file'} <= node.keys():
        start, end = as_int(node['elf_start']), as_int(node['elf_end_exclusive'])
        actual, offset = elf_read(library, start, end - start)
        assert sha(actual) == node['raw_sha256']
        assert actual.hex() == node['bytes_le']
        assert offset == as_int(node['file_offset'])
        hash_check(node['llvm_file'], node['llvm_sha256'], base)
        llvm_check(node['llvm_file'], library, start, end, base)
    if {'start', 'end_exclusive', 'word_count', 'file'} <= node.keys():
        count = llvm_check(node['file'], library, as_int(node['start']), as_int(node['end_exclusive']), base)
        assert count == node['word_count']
    for value in node.values():
        walk(value, base, library)


assert sha((APP.parent / 'app_xcs(新).apk.1.1').read_bytes()) == APK_SHA
for name, expected in EXPECTED.items():
    assert sha((LIBS / name).read_bytes()) == expected
artifacts = []
for folder in ['reconnect', 'authentication', 'preview', 'dart_http']:
    directory = OUT / folder
    assert directory.is_dir(), directory
    library = LIBS / ('libapp.so' if folder in ['preview', 'dart_http']
                      else 'librust_lib_distinguish.so')
    files = sorted(directory.rglob('*.json'))
    assert files, directory
    for path in files:
        node = json.loads(path.read_text())
        walk(node, path.parent, library)
        artifacts.append({'file': str(path.relative_to(APP)), 'sha256': sha(path.read_bytes())})
    for path in sorted(directory.rglob('*')):
        if path.is_file() and path.suffix in ['.asm', '.txt']:
            contents = read(path)[0].decode('utf-8', errors='replace')
            match = re.search(r'^(.+\.so):\s*file format', contents, re.M)
            if match:
                llvm_check(path, path_of(match[1], APP.parent))
reconnect = json.loads((OUT / 'reconnect/reconnect_flow.json').read_text())
reconnect_summary = json.loads((OUT / 'reconnect/verification.json').read_text())
assert reconnect_summary['passed']
assert sha((OUT / 'reconnect/reconnect_flow.json').read_bytes()) == reconnect_summary['reconnect_json_sha256']
for summary_key, key in [('source_excerpt_count', 'source_evidence'),
                         ('raw_instruction_check_count', 'raw_instruction_checks'),
                         ('relocation_binding_count', 'relocation_bindings'),
                         ('raw_data_check_count', 'raw_data_checks'),
                         ('llvm_snapshot_count', 'raw_llvm_snapshots'),
                         ('artifact_manifest_count', 'artifact_manifest')]:
    assert reconnect_summary[summary_key] == len(reconnect[key])
for binding in reconnect['direct_call_map']:
    for site in binding['branch_sites']:
        address = as_int(site)
        actual, _ = elf_read(LIBS / 'librust_lib_distinguish.so', address)
        branch_check(actual, address, as_int(binding['target_elf']))
scan = reconnect['finite_scan']
expected_inventory = scan['direct_B_BL_target_inventory']
actual_inventory = {target: [] for target in expected_inventory}
target_keys = {as_int(target): target for target in expected_inventory}
coverage = []
with (LIBS / 'librust_lib_distinguish.so').open('rb') as stream:
    elf = ELFFile(stream)
    for segment in elf.iter_segments():
        if segment['p_type'] != 'PT_LOAD' or not segment['p_flags'] & 1:
            continue
        start = segment['p_vaddr']
        data = segment.data()
        words = 0
        for offset in range(0, len(data) - 3, 4):
            address = start + offset
            word = int.from_bytes(data[offset:offset + 4], 'little')
            words += 1
            opcode = word & 0xfc000000
            if opcode not in (0x94000000, 0x14000000):
                continue
            imm = word & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            target = address + 4 * imm
            if target in target_keys:
                actual_inventory[target_keys[target]].append({
                    'elf_va': hex(address), 'kind': 'BL' if opcode == 0x94000000 else 'B',
                    'word_hex': f'{word:08x}'})
        coverage.append({'segment_elf_start': hex(start),
                         'segment_elf_end_exclusive': hex(start + len(data)),
                         'file_backed_bytes': len(data), 'aligned_words_inspected': words, 'pf_x': True})
        COUNTS['native_executable_words_scanned'] += words
assert coverage == scan['coverage']
assert actual_inventory == expected_inventory
relas = ELF_CACHE[path_of(LIBS / 'librust_lib_distinguish.so')][2]
assert len(relas) == scan['rela_entries_inspected']
COUNTS['native_rela_entries_scanned'] += len(relas)
auth = json.loads((OUT / 'authentication/authentication_failure.json').read_text())
auth_summary = auth['verification']
auth_actual = {
    'complete_body_count': len(auth['complete_body_inventory']),
    'fact_count': len(auth['facts']),
    'state_transition_count': len(auth['state_transitions']),
    'source_reference_count': sum(len(group) for group in auth['evidence_index'].values()),
    'raw_range_count': len({r['file'] for r in auth['native_raw_checks']}),
    'machine_word_count': len(auth['native_raw_checks']),
    'bl_target_count': sum('bl_target' in r for r in auth['native_raw_checks']),
    'critical_direct_call_count': len(auth['critical_direct_calls']),
    'close_control_data_bytes': len(bytes.fromhex(auth['close_control_data']['raw_bytes_hex']))}
for key, value in auth_actual.items():
    assert auth_summary[key] == value, (key, value, auth_summary[key])
for fact in auth['facts']:
    assert all(group in auth['evidence_index'] for group in fact['evidence']), fact
preview = json.loads((OUT / 'preview/preview_failure.json').read_text())
preview_manifest = json.loads((OUT / 'preview/evidence_manifest.json').read_text())
preview_summary = json.loads((OUT / 'preview/verification.json').read_text())
preview_actual = {
    'full_method_excerpts': len(preview_manifest['methods']),
    'claims': len(preview['claims']),
    'conditional_scenarios': len(preview['conditional_interleavings']),
    'error_paths': len(preview['error_paths']),
    'preview_parameters': len(preview['preview_parameter_state_writes']),
    'raw_direct_bl_checks': len(preview_manifest['raw_direct_bl_checks']),
    'raw_ranges': len(preview_manifest['raw_ranges']),
    'llvm_instruction_words': sum(len(r['instructions']) for r in preview_manifest['raw_ranges']),
    'source_support_ranges': len(preview_manifest['support_sources']),
    'business_files_scanned': len(preview_manifest['business_call_index']['source_inventory']),
    'direct_preview_calls': len(preview_manifest['business_call_index']['direct_calls']),
    'preview_exported_methods': len(preview_manifest['preview_export_inventory']['methods'])}
for key, value in preview_actual.items():
    assert preview_summary[key] == value, (key, value, preview_summary[key])
for key, actual_key in [('claims', 'claims'), ('conditional_scenarios', 'conditional_scenarios'),
                        ('error_paths', 'error_paths'), ('preview_parameters', 'preview_parameters'),
                        ('full_methods', 'full_method_excerpts'), ('direct_preview_calls', 'direct_preview_calls')]:
    assert preview['counts'][key] == preview_actual[actual_key]
http = json.loads((OUT / 'dart_http/dart_http_failure.json').read_text())
http_summary = json.loads((OUT / 'dart_http/verification.json').read_text())
assert http_summary['full_method_excerpts'] == len(http['methods']) == 29
assert len(http['dart_jwt_exact_field_scan']['inventory']) == 53
assert len(http['dart_jwt_exact_field_scan']['writes']) == 2
methods = {m['id']: read(m['snippet'])[0].decode() for m in http['methods']}
assert 'str             x0, [x1, #0x1748]' in methods['response_error_body']
assert '0x67f97c: b               #0x67f98c' in methods['response_error_body']
assert '0x67f988: bl              #0x67f76c' in methods['response_error_body']
assert 'Type: Exception' in methods['post'] and 'Type: Exception' in methods['get']
assert 'completeError' in methods['error_handler_next']
assert 'LoadField: r0 = r2->field_b' in methods['handler_future_return']
report = APP / '断线重连与预览失败恢复还原报告.txt'
assert report.is_file()
result = {'status': 'PASS', 'all_checks_passed': True,
          'original_apk_unchanged': True, 'original_apk_sha256': APK_SHA,
          'original_library_sha256': EXPECTED,
          'json_artifacts_checked': len(artifacts), 'evidence_checks': COUNTS,
          'unique_hashed_files': len(HASHED), 'unique_exact_source_lines': len(SOURCE_SEEN),
          'unique_original_instruction_addresses': len(RAW_SEEN), 'artifacts': artifacts,
          'report': {'file': str(report), 'sha256': sha(report.read_bytes())},
          'verification_script': {'file': str(Path(__file__).resolve()),
                                  'sha256': sha(Path(__file__).read_bytes())},
          'target_code_executed': False, 'business_server_contacted': False,
          'limits': 'Static evidence and instruction consistency; conditional asynchronous scenarios are not runtime traces or server guarantees.'}
(APP / 'analysis/reconnect_preview_failure_verification.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k != 'artifacts'}, ensure_ascii=False, indent=2))
