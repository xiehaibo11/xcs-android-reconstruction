#!/usr/bin/env python3
"""Verify static evidence files, source excerpts and original ARM64 instructions.

This validates the provenance of the reconstruction, not live server behavior.
Target code is never executed. Synthetic cases exercise only our own codec.
Core provenance checks are shared in design with the prior WS/result verifier.
"""

from _paths import app_root, workspace_root
import hashlib
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile

APP = app_root()
FOLDERS = ['local_state', 'image_codec', 'device_lifecycle', 'ws_event_contract']
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
          'synthetic_rule_cases': 0, 'synthetic_base64_cases': 0,
          'synthetic_url_cases': 0, 'synthetic_png_roundtrips': 0,
          'synthetic_frb_roundtrips': 0, 'native_executable_words_scanned': 0,
          'native_rela_entries_scanned': 0, 'device_methods_direct_bl_targets': 0,
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
            source_locations.update((node['file'], i + 1) for i in range(node['source_start_line'] - 1, node['source_end_line']))
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
        source_locations.update((node['source'], i + 1)
                                for i in range(node['start_line'] - 1, node['end_line']))
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


def runtime_walk(node, base, library=None):
    """Additional image/native evidence formats, preserving library context."""
    if isinstance(node, list):
        for item in node:
            runtime_walk(item, base, library)
        return
    if not isinstance(node, dict):
        return
    if isinstance(node.get('binary'), str) and node['binary'].endswith('.so'):
        library = APP / 'unpacked/lib/arm64-v8a' / node['binary']
    if isinstance(node.get('path'), str) and isinstance(node.get('sha256'), str):
        path = resolve(node['path'], base)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == node['sha256'], path
        checks['file_hashes'] += 1
        hashed_files.add(str(path))
    if isinstance(node.get('library'), str) and node['library'].endswith('.so'):
        library = resolve(node['library'], base)
        expected = node.get('library_sha256', node.get('sha256'))
        if expected:
            assert hashlib.sha256(library.read_bytes()).hexdigest() == expected
            checks['file_hashes'] += 1
            hashed_files.add(str(library))
    for key in ('inputs', 'artifacts'):
        if isinstance(node.get(key), dict):
            for name, expected in node[key].items():
                if isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected):
                    path = resolve(name, base)
                    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name
                    checks['file_hashes'] += 1
                    hashed_files.add(str(path))
    if {'file', 'start_line', 'end_line', 'excerpt'} <= node.keys():
        _, lines = read(node['file'], base)
        selected = lines[node['start_line'] - 1:node['end_line']]
        assert '\n'.join(selected) == node['excerpt'], node
        checks['source_ranges'] += 1
        checks['source_range_lines'] += len(selected)
        source_locations.update((node['file'], i + 1)
                                for i in range(node['start_line'] - 1, node['end_line']))
    if {'elf_va', 'bytes_le'} <= node.keys():
        assert library is not None
        address = int(node['elf_va'], 16)
        actual, _ = elf_read(library, address)
        assert actual.hex() == node['bytes_le'], node
        if 'word_hex' in node:
            assert int.from_bytes(actual, 'little') == int(node['word_hex'], 16)
        checks['raw_instruction_records'] += 1
        raw_locations.add((str(library), address))
        if 'target_elf' in node:
            opcode = int.from_bytes(actual, 'little')
            assert opcode & 0xfc000000 == 0x94000000
            imm = opcode & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            assert address + (imm << 2) == int(node['target_elf'], 16)
            checks['direct_bl_targets'] += 1
    if {'binary', 'elf_start', 'elf_end_exclusive', 'raw_bytes_sha256', 'file'} <= node.keys():
        start, end = int(node['elf_start'], 16), int(node['elf_end_exclusive'], 16)
        actual, _ = elf_read(library, start, end - start)
        assert hashlib.sha256(actual).hexdigest() == node['raw_bytes_sha256']
        contents = read(node['file'], base)[0].decode()
        seen = set()
        for instruction in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+', contents, re.M):
            address = int(instruction.group(1), 16)
            assert start <= address < end
            word, _ = elf_read(library, address)
            assert int.from_bytes(word, 'little') == int(instruction.group(2), 16)
            seen.add(address)
            checks['llvm_instruction_words'] += 1
            raw_locations.add((str(library), address))
        assert len(seen) == (end - start) // 4
    if {'elf_virtual_address', 'raw_bytes_hex', 'file_offset'} <= node.keys():
        assert library is not None
        address = int(node['elf_virtual_address'], 16)
        actual, offset = elf_read(library, address)
        assert offset == int(node['file_offset'], 16)
        assert actual.hex() == node['raw_bytes_hex'], node
        if 'instruction_word_hex' in node:
            assert int.from_bytes(actual, 'little') == int(node['instruction_word_hex'], 16)
        checks['raw_instruction_records'] += 1
        raw_locations.add((str(library), address))
        if 'bl_target' in node:
            opcode = int.from_bytes(actual, 'little')
            assert opcode & 0xfc000000 == 0x94000000
            imm = opcode & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            assert address + (imm << 2) == int(node['bl_target'], 16)
            checks['direct_bl_targets'] += 1
    for value in node.values():
        runtime_walk(value, base, library)


for folder in FOLDERS:
    directory = APP / 'analysis' / folder
    assert directory.is_dir(), f'Missing extraction directory: {directory}'
    for path in sorted(directory.rglob('*.json')):
        node = json.loads(path.read_text())
        walk(node, path.parent)
        default_library = APP / 'unpacked/lib/arm64-v8a' / (
            'libapp.so' if folder != 'ws_event_contract' else 'librust_lib_distinguish.so')
        runtime_walk(node, path.parent, default_library)
        artifacts.append({'file': str(path.relative_to(APP)),
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    for path in sorted(set(directory.rglob('*.llvm.txt')) | set(directory.rglob('*.asm.txt'))):
        contents = path.read_text()
        match = re.search(r'^(.+\.so):\s*file format', contents, re.M)
        if not match:
            continue
        library = Path(match.group(1))
        if not library.is_absolute():
            library = APP.parent / library
        for instruction in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+', contents, re.M):
            address = int(instruction.group(1), 16)
            actual, _ = elf_read(library, address)
            assert int.from_bytes(actual, 'little') == int(instruction.group(2), 16), str(path)
            checks['llvm_instruction_words'] += 1
            raw_locations.add((str(library), address))

# Recheck return-value discards from original bytes, independent of AOT labels.
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
local = json.loads((APP / 'analysis/local_state/local_state.json').read_text())
factory_lib = APP / 'unpacked/lib/arm64-v8a/libapp.so'
for item in local['from_json_raw_getter_return_discard_checks']:
    call_address = int(item['getter_call'], 16)
    call, _ = elf_read(factory_lib, call_address)
    decoded = next(decoder.disasm(call, call_address))
    assert (decoded.mnemonic, decoded.op_str) == ('blr', 'x30')
    address = int(item['next_x0_overwrite'], 16)
    actual, _ = elf_read(factory_lib, address)
    decoded = next(decoder.disasm(actual, address))
    assert (decoded.mnemonic, decoded.op_str) == (item['mnemonic'], item['operands'])

# Only our explicit offline implementation runs here, never APK/Dart/Rust code.
import importlib.util
codec_file = APP / 'analysis/image_codec/reconstructed_codec.py'
spec = importlib.util.spec_from_file_location('offline_image_codec_verification', codec_file)
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)
synthetic = json.loads((APP / 'analysis/image_codec/synthetic_validation.json').read_text())
for case in synthetic['rule_cases']:
    assert case['synthetic'] is True
    trace = []
    try:
        output = codec.decode_data(case['input'], case['rules'], trace=trace)
    except codec.RuleFormatError as error:
        assert 'error' in case and error.segment_index == case['segment_index']
    else:
        assert 'error' not in case
        assert output == case['expected'] == case['output']
    assert trace == case['analyst_trace']
    checks['synthetic_rule_cases'] += 1
for case in synthetic['base64_cases']:
    assert case['synthetic'] is True
    try:
        output = codec.dart_base64_decode(case['input'])
    except codec.Base64FormatError:
        assert 'error' in case
    else:
        assert 'error' not in case and output.hex() == case['output_hex']
    checks['synthetic_base64_cases'] += 1
for case in synthetic['url_cases']:
    assert case['synthetic'] is True
    assert codec.get_img_url(case['img'], case['host']) == case['output']
    checks['synthetic_url_cases'] += 1
png = synthetic['http_png_roundtrip']
assert png['synthetic'] is True and png['not_server_data'] is True
output = codec.decode_http_image_body(png['body'], png['rules'])
assert codec.decode_data(png['body'], png['rules']) == png['restored_base64']
assert output == resolve(png['result_file']).read_bytes()
assert hashlib.sha256(output).hexdigest() == png['sha256']
assert output.startswith(b'\x89PNG\r\n\x1a\n') and len(output) == png['size_bytes']
checks['synthetic_png_roundtrips'] += 1

# Supplement the device source excerpts with raw BL target checks.
device_manifest = json.loads((APP / 'analysis/device_lifecycle/evidence_manifest.json').read_text())
function_index = json.loads((APP / 'analysis/aot_runtime/function_index.json').read_text())
functions = {f['address']: f for f in function_index['functions']}
for method in device_manifest['methods']:
    function = functions[method['address']]
    for call in function['direct_calls']:
        address = int(call['address'], 16)
        actual, _ = elf_read(factory_lib, address)
        branch_check(factory_lib, address, actual.hex(), int(call['target'], 16), True)
        checks['device_methods_direct_bl_targets'] += 1

events = json.loads((APP / 'analysis/ws_event_contract/event_contract.json').read_text())
native_lib = APP / 'unpacked/lib/arm64-v8a/librust_lib_distinguish.so'
negative = events['finite_negative_evidence']
target = int(negative['known_emitter_target_elf'], 16)
coverage, sites, branch_count, scanned_words = [], [], 0, 0
with native_lib.open('rb') as stream:
    elf = ELFFile(stream)
    native_data = native_lib.read_bytes()
    for segment in elf.iter_segments():
        if segment['p_type'] != 'PT_LOAD' or not segment['p_flags'] & 1:
            continue
        start, offset, length = segment['p_vaddr'], segment['p_offset'], segment['p_filesz']
        coverage.append({'elf_start': hex(start), 'elf_end_exclusive': hex(start + length),
                         'file_offset': hex(offset), 'file_backed_bytes': length,
                         'memory_bytes': segment['p_memsz'], 'aligned_words': length // 4})
        for i in range(0, length - 3, 4):
            word = int.from_bytes(native_data[offset + i:offset + i + 4], 'little')
            scanned_words += 1
            if word & 0x7c000000 != 0x14000000:
                continue
            branch_count += 1
            imm = word & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            address = start + i
            if address + imm * 4 == target:
                sites.append({'elf_va': hex(address), 'ghidra_va': hex(address + 0x100000),
                              'opcode': 'BL' if word & 0x80000000 else 'B',
                              'bytes_le': native_data[offset + i:offset + i + 4].hex()})
    relas = [r for section in elf.iter_sections() if hasattr(section, 'iter_relocations')
             for r in section.iter_relocations() if r.is_RELA()]
    rela_matches = [{'relocation_offset_elf': hex(r['r_offset']),
                     'addend_target_elf': hex(r['r_addend'])}
                    for r in relas if r['r_addend'] == target]
    assert coverage == negative['coverage']
    assert scanned_words == negative['aligned_words_scanned']
    assert branch_count == negative['all_direct_branch_word_count']
    assert sites == negative['direct_call_sites']
    assert len(relas) == negative['RELA_entries_scanned']
    assert rela_matches == negative['RELA_exact_target_matches']
    relocations = {r['r_offset']: r for r in relas}
    for binding in events['relocation_bindings']:
        record = relocations[int(binding['relocation_offset_elf'], 16)]
        assert record['r_info_type'] == 1027  # R_AARCH64_RELATIVE
        assert record['r_addend'] == int(binding['addend_target_elf'], 16)
        checks['native_relocation_bindings'] += 1
checks['native_executable_words_scanned'] = scanned_words
checks['native_rela_entries_scanned'] = len(relas)
for source in negative['complete_decompilation_checks']:
    data, lines = read(source['file'])
    assert len(lines) == source['line_count']
    callees = sorted(set(re.findall(r'FUN_([0-9a-f]{8})\(', data.decode()))
                     - {Path(source['file']).stem})
    assert callees == source['direct_callees_ghidra']
    assert '001ec7f0' not in callees and '001b4058' not in callees
import struct
for example in events['synthetic_encoding_examples']:
    assert example['synthetic'] is True
    first, second = example['first_string'].encode(), example['second_string'].encode()
    encoded = b'\x00' + struct.pack('<II', example['event_integer'], len(first)) + first
    encoded += struct.pack('<I', len(second)) + second
    assert encoded.hex() == example['serialized_hex']
    assert len(encoded) == example['byte_length']
    checks['synthetic_frb_roundtrips'] += 1

required = ['运行状态与设备控制深度还原报告.txt',
            'analysis/local_state/local_state.json',
            'analysis/image_codec/algorithm_contract.json',
            'analysis/device_lifecycle/lifecycle.json',
            'analysis/ws_event_contract/event_contract.json']
missing = [name for name in required if not (APP / name).is_file()]
result = {'status': 'PASS' if not missing else 'FAIL', 'all_checks_passed': not missing,
          'original_apk_unchanged': True, 'original_apk_sha256': EXPECTED_APK,
          'original_library_hashes_valid': True, 'original_library_sha256': EXPECTED_LIBRARIES,
          'extraction_directories': FOLDERS, 'json_artifacts_checked': len(artifacts),
          'evidence_checks': checks, 'missing_required_outputs': missing,
          'unique_hashed_evidence_files': len(hashed_files),
          'unique_exact_source_lines': len(source_locations),
          'unique_original_instruction_addresses': len(raw_locations),
          'artifacts': artifacts, 'target_code_executed': False,
          'report': {'file': str(APP / required[0]),
                     'sha256': hashlib.sha256((APP / required[0]).read_bytes()).hexdigest()},
          'verification_script': str(Path(__file__).resolve()),
          'verification_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'business_server_contacted': False,
          'limits': 'Static evidence, instruction targets and synthetic analyst-codec cases only; no captured traffic or server behavior verified.'}
(APP / 'analysis/runtime_reconstruction_verification.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k != 'artifacts'}, ensure_ascii=False, indent=2))
if missing:
    raise SystemExit('Required outputs missing')

