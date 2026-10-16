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
OUT = APP / 'analysis/connection_preview_closure'
LIBS = APP / 'unpacked/lib/arm64-v8a'
EXPECTED = {'libapp.so': '40d890193daa716defe2eec6cd2959bdbf7f7cf8345f8213b1747e54863a5a55',
            'librust_lib_distinguish.so': '0af3f1f12e57e9b5f2d409343421c1fa21b0bcffe7860a30cf972a1265399847'}
APK_SHA = '8fd060966759990ab5ef90639e3376a2b6aea209f3f545d768a2fdc668dfeaa9'
COUNTS = dict(file_hashes=0, exact_source_lines=0, source_ranges=0,
              source_range_lines=0, raw_instruction_records=0,
              direct_bl_targets=0, direct_b_targets=0,
              llvm_instruction_words=0, relocation_bindings=0)
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
    selected = lines[start - 1:end]
    joined = '\n'.join(selected)
    assert expected in (joined, joined + '\n'), (path, start, end)
    COUNTS['source_ranges'] += 1
    COUNTS['source_range_lines'] += len(selected)
    SOURCE_SEEN.update((str(path_of(path, base)), i) for i in range(start, end + 1))


def llvm_check(path, library, start=None, end=None, base=APP):
    raw, _ = read(path, base)
    seen = set()
    for match in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+', raw.decode(), re.M):
        address, expected = (int(v, 16) for v in match.groups())
        if start is not None:
            assert start <= address < end
        actual, _ = elf_read(library, address)
        assert int.from_bytes(actual, 'little') == expected, (path, hex(address))
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
    if {'file', 'start_line', 'end_line', 'excerpt'} <= node.keys():
        source_range(node['file'], node['start_line'], node['end_line'], node['excerpt'], base)
    if {'source', 'start_line', 'end_line', 'snippet', 'snippet_sha256'} <= node.keys():
        hash_check(node['snippet'], node['snippet_sha256'], base)
        source_range(node['source'], node['start_line'], node['end_line'],
                     read(node['snippet'], base)[0].decode(), base)
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
        actual, offset = elf_read(library, address)
        assert actual.hex() == node[bytes_key], node
        if 'file_offset' in node:
            assert offset == as_int(node['file_offset'])
        if word_key in node:
            assert int.from_bytes(actual, 'little') == as_int(node[word_key])
        if node.get(target_key) is not None:
            branch_check(actual, address, as_int(node[target_key]))
        COUNTS['raw_instruction_records'] += 1
        RAW_SEEN.add((str(library), address))
    if {'relocation_offset_elf', 'addend_target_elf'} <= node.keys():
        elf_read(library, 0) if path_of(library) not in ELF_CACHE else None
        record = ELF_CACHE[path_of(library)][2][as_int(node['relocation_offset_elf'])]
        assert record == (1027, as_int(node['addend_target_elf'])), node
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
    for value in node.values():
        walk(value, base, library)


assert sha((APP.parent / 'app_xcs(新).apk.1.1').read_bytes()) == APK_SHA
for name, expected in EXPECTED.items():
    assert sha((LIBS / name).read_bytes()) == expected
artifacts = []
for folder in ['is_content_ws', 'end_preview', 'state_audit', 'stream_lifetime']:
    directory = OUT / folder
    assert directory.is_dir(), directory
    library = LIBS / ('libapp.so' if folder in ['end_preview', 'stream_lifetime']
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

# Independently fix the two conclusions to their original bytes, not labels.
native = json.loads((OUT / 'is_content_ws/is_content_ws.json').read_text())
assert native['determination']['user_parameter_count'] == 0
assert native['determination']['normal_return_formula'] == 'Dart bool = (SDK byte at +0x2a5 read under lock != 0)'
serializer = next(e['excerpt'] for e in native['source_evidence'] if e['id'] == 'dart_empty_id5_serializer')
assert 'sse_encode_String' not in serializer and 'r3 = 5' in serializer
assert elf_read(LIBS / 'librust_lib_distinguish.so', 0xe2c48)[0].hex() == '08940a91'
assert elf_read(LIBS / 'librust_lib_distinguish.so', 0xe2c50)[0].hex() == '00014039'
assert elf_read(LIBS / 'libapp.so', 0x6f2a58, 8)[0].hex() == 'e00316aac0035fd6'
old_pseudo = (APP / 'analysis/device_lifecycle/reconstructed.dart').read_text()
assert 'isContentWs(host)' not in old_pseudo and 'isContentWs()' in old_pseudo
report = APP / '连接判定与预览退出补全报告.txt'
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
          'limits': 'Static provenance and ARM64 instruction consistency only; no runtime traffic or server behavior verified.'}
(APP / 'analysis/connection_preview_closure_verification.json').write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k != 'artifacts'}, ensure_ascii=False, indent=2))
