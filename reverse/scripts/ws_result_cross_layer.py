#!/usr/bin/env python3
"""Cross-check WebSocket-to-HTTP edges using static AOT and original ELF bytes.

This is an evidence extractor, not a client or recovered application source.
It does not load native libraries, execute the APK or contact any server.
"""

from _paths import app_root, workspace_root
import hashlib
import json
import re
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

APP = app_root()
OUT = APP / 'analysis/ws_result_integration'
OUT.mkdir(parents=True, exist_ok=True)
LLVM = '/opt/homebrew/opt/llvm/bin/llvm-objdump'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def proof(path, needle):
    lines = path.read_text().splitlines()
    i = next(i for i, line in enumerate(lines) if needle in line)
    return {'file': str(path), 'line': i + 1, 'excerpt': lines[i].strip(),
            'sha256': digest(path)}


def image(name):
    path = APP / 'unpacked/lib/arm64-v8a' / name
    data = path.read_bytes()
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        sections = [(s['sh_addr'], s['sh_offset'], s['sh_size'])
                    for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']
    return path, data, sections


images = {name: image(name) for name in ('libapp.so', 'librust_lib_distinguish.so')}


def raw(name, address):
    path, data, sections = images[name]
    section = next(s for s in sections if s[0] <= address < s[0] + s[2])
    offset = section[1] + address - section[0]
    value = data[offset:offset + 4]
    return {'library': str(path), 'library_sha256': digest(path),
            'elf_virtual_address': hex(address), 'file_offset': hex(offset),
            'bytes_hex': value.hex(), 'opcode': hex(int.from_bytes(value, 'little'))}


index = json.loads((APP / 'analysis/aot_runtime/function_index.json').read_text())
functions = {int(f['address'], 16): f for f in index['functions']}
selected = [0x520e6c, 0x527460, 0x529164, 0x4a26cc, 0x4a2d48,
            0x4a2164, 0x4a25ac, 0x4a2ea8, 0x4b9594]
excerpts, calls = [], []
for address in selected:
    function = functions[address]
    path = APP / function['path']
    lines = path.read_text().splitlines()
    start = function['line'] - 2
    end = next((i for i in range(start + 2, len(lines)) if lines[i] == '  }'), len(lines) - 1)
    content = '\n'.join(lines[start:end + 1]) + '\n'
    snippet = OUT / f'{address:08x}.asm.txt'
    snippet.write_text(content)
    excerpts.append({'file': str(path), 'sha256': digest(path),
                     'source_start_line': start + 1, 'source_end_line': end + 1,
                     'snippet': str(snippet), 'snippet_sha256': digest(snippet),
                     'function_address': hex(address), 'function_signature': function['signature']})
    for call in function['direct_calls']:
        checked = raw('libapp.so', int(call['address'], 16))
        opcode = int(checked['opcode'], 16)
        assert opcode & 0xfc000000 == 0x94000000
        imm = opcode & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        assert int(call['address'], 16) + (imm << 2) == int(call['target'], 16)
        checked.update({'target': call['target'], 'label': call['label'],
                        'function_address': function['address'], 'verified': True})
        calls.append(checked)

checks = []
# CMP X1,#imm: operands have already been unboxed, so 40 and 4 are literal values.
for address, value, purpose in [(0x4a2d80, 40, 'tile_code_below_40'),
                                 (0x4a2d98, 0, 'observed_count_positive'),
                                 (0x4a2da0, 4, 'observed_count_exactly_four')]:
    checked = raw('libapp.so', address)
    expected = 0xf100003f | (value << 10)
    assert int(checked['opcode'], 16) == expected
    checked.update({'purpose': purpose, 'instruction': f'cmp x1, #{value}',
                    'value_is_unboxed': True, 'verified': True})
    checks.append(checked)
# The Rust receiver admits 113..117, plus 101 and 102, and writes bridge event 4.
for address, expected, purpose in [
    (0xc6090, 0x5101c509, 'sub w9,w8,#113'),
    (0xc6094, 0x7100153f, 'cmp w9,#5, unsigned range check'),
    (0xc60d8, 0x7101951f, 'cmp w8,#101'),
    (0xc60e0, 0x7101991f, 'cmp w8,#102'),
    (0xc60a0, 0x52800088, 'bridge event integer=4'),
    (0xc616c, 0x52800088, 'bridge event integer=4 for 101'),
]:
    checked = raw('librust_lib_distinguish.so', address)
    assert int(checked['opcode'], 16) == expected
    checked.update({'purpose': purpose, 'verified': True})
    checks.append(checked)

native = APP / 'analysis/deep_rust/lifecycle/functions/001c5f58.c'
frb = APP / 'analysis/aot_dump/asm/distinguish/src/rust/frb_generated.dart'
page = APP / 'analysis/aot_dump/asm/distinguish/pages/main/main_page.dart'
service = APP / 'analysis/aot_dump/asm/distinguish/service/games_service.dart'
native_excerpt = subprocess.run([LLVM, '--disassemble', '--start-address=0xc5f58',
                                '--stop-address=0xc61cc', str(images['librust_lib_distinguish.so'][0])],
                               capture_output=True, text=True, check=True).stdout
(OUT / 'rust_business_to_flutter.llvm.txt').write_text(native_excerpt)
result = {
    'scope': 'Cross-layer static evidence; semantic names are analyst reconstruction.',
    'address_domains': {'libapp': 'Dart ELF virtual address',
                        'rust': 'Rust ELF virtual address; Ghidra address adds 0x100000'},
    'layers': [
        {'layer': 'WebSocket wire', 'format': 'JSON object; data_content is a String'},
        {'layer': 'business data_content', 'format': 'JSON text with msg_type and msg_content'},
        {'layer': 'Rust to Dart bridge', 'format': 'integer event 4 + two Strings; first is empty, second is original inner JSON text',
         'evidence': [proof(native, 'local_90 = 4;'), proof(native, 'lStack_a0 = param_3[1];')]},
        {'layer': 'Dart FRB decode', 'format': 'uint32 event followed by two length-prefixed UTF-8 Strings; not the WebSocket wire format',
         'evidence': [proof(frb, '0x520e98: r0 = getUint32()'),
                      proof(frb, '0x520ea8: r0 = sse_decode_String()'),
                      proof(frb, '0x520eb8: r0 = sse_decode_String()')]},
        {'layer': 'Dart business dispatch', 'format': 'Decode event second String -> Message.fromJson -> branches 101/102/113..117'},
        {'layer': 'HTTP results', 'format': 'JSON array of numeric maps at POST /api/zhuo/add',
         'evidence': [proof(service, '"/api/zhuo/add"'),
                      proof(page, '0x4a219c: bl'), proof(page, '0x4a24e8: bl')]},
    ],
    'function_excerpts': excerpts,
    'raw_instruction_checks': checks,
    'raw_direct_call_checks': calls,
    'verification': {'raw_instructions': len(checks), 'raw_direct_calls': len(calls),
                     'all_verified': True, 'target_code_executed': False,
                     'business_server_contacted': False},
    'limits': ['No captured server frames or actual JWT.',
               'Direct BL verification checks targets, not every dynamic dispatch label.',
               'No original Rust/Dart source or complete build recovered.']
}
(OUT / 'cross_layer_flow.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(result['verification'], ensure_ascii=False))
