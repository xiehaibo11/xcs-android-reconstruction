#!/usr/bin/env python3
"""Static provenance for the main page's FRB stream lifetime.

No APK, snapshot, native library or business endpoint is executed.
"""

from _paths import app_root, workspace_root
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

APP = app_root()
OUT = APP / 'analysis/connection_preview_closure/stream_lifetime'
LIB = APP / 'unpacked/lib/arm64-v8a/libapp.so'
LLVM = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
SELECTED = [0x51f028, 0x556974, 0x51f420, 0x51f4a0, 0x51f5ac,
            0x51f66c, 0x51f6f8, 0x51f85c, 0x51fcb8, 0x51f954, 0x51fb54]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_elf():
    with LIB.open('rb') as stream:
        elf = ELFFile(stream)
        sections = [(s['sh_addr'], s['sh_offset'], s['sh_size'])
                    for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']
    data = LIB.read_bytes()

    def read(address, length=4):
        start, offset, size = next(s for s in sections
                                 if s[0] <= address and address + length <= s[0] + s[2])
        offset += address - start
        return data[offset:offset + length]
    return read


def dump_json(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def build():
    (OUT / 'evidence').mkdir(parents=True, exist_ok=True)
    read = load_elf()
    methods, checks = [], []
    for path in sorted((APP / 'analysis/aot_dump/asm').rglob('*.dart')):
        data = path.read_bytes()
        lines = data.decode().splitlines()
        for i, line in enumerate(lines):
            header = re.search(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)', line)
            if not header or int(header[1], 16) not in SELECTED:
                continue
            end = next(j for j in range(i + 1, len(lines)) if lines[j] == '  }')
            text = '\n'.join(lines[i - 1:end + 1]) + '\n'
            snippet = OUT / 'evidence' / (header[1][2:] + '.asm.txt')
            snippet.write_text(text)
            methods.append({'address': header[1], 'size': header[2], 'source': str(path),
                            'source_sha256': sha(data), 'start_line': i,
                            'end_line': end + 1, 'snippet': str(snippet),
                            'snippet_sha256': sha(snippet.read_bytes())})
            for instruction in re.finditer(r'//\s+(0x[0-9a-f]+): bl\s+#(0x[0-9a-f]+)', text):
                address, target = (int(x, 16) for x in instruction.groups())
                word = int.from_bytes(read(address), 'little')
                imm = word & 0x3ffffff
                if imm & 0x2000000:
                    imm -= 0x4000000
                assert word & 0xfc000000 == 0x94000000
                assert address + imm * 4 == target
                checks.append({'binary': str(LIB), 'elf_va': hex(address),
                               'bytes_le': read(address).hex(), 'word_hex': f'{word:08x}',
                               'check': 'BL', 'target_elf': hex(target)})
    assert {int(m['address'], 16) for m in methods} == set(SELECTED)
    # The SDK/core libraries were omitted from Blutter's asm files. Bound the
    # receive-port close body with the next known closure entry and raw ELF.
    start, stop = 0x43f184, 0x43f1d8
    raw = read(start, stop - start)
    snapshot = OUT / 'evidence/receive_port_close.llvm.txt'
    snapshot.write_text(subprocess.check_output([
        LLVM, '-D', f'--start-address={hex(start)}', f'--stop-address={hex(stop)}', str(LIB)
    ], text=True))
    snapshot_record = {'binary': str(LIB), 'elf_start': hex(start),
                       'elf_end_exclusive': hex(stop), 'raw_bytes_sha256': sha(raw),
                       'file': str(snapshot), 'sha256': sha(snapshot.read_bytes())}
    out = {'scope': 'main FRB subscription and Dart receive-port lifetime; static only',
           'source_binary': {'file': str(LIB), 'sha256': sha(LIB.read_bytes())},
           'generator': {'file': str(Path(__file__).resolve()),
                         'sha256': sha(Path(__file__).read_bytes())},
           'methods': methods, 'raw_instruction_checks': checks,
           'raw_llvm_snapshots': [snapshot_record],
           'claims': [
               {'id': 'subscription_owner', 'methods': ['0x51f028', '0x556974'],
                'conclusion': 'Main.initState creates/listens to the Rust event stream and stores its subscription in MainState+0x17. Main.dispose loads that field and invokes cancel through GDT, without awaiting its Future.'},
               {'id': 'stream_setup', 'methods': ['0x51f4a0', '0x51f6f8', '0x51f85c', '0x51f954'],
                'conclusion': 'RustStreamSink stores the receive port and a buffered stream. The public event stream uses listenAndBuffer; preview route exit is not the owner dispose of this Main subscription.'},
               {'id': 'dart_stream_finally', 'methods': ['0x51fcb8'],
                'conclusion': 'The reviewed async-star worker has iterator.cancel/await and ReceivePort.close in normal cancellation/end and finally paths (0x51ff04/0x51ff18, 0x51ff38, 0x51ff94/0x51ffb0, 0x520020/0x520064). These release Dart stream/port resources.'},
               {'id': 'port_close_body', 'elf_range': ['0x43f184', '0x43f1d8'],
                'conclusion': 'ReceivePort.close calls RawReceivePort.close at 0x2d0408 and its StreamController.close at 0x5f0874, then returns Null. No app wsLogout/stop call appears in this bounded body.'},
               {'id': 'cancellation_scope', 'methods': ['0x556974', '0x51fcb8'],
                'conclusion': 'Cancelling the Dart subscription is not evidence of an authenticated native logout. These complete methods do not call the known app wsLogout entry; no guarantee about all indirect/native-side consequences is inferred.'}
           ],
           'target_code_executed': False, 'business_server_contacted': False}
    dump_json('stream_lifetime.json', out)
    (OUT / '事件订阅清理说明.txt').write_text(
        '预览页面退出与Main页面销毁的边界\n\n'
        'Main.initState 0x51f028创建Rust事件流，并将listen返回的订阅放在State+0x17。\n'
        'Main.dispose 0x556974才读取该订阅并通过GDT调用cancel，Future没有await。\n'
        '预览路由关闭不等于其下方Main被销毁，因此不能把此处清理归于endPreview。\n\n'
        'FRB RustStreamSink._setup建立ReceivePort与async-star解码流，listenAndBuffer提供缓冲。\n'
        '完整worker 0x51fcb8包含StreamIterator.cancel/await以及ReceivePort.close收尾路径。\n'
        'ReceivePort.close 0x43f184的原始21条指令调用RawReceivePort.close和StreamController.close。\n'
        '已审查body没有业务wsLogout/原生stop调用；关闭Dart接收端口不能当作认证退出证据。\n'
        '此结论限于列出的方法与原始指令，不扩展为所有间接/native行为不存在的证明。\n\n'
        '来源、完整方法片段、原ELF的直接BL核对、LLVM快照及哈希见stream_lifetime.json。\n')


def verify():
    data = json.loads((OUT / 'stream_lifetime.json').read_text())
    read = load_elf()
    count = 0
    for record in data['methods']:
        source = Path(record['source']).read_bytes()
        assert sha(source) == record['source_sha256']
        lines = source.decode().splitlines()
        snippet = Path(record['snippet']).read_bytes()
        assert sha(snippet) == record['snippet_sha256']
        assert snippet.decode() == '\n'.join(lines[record['start_line'] - 1:record['end_line']]) + '\n'
    for record in data['raw_instruction_checks']:
        address = int(record['elf_va'], 16)
        actual = read(address)
        assert actual.hex() == record['bytes_le']
        word = int.from_bytes(actual, 'little')
        assert word == int(record['word_hex'], 16) and word & 0xfc000000 == 0x94000000
        imm = word & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        assert address + imm * 4 == int(record['target_elf'], 16)
        count += 1
    words = 0
    for snapshot in data['raw_llvm_snapshots']:
        content = Path(snapshot['file']).read_bytes()
        assert sha(content) == snapshot['sha256']
        start, stop = int(snapshot['elf_start'], 16), int(snapshot['elf_end_exclusive'], 16)
        assert sha(read(start, stop - start)) == snapshot['raw_bytes_sha256']
        for instruction in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', content.decode(), re.M):
            address, expected = (int(v, 16) for v in instruction.groups())
            assert int.from_bytes(read(address), 'little') == expected
            words += 1
        assert words == 21
    assert sha(Path(data['generator']['file']).read_bytes()) == data['generator']['sha256']
    result = {'status': 'PASS', 'complete_methods': len(data['methods']),
              'raw_direct_bl_checks': count, 'llvm_words_checked': words,
              'target_code_executed': False, 'business_server_contacted': False}
    dump_json('verification.json', result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if not args.verify:
        build()
    verify()
