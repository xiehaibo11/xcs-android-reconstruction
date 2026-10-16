#!/usr/bin/env python3
"""Read-only static SDK flag audit. Never loads or executes target libraries."""

from _paths import app_root, workspace_root
import hashlib
from functools import lru_cache
import json
from pathlib import Path
import re
import struct
import subprocess

BASE = app_root()
OUT = BASE / 'analysis/connection_preview_closure/state_audit'
RAW = OUT / 'raw_llvm'
RUST = BASE / 'unpacked/lib/arm64-v8a/librust_lib_distinguish.so'
DART = BASE / 'unpacked/lib/arm64-v8a/libapp.so'
LLVM = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
NATIVE_SOURCE = {
    'constructor': BASE / 'analysis/ws_event_contract/native_pseudocode/functions/001dbaf0.c',
    'lazy_constructor': BASE / 'analysis/ws_event_contract/native_pseudocode/functions/001dbef8.c',
    'global': BASE / 'analysis/deep_rust/lifecycle/functions/001e31e0.c',
    'transport_get': BASE / 'analysis/deep_rust/lifecycle/functions/001e2c04.c',
    'transport_set': BASE / 'analysis/deep_rust/lifecycle/functions/001e2d2c.c',
    'full_stop': BASE / 'analysis/deep_rust/lifecycle/functions/001e2ea0.c',
    'inbound': BASE / 'analysis/deep_rust/lifecycle/functions/001e99a0.c',
    'disconnect': BASE / 'analysis/login_flow/native_pseudocode/functions/001eab5c.c',
    'login_gate': BASE / 'analysis/login_flow/native_pseudocode/functions/001eaf88.c',
    'gated_close': BASE / 'analysis/login_flow/native_pseudocode/functions/001e8b4c.c',
    'send_gate': BASE / 'analysis/deep_rust/lifecycle/functions/001eb854.c',
    'connect_poll_a': BASE / 'analysis/deep_rust/functions/001a5ec8.c',
    'connect_poll_b': BASE / 'analysis/deep_rust/functions/001d327c.c',
    'logout': BASE / 'analysis/ws_heartbeat/native_pseudocode/functions/001cec94.c',
    'is_content_ws': BASE / 'analysis/connection_preview_closure/is_content_ws/native_pseudocode/functions/001b8348.c',
}
DART_ROOT = BASE / 'analysis/aot_dump/asm/distinguish'
DART_METHODS = [
    ('end_preview', 'service/preview_service.dart', 0x461014),
    ('preview_save_callback', 'pages/frame_preview/frame_preview_page.dart', 0x460b60),
    ('preview_route_callback', 'pages/main/main_page.dart', 0x4ac0b8),
    ('http_post', 'common/http/http_client.dart', 0x42c230),
    ('http_handle_response', 'common/http/http_client.dart', 0x42cc54),
    ('http_handle_exception', 'common/http/http_client.dart', 0x42c3d4),
    ('http_parse_exception', 'common/http/http_client.dart', 0x42c428),
    ('explicit_logout_button', 'pages/main/main_page.dart', 0x4a83b0),
]


@lru_cache(maxsize=None)
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(p, line):
    return {'file': str(p), 'line': line, 'excerpt': p.read_text().splitlines()[line-1], 'sha256': sha(p)}


def hits(p, needle):
    return [ref(p, n) for n, s in enumerate(p.read_text().splitlines(), 1) if needle in s]


def elf_offset(data, address):
    ph = struct.unpack_from('<Q', data, 32)[0]
    es, count = struct.unpack_from('<HH', data, 54)
    for i in range(count):
        typ, flags, off, va, pa, size, mem, align = struct.unpack_from('<IIQQQQQQ', data, ph+i*es)
        if typ == 1 and va <= address < va+size:
            return off+address-va
    raise ValueError(hex(address))


def parse_raw(p, elf):
    data = elf.read_bytes()
    records = []
    file_sha = sha(p)
    for n, line in enumerate(p.read_text().splitlines(), 1):
        m = re.match(r'^\s*([0-9a-f]+):\s*([0-9a-f]{8})\s+(.+)', line)
        if not m:
            continue
        addr = int(m[1], 16)
        word = int(m[2], 16)
        off = elf_offset(data, addr)
        assert data[off:off+4] == word.to_bytes(4, 'little'), (str(p), hex(addr))
        item = {'file': str(p), 'line': n, 'excerpt': line, 'sha256': file_sha,
                'elf_file': str(elf), 'elf_sha256': sha(elf),
                'elf_virtual_address': hex(addr), 'file_offset': hex(off),
                'raw_bytes_hex': data[off:off+4].hex(), 'instruction_word_hex': f'{word:08x}',
                'instruction': m[3].strip()}
        if word >> 26 == 0b100101:
            signed = (word & 0x3ffffff)
            if signed & 0x2000000:
                signed -= 0x4000000
            target = addr+signed*4
            item['bl_target'] = hex(target)
            assert int(re.search(r'\bbl\s+0x([0-9a-f]+)', m[3])[1], 16) == target
        records.append(item)
    return records


def extract_dart(name, relative, start):
    p = DART_ROOT / relative
    lines = p.read_text().splitlines()
    idx = next(i for i, s in enumerate(lines) if f'** addr: {hex(start)},' in s)
    size = int(re.search(r'size: (0x[0-9a-f]+)', lines[idx])[1], 16)
    end = start+size
    following = next((i for i in range(idx+1, len(lines)) if '** addr:' in lines[i]), len(lines))
    text = '\n'.join(lines[max(0, idx-1):following])+'\n'
    excerpt_file = OUT / 'dart_methods' / f'{name}.asm.txt'
    excerpt_file.write_text(text)
    raw = RAW / f'{name}.asm.txt'
    result = subprocess.run([LLVM, '-D', f'--start-address={start}', f'--stop-address={end}', str(DART)], check=True, capture_output=True, text=True)
    raw.write_text(result.stdout)
    records = parse_raw(raw, DART)
    direct = []
    indirect = []
    for n in range(idx+1, following):
        s = lines[n]
        m = re.match(r'\s*//\s+(0x[0-9a-f]+):\s+bl\s+#(0x[0-9a-f]+)\s*(.*)', s)
        if m and start <= int(m[1], 16) < end:
            direct.append({'address': m[1], 'target': m[2], 'annotation': m[3].strip(), 'evidence': ref(p, n+1)})
        if re.match(r'\s*//\s+0x[0-9a-f]+:\s+blr\s+', s):
            indirect.append(ref(p, n+1))
    return {'name': name, 'source': str(p), 'source_sha256': sha(p), 'source_start_line': idx+1,
            'elf_start': hex(start), 'elf_end_exclusive': hex(end), 'extent_evidence': ref(p, idx+1),
            'complete_excerpt': str(excerpt_file), 'complete_excerpt_sha256': sha(excerpt_file),
            'direct_calls': direct, 'indirect_calls': indirect, 'raw_checks': records}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    RAW.mkdir(exist_ok=True)
    (OUT/'dart_methods').mkdir(exist_ok=True)
    full = RAW / 'all_native.asm.txt'
    result = subprocess.run([LLVM, '-d', str(RUST)], check=True, capture_output=True, text=True)
    full.write_text(result.stdout)
    # Verify full disassembly once, but preserve only relevant instruction records in JSON.
    all_records = parse_raw(full, RUST)
    by_addr = {int(x['elf_virtual_address'], 16): x for x in all_records}
    immediate_inventory = [x for x in all_records if re.search(r'#0x(?:2a5|2b1)\b', x['instruction'])]
    # This exact-offset inventory excludes stack offsets, where the same numbers have another meaning.
    assert len(immediate_inventory) == 20
    assert all('[sp,' not in x['instruction'] for x in immediate_inventory)
    writes = [x for x in immediate_inventory if x['instruction'].startswith('strb')]
    assert len(writes) == 16  # 10 transport writes, 6 auth writes, including lock slow paths.
    aliases = [by_addr[a] for a in [0xa6020, 0xd3578, 0xe2c50]]
    assert all(x['instruction'].startswith('ldrb') for x in aliases)
    init = [by_addr[a] for a in [0xdbd18, 0xdbd20, 0xdbd88, 0xdbd8c, 0xdbd90, 0xdbd94]]
    calls = [x for x in all_records if x.get('bl_target') in ['0xe2c04','0xe2d2c','0xe2ea0']]
    assert len(calls) == 12
    native_checks = []
    ranges = [('initializer', 0xdbaf0, 0xdbdac+4), ('transport_get_set_stop', 0xe2c04, 0xe303c),
              ('inbound_auth', 0xea380, 0xea730), ('inbound_server_stop', 0xe9f80, 0xea020),
              ('disconnect_cleanup', 0xeab5c, 0xeaf88), ('logout_clear_and_stop', 0xcec94, 0xcee30)]
    for name, start, end in ranges:
        p = RAW / f'{name}.asm.txt'
        p.write_text('\n'.join(x['excerpt'] for x in all_records if start <= int(x['elf_virtual_address'],16) < end)+'\n')
        native_checks.extend(parse_raw(p, RUST))
    key_addrs = [0xa6018,0xa6020,0xa6dc0,0xa6dc8,0xa70f4,0xa74f8,0xa75d8,0xa75dc,
                 0xd3570,0xd3578,0xd4328,0xd4330,0xd466c,0xd4c7c,0xd4d2c,0xd4d30,
                 0xe2c48,0xe2c50,0xe2d78,0xe2e08,0xe2f30,0xe2fa4,
                 0xea508,0xea510,0xea5f8,0xea600,0xea954,0xea958,0xea9c4,0xea9c8]
    key = [by_addr[a] for a in key_addrs]
    source_groups = {}
    needles = {
        'constructor': ['+ 0x29c) = 0','+ 0x2a4) = 0','puVar6[0x55] = 0','puVar6 + 0x56) = 0'],
        'lazy_constructor': ['FUN_001dbaf0('], 'global': ['DAT_002b4508'],
        'transport_get': ['+ 0x29c','+ 0x2a4','+ 0x2a5'],
        'transport_set': ['+ 0x29c','+ 0x2a4','+ 0x2a5'],
        'full_stop': ['FUN_001e2d2c(param_1,0)', '+ 0x2a8', '+ 0x2b0', '+ 0x2b1'],
        'inbound': ['local_1c0 == 0x36','FUN_001e2ea0(local_100)', '(int)local_108 == 0', '+ 0x2b1', 'FUN_001e2d2c(uVar9,1)', 'FUN_001e2d2c(uVar9,0)'],
        'disconnect': ['FUN_001e2d2c(local_48,0)','FUN_001e2838','FUN_001ec290','FUN_001bfa3c'],
        'login_gate': ['FUN_001e2c04','FUN_001eb278'],
        'gated_close': ['FUN_001e2c04','(uVar6 & 1) == 0'],
        'send_gate': ['FUN_001e2c04','uVar18 = 0xcb'],
        'connect_poll_a': ['+ 0x2a5'], 'connect_poll_b': ['+ 0x2a5'],
        'logout': ['local_f0 = 3','FUN_001eb5a4','puVar6 + 0x120','puVar6 + 0x110','puVar6 + 0x118','FUN_001e2ea0'],
        'is_content_ws': ['FUN_001e2c04','FUN_001b3f34'],
    }
    for name, p in NATIVE_SOURCE.items():
        refs = [r for needle in needles[name] for r in hits(p, needle)]
        source_groups[name] = {'file': str(p), 'sha256': sha(p), 'line_count': len(p.read_text().splitlines()),
                               'evidence': sorted({r['line']: r for r in refs}.values(), key=lambda r:r['line'])}
    methods = [extract_dart(*x) for x in DART_METHODS]
    boundary_methods = [m for m in methods if m['name'] != 'explicit_logout_button']
    ws_targets = {'0x4a8418'}
    assert not any(c['target'] in ws_targets for m in boundary_methods for c in m['direct_calls'])
    assert any(c['target'] == '0x4a8418' for c in methods[-1]['direct_calls'])
    auth_failure = NATIVE_SOURCE['inbound'].read_text().splitlines()[530:553]
    assert any('FUN_001e2d2c(uVar9,0)' in s for s in auth_failure)
    assert not any('0x2b1' in s or 'FUN_001e2ea0' in s for s in auth_failure)
    for name in ['disconnect','gated_close']:
        text = NATIVE_SOURCE[name].read_text()
        assert '0x2b1' not in text and 'FUN_001e2ea0' not in text
    matrix = [
        {'event':'SDK lazy initialization', 'transport':0, 'auth':0, 'reason':'two halfword zero stores include each flag byte', 'raw_addresses':['0xdbd8c','0xdbd94']},
        {'event':'transport connect success (two async polls)', 'transport':1, 'auth':'unchanged', 'reason':'socket sender install occurs after transport=true; no auth write in either complete poll', 'raw_addresses':['0xa6dc8','0xa75dc','0xd4330','0xd4d30']},
        {'event':'transport connect error/disconnect poll cleanup', 'transport':0, 'auth':'unchanged in these complete functions', 'raw_addresses':['0xa70f4','0xa74f8','0xd466c','0xd4c7c']},
        {'event':'types=50 parsed login response code=0', 'transport':1, 'auth':1, 'reason':'auth=true is performed twice, each with a lock fallback; then transport setter(1)', 'raw_addresses':['0xea510','0xea600','0xea958','0xea9c8','0xea6f0']},
        {'event':'types=50 parsed login response code!=0', 'transport':0, 'auth':'unchanged in this branch and audited cleanup helpers', 'reason':'gated close, stop relogin, transport setter(0); no fullstop', 'raw_addresses':['0xea3e0']},
        {'event':'internal disconnect callback', 'transport':0, 'auth':'unchanged in complete 0xeab5c and audited cleanup helpers', 'reason':'transport setter(0), stop heartbeat/QoS, schedule relogin; no fullstop', 'raw_addresses':['0xeac00']},
        {'event':'full local stop', 'transport':0, 'auth':0, 'reason':'transport setter(0), multiple workers stopped, auth write=false', 'raw_addresses':['0xe2ebc','0xe2f30','0xe2fa4']},
        {'event':'public wsLogout poll', 'transport':0, 'auth':0, 'reason':'try types3 send; clear saved JWT; call fullstop', 'raw_addresses':['0xced44','0xcee1c']},
        {'event':'server types=54 response', 'transport':0, 'auth':0, 'reason':'calls fullstop', 'raw_addresses':['0xe9fe0']},
    ]
    # Complete source-local negative evidence, deliberately not a dynamic/global impossibility claim.
    payload = {
        'scope':'Only static local APK/ELF/AOT inspection. Original inputs unchanged. No target execution, backend requests, live state or private data.',
        'address_convention':{'Rust':'ELF VA = Ghidra address - 0x100000','Dart':'AOT addresses = ELF VA'},
        'fields':[
            {'name':'transport flag (descriptive reconstructed name)', 'sdk_offset':'0x2a5','lock_offset':'0x29c','poison_offset':'0x2a4','getter_elf':'0xe2c04','setter_elf':'0xe2d2c'},
            {'name':'authenticated flag (descriptive reconstructed name)', 'sdk_offset':'0x2b1','lock_offset':'0x2a8','poison_offset':'0x2b0','read_status':'No value-read found by this exact-offset disassembly and exported SDK-path audit. Lock/poison reads are not auth-value reads.'},
        ],
        'state_matrix':matrix,
        'is_content_ws':{'fact':'normal bool result uses transport getter only; no auth read and no host input',
            'body_elf':'0xb8348','getter_call_elf':'0xb8384','delegated_complete_bridge_audit':str(BASE/'analysis/connection_preview_closure/is_content_ws'),
            'independence':'transport=true can be reached by connect polls before a types50 success; auth may remain1 after ordinary disconnect while transport is0. These are static reachable assignments, not observed runtime traces.'},
        'field_access_inventory':{
            'method':'All executable LLVM -d output scanned for exact #0x2a5/#0x2b1 immediates; alias loads tied to preceding ADD and constructor overlapping STRH separately included. Existing per-function C exports cross-checked, deduplicated by function name.',
            'limit':'Exact immediate scan cannot alone prove absence under arbitrary pointer aliases or indirect paths; SDK function context and complete cleanup bodies supply finite confirmation.',
            'direct_offset_candidates':immediate_inventory,'alias_value_reads':aliases,'initialization_overlapping_stores':init,
            'runtime_store_counts':{'transport':10,'auth':6},'exact_offset_auth_value_load_count':0,
        },
        'getter_setter_fullstop_direct_bl_inventory':calls,
        'source_groups':source_groups,
        'native_raw_checks':native_checks,
        'key_instruction_checks':key,
        'end_preview_boundary':{
            'fact':'endPreview immediately clears PreviewService currentDeviceId, converts passed id to string, POSTs /api/preview/end_preview/<id> and returns its Future; no data argument is supplied.',
            'examined_method_count':len(boundary_methods),'methods':methods,
            'negative_result':'No direct wsLogout BL target 0x4a8418 or annotated native stop/wsLogout call in the seven audited complete Dart methods. endPreview direct calls are string concatenation, HttpClient.post and runtime stubs; two business callers only register then/return or Navigator.pop.',
            'positive_control':'Separate Main explicit logout button 0x4a83b0 directly calls wsLogout at0x4a83c8 then navigates to LoginPage.',
            'limits':['Not an exhaustive Dart indirect dispatch/callback graph.','Shared end Future callback0x6f2a58 is not a complete distinguish method in current AOT dump.','Dio interceptor/navigation effects and server consequences were not assumed absent.','No backend implementation or received logout acknowledgement is available.','No claim that every route exit, 401 navigation or disposal cannot eventually cause another action.'],
        },
        'verification':{
            'all_native_words_checked':len(all_records),'direct_offset_candidates':len(immediate_inventory),
            'alias_loads':len(aliases),'overlapping_initializer_instructions':len(init),
            'runtime_stores':len(writes),'getter_setter_fullstop_bl_count':len(calls),
            'native_selected_words_checked':len(native_checks),'dart_selected_words_checked':sum(len(m['raw_checks']) for m in methods),
            'selected_bl_targets_checked':sum('bl_target'in x for x in native_checks)+sum('bl_target'in x for m in methods for x in m['raw_checks']),
            'status':'passed: original ELF words/VA mapping/BL sign decoding, source-local branch checks, exact field inventory, seven-method bounded direct-call test and positive control',
        },
    }
    (OUT/'state_audit.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    input_files = list(NATIVE_SOURCE.values())+[DART_ROOT/r for _,r,_ in DART_METHODS]+[RUST,DART,Path(__file__).resolve()]
    manifest = {'inputs':[{'file':str(p),'sha256':sha(p)} for p in sorted(set(input_files))],
                'artifacts':[{'file':str(p),'sha256':sha(p)} for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='source_manifest.json']}
    (OUT/'source_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(payload['verification'],ensure_ascii=False))


if __name__ == '__main__':
    main()
