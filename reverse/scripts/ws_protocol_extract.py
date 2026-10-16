#!/usr/bin/env python3
"""Build an evidence-backed WebSocket catalog from local static artifacts.

Only reads the target ELF and existing Ghidra/AOT output. LLVM disassembles bytes;
the APK/native library is never loaded or executed. Outputs are analyst
reconstructions and synthetic examples, not captured traffic or original source.
"""

from _paths import app_root, workspace_root
import copy
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

APP = app_root()
OUT = APP / 'analysis/ws_protocol'
RUST = APP / 'analysis/deep_rust'
LOGIN = APP / 'analysis/login_flow'
LIB = APP / 'unpacked/lib/arm64-v8a/librust_lib_distinguish.so'
LLVM = Path('/opt/homebrew/opt/llvm/bin/llvm-objdump')
BASE = 0x100000
EVIDENCE = {}
INPUTS = {}


def read(path):
    data = path.read_bytes()
    INPUTS[str(path)] = hashlib.sha256(data).hexdigest()
    return data.decode('utf-8')


def load(path):
    return json.loads(read(path))


def ref(path, needle, occurrence=0, ghidra=None):
    lines = read(path).splitlines()
    hits = [(i, s) for i, s in enumerate(lines, 1) if needle in s]
    assert len(hits) > occurrence, (path, needle)
    line, excerpt = hits[occurrence]
    entry = {'file': str(path), 'line': line, 'excerpt': excerpt.strip(),
             'sha256': INPUTS[str(path)]}
    if ghidra:
        entry.update(ghidra_address=hex(ghidra), elf_virtual_address=hex(ghidra - BASE))
    return entry


def fn(number, stage='functions'):
    return RUST / stage / f'{number:08x}.c'


def add(name, refs, meaning):
    EVIDENCE[name] = {'claim': meaning, 'references': refs}
    return name


def va_offset(data, address):
    phoff = struct.unpack_from('<Q', data, 32)[0]
    entsize, count = struct.unpack_from('<HH', data, 54)
    for i in range(count):
        typ, _, off, va, _, fs, _, _ = struct.unpack_from('<IIQQQQQQ', data, phoff + i * entsize)
        if typ == 1 and va <= address < va + fs:
            return off + address - va
    raise ValueError(hex(address))


def raw_word(data, address):
    off = va_offset(data, address)
    return struct.unpack_from('<I', data, off)[0]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = LIB.read_bytes()
    INPUTS[str(LIB)] = hashlib.sha256(data).hexdigest()
    ranges = [
        ('protocol_default_and_type1_and_ack_constructors', 0xc5ce4, 0xc5f44),
        ('business_inner_forwarding', 0xc5f58, 0xc6214),
        ('named_key_recognizer_and_serializer', 0xc6ba4, 0xc6e5c),
        ('protocol_parser_and_trailing_input_check', 0xc6fc0, 0xc7148),
        ('protocol_deserializer', 0xcae5c, 0xcc21c),
        ('logout_protocol_constructor_binding', 0xcec94, 0xced48),
        ('inbound_dispatch_and_qos', 0xe99a0, 0xea030),
        ('remaining_dispatch', 0xea030, 0xea330),
        ('login_constructor', 0xeb278, 0xeb398),
        ('heartbeat_sender_constructor_binding', 0xeb3d4, 0xeb530),
        ('generic_send_and_qos_tracking', 0xeb5a4, 0xeb7e0),
        ('serialization_to_socket_queue', 0xeb854, 0xebf18),
        ('received_ack_fingerprint_lookup', 0xe0cf4, 0xe10b8),
        ('uuid_hyphenated_formatter', 0x10a120, 0x10a328),
        ('uuid_random_version_variant_bits', 0x10a4a4, 0x10a5b0),
    ]
    chunks = []
    for label, start, end in ranges:
        result = subprocess.run([str(LLVM), '-d', f'--start-address={hex(start)}',
                                 f'--stop-address={hex(end)}', str(LIB)],
                                check=True, capture_output=True, text=True)
        chunks.append(f'// RANGE {label}: ELF {hex(start)}..{hex(end)} exclusive\n' + result.stdout)
    raw_path = OUT / 'raw_protocol_instructions.asm.txt'
    raw_path.write_text('\n'.join(chunks))
    raw_text = raw_path.read_text()

    def rawref(address, expected_text=None, expected_word=None):
        pattern = re.compile(r'^\s*' + f'{address:x}' + r':\s+([0-9a-f]{8})\s+(.+)$', re.M)
        hit = pattern.search(raw_text)
        assert hit, hex(address)
        word = raw_word(data, address)
        assert int(hit.group(1), 16) == word
        if expected_word is not None:
            assert word == expected_word, (hex(address), hex(word), hex(expected_word))
        if expected_text is not None:
            assert expected_text in hit.group(2), (hex(address), hit.group(2), expected_text)
        entry = ref(raw_path, hit.group(0).strip())
        off = va_offset(data, address)
        entry.update(elf_virtual_address=hex(address), ghidra_address=hex(address + BASE),
                     file_offset=hex(off), raw_bytes_hex=data[off:off+4].hex())
        return entry

    serializer = fn(0x1c6ce0)
    parser = fn(0x1cae5c)
    recognizer = fn(0x1c6ba4)
    dispatch = fn(0x1e99a0, 'lifecycle/functions')
    default = fn(0x1c5ce4, 'lifecycle/functions')
    ack = fn(0x1c5e50, 'lifecycle/functions')
    send = fn(0x1eb854, 'lifecycle/functions')
    generic = fn(0x1eb5a4)
    ack_in = fn(0x1e0cf4, 'lifecycle/functions')
    business = fn(0x1c5f58, 'lifecycle/functions')
    native = load(LOGIN / 'native_login_flow.json')
    old_layout = load(RUST / 'protocol_layout.json')
    inner_mapping = load(APP / 'analysis/message_semantics/msg_type_mapping.json')
    inner_schema = load(APP / 'analysis/message_semantics/payload.schema.json')
    assert native['library']['sha256'] == INPUTS[str(LIB)]
    assert old_layout['library_sha256'] == INPUTS[str(LIB)]

    add('outer_serialization', [ref(serializer, '"types",5,param_1 + 0x60', ghidra=0x1c6ce0),
        ref(serializer, 'lVar6 == 0 ||', ghidra=0x1c6ce0),
        ref(serializer, '"to",2,param_1 + 0x30', ghidra=0x1c6ce0),
        ref(serializer, '"fp",2,param_1 + 0x48', ghidra=0x1c6ce0),
        ref(serializer, '"qos",3,param_1 + 0x68', ghidra=0x1c6ce0)],
        'Exactly six named fields, fixed output order; empty String fields omitted; types and qos always written.')
    add('string_json_encoding', [ref(fn(0x1acba4), 'FUN_001ad2e4(*puVar5,uVar3,uVar1)', ghidra=0x1acba4),
        ref(fn(0x1accb4), '0x736c6166', ghidra=0x1accb4),
        ref(fn(0x1accb4), '0x65757274', ghidra=0x1accb4)],
        'String fields use JSON string encoding; qos is JSON false/true, not an integer/string.')
    add('native_defaults', [ref(default, 'FUN_0020a070(param_1 + 9', ghidra=0x1c5ce4),
        ref(default, 'param_1[0xc] = 0', ghidra=0x1c5ce4),
        rawref(0xc5d24, 'strb\twzr'), rawref(0xc5d28, 'str\txzr')],
        'Default constructor generates UUID fp, empty data_content/from/to, types=0 and qos=false.')
    add('named_key_ids', [ref(recognizer, '0x6f74', ghidra=0x1c6ba4),
        ref(recognizer, '0x7066', ghidra=0x1c6ba4),
        ref(recognizer, '0x6d6f7266', ghidra=0x1c6ba4),
        ref(recognizer, '0x6e6f635f61746164', ghidra=0x1c6ba4),
        ref(recognizer, '0x65707974', ghidra=0x1c6ba4),
        ref(recognizer, '+ 1) = 6', ghidra=0x1c6ba4)],
        'Named decoder IDs: types0,data_content1,from2,to3,fp4,qos5; unrecognized key ID6.')
    add('inbound_defaults', [ref(parser, 'if (puVar17 == (undefined1 *)0x0)', ghidra=0x1cae5c),
        ref(parser, 'local_184 = 0', ghidra=0x1cae5c),
        ref(parser, 'bVar9 = bVar9 & 1', ghidra=0x1cae5c)],
        'Named object path assigns missing types=0, strings empty, qos=false. Empty inbound fp is not regenerated.')
    add('inbound_unknown_and_duplicate', [ref(parser, 'auVar26 = FUN_001c960c(param_2)', ghidra=0x1cae5c),
        ref(parser, 'FUN_001e8478(local_160,uVar5)', ghidra=0x1cae5c),
        ref(parser, 'if (bVar9 != 2)', ghidra=0x1cae5c)],
        'Unknown named values go to a JSON skip-value decoder; duplicate known fields reach an error constructor. Schema cannot model duplicate JSON keys.')
    add('inbound_trailing_and_sequence', [ref(fn(0x1c6fc0, 'lifecycle/functions'), 'local_78[0] = 0x16', ghidra=0x1c6fc0),
        ref(parser, 'if (bVar9 == 0x5b)', ghidra=0x1cae5c)],
        'After decoding, trailing non-whitespace is rejected. A sequence/array decoder path also exists; this catalog schemas the confirmed named JSON-object output only.')

    raw_type_checks = []
    for value, addr in [(2, 0xe9e74), (4, 0xe9e80), (50, 0xe9e88),
                        (51, 0xe9f40), (52, 0xe9f48), (54, 0xe9f50)]:
        raw_type_checks.append(rawref(addr, f'cmp\tw8, #{hex(value)}',
                                      0x71000000 | (value << 10) | (8 << 5) | 31))
    add('outer_receive_type_comparisons', raw_type_checks,
        'Raw ARM64 comparisons verify inbound types 2,4,50,51,52,54. These are ordinary i32 values, not Dart Smi.')
    add('type1_constructor', [rawref(0xc5d70, 'ldr\tq0, [x20]'),
        rawref(0xc5d78, 'mov\tw21, #0x1', 0x52800035),
        rawref(0xc5d90, 'stur\tq0, [sp, #0x18]'),
        rawref(0xc5db0, 'mov\tw8, #0x9ff0'), rawref(0xc5db4, 'movk\tw8, #0x9392'),
        rawref(0xc5db8, 'str\tw21, [sp, #0x60]'), rawref(0xc5dbc, 'str\tw8, [x0]')],
        'Constructor ELF0xc5d3c: types=1, data_content four UTF-8 bytes f09f9293 (💓), from=input String, to empty, fresh UUID fp, qos=false.')
    heartbeat_send = APP / 'analysis/ws_heartbeat/native_pseudocode/functions/001eb3d4.c'
    heartbeat_worker = APP / 'analysis/ws_heartbeat/native_pseudocode/functions/001e1110.c'
    add('heartbeat_sender_binding', [ref(heartbeat_worker, 'FUN_001eb3d4()', ghidra=0x1e1110),
        ref(heartbeat_send, 'FUN_00290ab4(local_40,puVar5 + 0x160', ghidra=0x1eb3d4),
        ref(heartbeat_send, 'FUN_001c5d3c(&local_b0', ghidra=0x1eb3d4),
        ref(heartbeat_send, 'FUN_001eb854(&local_b0)', ghidra=0x1eb3d4),
        rawref(0xeb438, 'add\tx0, x20, #0x160'), rawref(0xeb458, 'bl\t0xc5d3c'),
        rawref(0xeb460, 'bl\t0xeb854')],
        'Heartbeat worker0x1e1110 ->sender0x1eb3d4 ->types1 constructor0x1c5d3c ->direct sender0x1eb854; from copies SDK saved String at+0x160. Timing is outside this catalog.')
    add('type6_login_constructor', [ref(fn(0x1eb278, 'lifecycle/functions'), 'local_40 = 6', ghidra=0x1eb278),
        ref(fn(0x1eb278, 'lifecycle/functions'), 'uVar1 = FUN_001eb854', ghidra=0x1eb278),
        rawref(0xeb32c, 'mov\tw9, #0x6', 0x528000c9), rawref(0xeb334, 'stur\tw9, [x29, #-0x10]')],
        'Login copies wsLogin String unchanged into data_content, sets types6 and calls direct sender.')
    logout_poll = APP / 'analysis/ws_heartbeat/native_pseudocode/functions/001cec94.c'
    add('type3_logout_constructor', [ref(logout_poll, 'FUN_001c5ce4(&local_150)', ghidra=0x1cec94),
        ref(logout_poll, 'local_f0 = 3', ghidra=0x1cec94),
        ref(logout_poll, 'FUN_001eb5a4(&local_e0)', ghidra=0x1cec94),
        ref(logout_poll, 'FUN_001e2ea0(local_68)', ghidra=0x1cec94),
        rawref(0xced10, 'add\tx8, sp, #0x20'), rawref(0xced14, 'bl\t0xc5ce4'),
        rawref(0xced1c, 'mov\tw8, #0x3', 0x52800068), rawref(0xced20, 'str\tw8, [sp, #0x80]'),
        rawref(0xced40, 'sub\tx0, x29, #0x80'), rawref(0xced44, 'bl\t0xeb5a4')],
        'Logout async worker initializes Protocol at sp+0x20, stores types3 at sp+0x80 (Protocol+0x60), passes to generic sender, then performs stop/cleanup. Content/from/to empty, fresh UUID fp, qosfalse from default constructor.')
    add('outgoing_ack_constructor', [ref(ack, 'param_2 + 0x30', ghidra=0x1c5e50),
        ref(ack, 'param_2 + 0x18', ghidra=0x1c5e50),
        ref(ack, 'param_2 + 0x48', ghidra=0x1c5e50),
        ref(ack, 'CONCAT44(local_50._4_4_,4)', ghidra=0x1c5e50),
        rawref(0xc5eac, 'add\tx0, x20, #0x30'), rawref(0xc5ed0, 'add\tx0, x20, #0x18'),
        rawref(0xc5ef4, 'add\tx0, x20, #0x48'), rawref(0xc5efc, 'mov\tw9, #0x4', 0x52800089),
        rawref(0xc5f08, 'str\tw9, [sp, #0x60]')],
        'Generated ACK swaps from/to; data_content=received.fp; ACK fp is a newly generated UUID; types4,qosfalse.')
    add('inbound_ack_uses_outer_fp', [ref(ack_in, 'lVar2 = param_2 + 0x48', ghidra=0x1e0cf4),
        ref(ack_in, 'FUN_001cde9c(&local_f0', ghidra=0x1e0cf4),
        ref(ack_in, 'FUN_001cdcb8(&local_f0', ghidra=0x1e0cf4),
        rawref(0xe0d50, 'add\tx21, x1, #0x48'), rawref(0xe0d78, 'mov\tx2, x21'),
        rawref(0xe0d7c, 'bl\t0xcde9c'), rawref(0xe0e20, 'mov\tx2, x21'),
        rawref(0xe0e24, 'bl\t0xcdcb8')],
        'Received types4 handler removes entries in two outbound QoS structures using received ACK.fp, not data_content. Outbound/inbound ACK association is asymmetric in inspected code.')
    add('generic_send_qos_tracking', [ref(generic, 'iVar2 = FUN_001eb854', ghidra=0x1eb5a4),
        ref(generic, "((char)param_1[0xd] == '\\x01')", ghidra=0x1eb5a4),
        ref(generic, 'FUN_001e0480(local_60 + 0x1f8,param_1 + 9)', ghidra=0x1eb5a4),
        ref(generic, 'FUN_001e06c4(local_60 + 0x1f8', ghidra=0x1eb5a4)],
        'Generic Protocol sender first sends a clone, then after local success and qos=true records original Protocol by fp if absent. Direct login send bypasses this wrapper.')
    add('socket_queue', [ref(send, 'iVar15 = FUN_001e2c04', ghidra=0x1eb854),
        ref(send, 'uVar18 = 0xcb', ghidra=0x1eb854),
        ref(send, 'FUN_001c6ce0(param_1', ghidra=0x1eb854),
        ref(send, 'FUN_001b3bf8(&local_120', ghidra=0x1eb854),
        ref(send, 'uVar18 = 3', ghidra=0x1eb854)],
        'Sender gates connection state, serializes JSON and enqueues socket text. Local results include0(success),203(initial gate false),3(final failure); they are not server authentication codes.')
    add('inbound_qos_order', [ref(dispatch, 'if ((uStack_228 & 1) == 0)', ghidra=0x1e99a0),
        ref(dispatch, 'FUN_001de924(ppppppuVar1 + 0x10', ghidra=0x1e99a0),
        ref(dispatch, 'FUN_001de38c(ppppppuVar1 + 0x10', ghidra=0x1e99a0),
        ref(dispatch, 'FUN_001c5e50(&local_1b0,&local_220)', ghidra=0x1e99a0),
        ref(dispatch, 'FUN_001eb5a4(&local_1b0)', ghidra=0x1e99a0)],
        'Inbound qos=true checks fp in receive tracking. Fresh fingerprint records, ACKs then dispatches; duplicate fingerprints ACK then drop. qos=true types50 has a preliminary code check; nonzero bypasses this ACK block.')
    add('inner_business_forwarding', [ref(business, 'FUN_001c7178(&local_e0', ghidra=0x1c5f58),
        ref(business, 'FUN_002092a4("msg_type",8', ghidra=0x1c5f58),
        ref(business, 'iVar2 - 0x71U < 5', ghidra=0x1c5f58),
        ref(business, 'iVar2 != 0x65', ghidra=0x1c5f58),
        ref(business, 'iVar2 != 0x66', ghidra=0x1c5f58),
        ref(business, 'local_90 = 4', ghidra=0x1c5f58),
        ref(business, 'FUN_001ec7f0(&local_c0)', ghidra=0x1c5f58)],
        'types2 parses data_content JSON, tests integer msg_type101/102/113..117, forwards original string in WsEvent integer4. Other inner msg_type do not forward here.')
    add('uuid_generation', [ref(fn(0x20a4a4, 'stage2/functions'), 'FUN_0024bb24(&local_70,0x10)', ghidra=0x20a4a4),
        ref(fn(0x20a4a4, 'stage2/functions'), '0xffffffffffffff3f | 0x80', ghidra=0x20a4a4),
        ref(fn(0x20a4a4, 'stage2/functions'), '0xff0fffffffffffff | 0x40000000000000', ghidra=0x20a4a4),
        rawref(0x10a140, 'mov\tw10, #0x2d'), rawref(0x10a278, 'mov\tw2, #0x24')],
        'fp generation reads16 random bytes, sets UUID v4/variant bits, formats36 lowercase hex characters with 8-4-4-4-12 hyphen groups. Inbound fp remains unrestricted String.')
    hexoff = va_offset(data, 0x44250)
    assert data[hexoff:hexoff+16] == b'0123456789abcdef'
    add('uuid_hex_alphabet', [{'file': str(LIB), 'sha256': INPUTS[str(LIB)],
        'elf_virtual_address': '0x44250', 'file_offset': hex(hexoff),
        'bytes_hex': data[hexoff:hexoff+16].hex(), 'excerpt': '0123456789abcdef'}],
        'Raw lowercase UUID hexadecimal lookup alphabet, independently checked in ELF bytes.')
    add('internal_offset64_zero', [rawref(0xc5d28, 'str\txzr, [x19, #0x60]'),
        rawref(0xc5d8c, 'str\txzr, [sp, #0x60]'), rawref(0xc5db8, 'str\tw21, [sp, #0x60]'),
        rawref(0xc5e9c, 'str\txzr, [sp, #0x60]'), rawref(0xc5f08, 'str\tw9, [sp, #0x60]'),
        rawref(0xeb310, 'bl\t0xc5ce4'), rawref(0xeb334, 'stur\tw9, [x29, #-0x10]')],
        'There is an additional internal32-bit slot+0x64, initialized zero by constructors, copied beside types. It is not a named JSON field in inspected serializer; retry use is analyzed separately.')

    fields = []
    for f in old_layout['fields']:
        field = copy.deepcopy(f)
        field.update(status='confirmed_static', evidence=['outer_serialization', 'named_key_ids'])
        key = f['json_key']
        field['inbound_missing_default'] = 0 if key == 'types' else False if key == 'qos' else ''
        field['outbound_presence'] = 'always' if key in ('types', 'qos') else 'only when nonempty'
        fields.append(field)
    types = [
        {'types': 1, 'direction': 'send_constructor', 'meaning': '心跳请求',
         'status': 'confirmed_static', 'ghidra_entry': '0x1c5d3c',
         'data_content': {'representation': 'String', 'known_value': '💓'},
         'from': 'SDK saved String+0x160 copied into constructor input', 'to': 'empty/omitted', 'qos': False,
         'fp': 'fresh UUID v4 String', 'evidence': ['type1_constructor', 'heartbeat_sender_binding', 'uuid_generation']},
        {'types': 2, 'direction': 'receive', 'meaning': '业务消息', 'status': 'confirmed_static',
         'ghidra_handler': '0x1c5f58', 'data_content': {'representation': 'JSON serialized inside String',
         'known_inner_msg_types': [101,102,113,114,115,116,117]},
         'evidence': ['outer_receive_type_comparisons','inner_business_forwarding']},
        {'types': 3, 'direction': 'send', 'meaning': '客户端主动退出请求', 'status': 'confirmed_static',
         'ghidra_constructor_and_send': '0x1cec94', 'data_content': {'representation': 'empty/omitted'},
         'from':'empty/omitted','to':'empty/omitted','qos':False,'fp':'fresh UUID v4 String',
         'evidence':['type3_logout_constructor','native_defaults'],
         'limit':'wsLogout bridge-to-worker association is documented in the independent lifecycle audit; local queueing does not establish a server response.'},
        {'types': 4, 'direction': 'send_and_receive', 'meaning': 'QoS ACK', 'status': 'confirmed_static',
         'ghidra_constructor': '0x1c5e50', 'ghidra_handler': '0x1e0cf4',
         'data_content': {'outbound': 'received.fp (opaque String)',
                          'inbound_handler': 'not used by inspected handler'},
         'qos_outbound': False, 'outbound_fp': 'fresh UUID v4 String',
         'inbound_matching_key': 'ACK outer fp',
         'evidence': ['outgoing_ack_constructor','inbound_ack_uses_outer_fp']},
        {'types': 6, 'direction': 'send', 'meaning': '登录请求', 'status': 'confirmed_static',
         'ghidra_constructor': '0x1eb278',
         'data_content': {'representation': 'raw wsLogin input String; actual Dart input is JWT',
                          'extra_json_parse_in_native_constructor': False},
         'from': 'empty/omitted', 'to': 'empty/omitted', 'qos': False,
         'fp': 'fresh UUID v4 String', 'evidence': ['type6_login_constructor','native_defaults']},
        {'types': 50, 'direction': 'receive', 'meaning': '登录响应', 'status': 'confirmed_static',
         'ghidra_handler': '0x1c6e5c ->0x1ca468',
         'data_content': {'representation': 'JSON serialized inside String',
             'inner_fields': {'code': 'required i32', 'user_id': 'required String', 'data': 'required String'}},
         'behavior': 'code0 success branch; nonzero failure. user_id/data not confirmed forwarded to Flutter.',
         'evidence': ['outer_receive_type_comparisons'],
         'upstream_evidence_refs': ['login_response_parser','login_response_required_user_id','login_response_required_data','response_code_zero_branch']},
        {'types': 51, 'direction': 'receive', 'meaning': '心跳响应', 'status': 'confirmed_static',
         'data_content': {'representation': 'not read in inspected handler'},
         'behavior': 'Reads local current time, converts to epoch seconds, stores heartbeat timestamp; scheduling analyzed separately.',
         'evidence': ['outer_receive_type_comparisons']},
        {'types': 52, 'direction': 'receive', 'meaning': '服务端错误分支', 'status': 'confirmed_static_branch; payload_unknown',
         'data_content': {'representation': 'unknown contract; no payload consumer established here'},
         'evidence': ['outer_receive_type_comparisons']},
        {'types': 54, 'direction': 'receive', 'meaning': '服务端被踢指令/清理连接', 'status': 'confirmed_static',
         'ghidra_handler': '0x1e2ea0', 'data_content': {'representation': 'not forwarded to confirmed Flutter event encoder here'},
         'evidence': ['outer_receive_type_comparisons']},
    ]
    for key in ('login_response_parser','login_response_required_user_id','login_response_required_data','response_code_zero_branch'):
        upstream = native['evidence_index'][key]
        path = Path(upstream['file'])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == upstream['sha256']
        add(key, [ref(path, upstream['locator'], ghidra=int(upstream['ghidra_address'],16))],
            'Previously audited native login evidence, locator and file hash independently rechecked.')

    catalog = {
        'title': '本 APK WebSocket 外层 Protocol 静态重建',
        'library': {'file': str(LIB), 'sha256': INPUTS[str(LIB)]},
        'addressing': {'ghidra_image_base': hex(BASE), 'conversion': 'Ghidra=ELF virtual address+0x100000; do not mix Rust and Dart addresses.'},
        'status_meaning': {'confirmed_static': 'Read in original raw instructions and/or exact named Ghidra decoder/serializer paths',
                           'reconstructed': 'Analyst description or synthesized representation; not original source',
                           'unknown': 'Not established by inspected paths'},
        'outer_fields': fields, 'serialization_order': ['types','data_content','from','to','fp','qos'],
        'internal_non_json_slot': {'offset':'0x64','observed_width':'32 bits','constructor_initial_value':0,
            'original_name':None,'serialized':False,'evidence':['internal_offset64_zero'],
            'limit':'Retry-counter use belongs to independent lifecycle audit; do not add a JSON field from memory layout.'},
        'serialization': {'format': 'compact JSON text', 'string_encoding': 'JSON quoted/escaped Strings',
            'inbound': {'missing_defaults': 'types0; strings empty; qosfalse', 'unknown_named_fields': 'skip JSON value',
                        'duplicate_known_fields': 'error path', 'trailing_non_whitespace': 'error',
                        'array_path': 'Observed decoder branch; complete array contract excluded from schemas.'},
            'not_wire_offsets': 'Memory offsets are build-specific Rust layout, not byte positions in JSON.'},
        'message_types': types,
        'inner_business_catalog': [{k:v for k,v in e.items() if k in ('msg_type','semantic_label','payload','processing_order')}
                                   for e in inner_mapping['entries']],
        'layer_distinction': {'outer_protocol_types': [1,2,3,4,6,50,51,52,54],
            'inner_msg_type': [101,102,113,114,115,116,117], 'flutter_event_integer_for_business': 4,
            'clarification': 'Outer ACK types4 and WsEvent integer4 are unrelated fields. wsLogin wrapper4/send0/3/203/server code are separate values.'},
        'qos_fingerprint': {'fp_role': 'Message fingerprint used for receive deduplication and outbound tracking; not established as user/device hardware fingerprint.',
            'generation': 'Random UUID v4, lowercase hyphenated36-character String in inspected constructors.',
            'incoming_type': 'String, no UUID-shape validation established.',
            'ack_outgoing': {'types':4,'data_content':'received.fp','from':'received.to','to':'received.from','fp':'new UUID','qos':False},
            'ack_incoming_lookup': 'received ACK.fp, not ACK.data_content',
            'asymmetry': 'Do not assume server ACK uses the client outgoing-ACK recipe. No traffic/server source was examined.',
            'evidence': ['outgoing_ack_constructor','inbound_ack_uses_outer_fp','inbound_qos_order','generic_send_qos_tracking']},
        'send_entrypoints': [
            {'name': 'generic Protocol sender (analyst name)', 'ghidra': '0x1eb5a4', 'elf': '0xeb5a4',
             'chain': 'clone Protocol ->0x1eb854 ->0x1c6ce0 ->socket queue0x1b3bf8; qos=true adds fp tracking on local success',
             'evidence': ['generic_send_qos_tracking','socket_queue']},
            {'name':'wsLogin','dart':'0x4ab08c','ghidra':'0x1eb278','chain':'Dart FRB String ->saved native input ->types6 ->direct sender0x1eb854',
             'evidence':['type6_login_constructor'], 'upstream_artifact': str(LOGIN / 'native_login_flow.json')},
            {'name':'automatic ACK','ghidra':'0x1c5e50','chain':'receive qos handling0x1e99a0 ->ACK constructor ->generic sender0x1eb5a4',
             'evidence':['inbound_qos_order','outgoing_ack_constructor']},
            {'name':'types1 heartbeat','ghidra':'0x1c5d3c','chain':'heartbeat worker0x1e1110 ->0x1eb3d4 ->0x1c5d3c ->0x1eb854',
             'evidence':['type1_constructor','heartbeat_sender_binding'], 'limit':'Timing belongs to separate lifecycle audit.'},
            {'name':'wsLogout','ghidra':'0x1cec94','chain':'wsLogout bridge/async workers (separate lifecycle audit) ->poll0x1cec94 ->default Protocol ->types3 ->generic sender0x1eb5a4 ->cleanup0x1e2ea0',
             'evidence':['type3_logout_constructor'],'upstream_artifact': str(APP / 'analysis/ws_heartbeat')}],
        'unknowns': ['No complete original Rust protocol enum/source recovered; values outside catalog may exist.',
                    'No generic Dart business-send API was established in inspected simple.dart AOT methods.',
                    'from/to are routing Strings; constructors show swaps/input copy, not universal user/device identity semantics.',
                    'types52/54 payload contracts unknown; receiving branch existence does not imply a specific content schema.',
                    'Schemas describe static receiver/serializer constraints, not backend validation rules.',
                    'WebSocket frame masking/opcodes and heartbeat/reconnection timing are outside this task.'],
        'evidence_ids': list(EVIDENCE),
        'static_only': True, 'examples_are_synthetic': True,
    }

    schema_props = {
        'types': {'type':'integer','minimum':-2147483648,'maximum':2147483647,'default':0},
        'data_content': {'type':'string','default':'','description':'String; some types carry JSON text inside it.'},
        'from': {'type':'string','default':''}, 'to': {'type':'string','default':''},
        'fp': {'type':'string','default':'','description':'Incoming String; inspected outgoing constructors generate UUIDv4.'},
        'qos': {'type':'boolean','default':False},
    }
    inbound_schema = {'$schema':'https://json-schema.org/draft/2020-12/schema',
        'title':'Protocol inbound named-object path (static reconstruction)', 'type':'object',
        'properties':copy.deepcopy(schema_props), 'additionalProperties':True,
        '$comment':'Defaults describe native missing-field behavior but JSON Schema does not apply defaults. Duplicate known JSON keys/trailing data are rejected by native decoder, outside this object schema. Decoder also has array path; excluded here.'}
    outbound_schema = {'$schema':'https://json-schema.org/draft/2020-12/schema',
        'title':'Protocol outbound serializer shape (static reconstruction)', 'type':'object',
        'properties':copy.deepcopy(schema_props), 'required':['types','qos'], 'additionalProperties':False,
        'x-serialization-order':catalog['serialization_order'],
        '$comment':'Empty String fields omitted by inspected serializer. Type enumeration deliberately not closed.'}
    for key in ('data_content','from','to','fp'):
        outbound_schema['properties'][key]['minLength'] = 1
        outbound_schema['properties'][key].pop('default',None)
    login_schema = load(RUST / 'login_response.schema.json')
    login_schema['x-evidence'] = [EVIDENCE[k]['references'][0] for k in
        ('login_response_parser','login_response_required_user_id','login_response_required_data')]
    inner_schema['title'] = 'Decoded business JSON inside types2.data_content (static receiver reconstruction)'
    inner_schema['required'] = ['msg_type']
    inner_schema['properties']['msg_type'] = {'type':'integer', 'enum':[101,102,113,114,115,116,117]}
    inner_schema['$comment'] += ' Rust forwarding path requires integer msg_type and supports these seven values; this restriction describes the forwarded subset, not all server business messages.'

    u1 = '00000000-0000-4000-8000-000000000001'
    u2 = '00000000-0000-4000-8000-000000000002'
    examples = []

    def example(name, direction, message, note, inner=None, constructed=False):
        ordered = {key:message[key] for key in catalog['serialization_order'] if key in message}
        assert isinstance(ordered['types'],int) and not isinstance(ordered['types'],bool)
        assert isinstance(ordered['qos'],bool)
        for key in ('data_content','from','to','fp'):
            if key in ordered: assert isinstance(ordered[key],str)
        if constructed:
            for key in ('data_content','from','to','fp'):
                if key in ordered: assert len(ordered[key])>0
        item = {'name':name,'synthetic':True,'direction':direction,'note':note,'message':ordered,
                'wire_json_text':json.dumps(ordered,ensure_ascii=False,separators=(',',':'))}
        if inner is not None:
            assert json.loads(ordered['data_content']) == inner
            item['decoded_data_content'] = inner
        examples.append(item)

    example('login_types6','client_to_server',{'types':6,'data_content':'SYNTHETIC.JWT.PLACEHOLDER','fp':u1,'qos':False},
            'wsLogin String copied directly. Placeholder is not a real JWT or credential. Empty from/to omitted.', constructed=True)
    example('heartbeat_types1','client_to_server',{'types':1,'data_content':'💓','from':'SYNTHETIC_CONSTRUCTOR_INPUT','fp':u1,'qos':False},
            'Heartbeat sender format verified. from copies a saved SDK String; its runtime identity meaning remains a separate claim.',constructed=True)
    example('logout_types3','client_to_server',{'types':3,'fp':u1,'qos':False},
            'Active logout worker sets default Protocol types to3 before generic send; empty content/from/to omitted. Server response is unknown.',constructed=True)
    payloads = {
        101: {'serial_number':'SYNTHETIC_DEVICE','mahjong_number':1,'img':'synthetic/card.png','ai_val':11,'ai_precision':0.95},
        102: '42|<SYNTHETIC_ENCODED_JPEG_PLACEHOLDER>',
        113: None,114:'SYNTHETIC_DEVICE',115:'SYNTHETIC_DEVICE',116:'SYNTHETIC_DEVICE',117:'SYNTHETIC_DEVICE|UNUSED_SYNTHETIC_PART',
    }
    for num in sorted(payloads):
        inner = {'msg_type':num}
        if num != 113: inner['msg_content'] = payloads[num]
        content = json.dumps(inner,ensure_ascii=False,separators=(',',':'))
        example(f'business_types2_msg_type{num}','server_to_client',
                {'types':2,'data_content':content,'from':'SYNTHETIC_SENDER','to':'SYNTHETIC_RECEIVER','fp':u1,'qos':True},
                'Synthetic type-valid payload only. Routing/UUID values are invented; image path/data are placeholders. msg113 handler ignores content.',inner=inner)
    example('generated_ack_types4','client_to_server',
            {'types':4,'data_content':u1,'from':'SYNTHETIC_RECEIVER','to':'SYNTHETIC_SENDER','fp':u2,'qos':False},
            'Recipe for ACK generated from preceding synthetic inbound message: content copies received fp; new ACK fp differs.',constructed=True)
    example('received_ack_types4_lookup_key','server_to_client',{'types':4,'fp':u1,'qos':False},
            'Illustrates inspected receiver lookup by ACK.fp only. This is not a confirmed server reply format; data_content omitted because handler does not read it.')
    inner = {'code':0,'user_id':'SYNTHETIC_USER','data':'SYNTHETIC_STRING'}
    example('login_response_types50','server_to_client',
            {'types':50,'data_content':json.dumps(inner,separators=(',',':')),'qos':False},
            'Required inner field types verified; fabricated values, not a captured successful login.',inner=inner)
    for val in (51,52,54):
        example(f'receive_types{val}_minimal_named_shape','server_to_client',{'types':val,'qos':False},
                'Minimal named-object decoder shape only. This does not establish backend required fields or an actual server packet.')
    for item in examples:
        assert json.loads(item['wire_json_text']) == item['message']
    assert len(examples) == 16

    write_json = lambda name, value: (OUT / name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    write_json('protocol_catalog.json',catalog)
    write_json('protocol_inbound.schema.json',inbound_schema)
    write_json('protocol_outbound.schema.json',outbound_schema)
    write_json('inner_business.schema.json',inner_schema)
    write_json('inner_login_response.schema.json',login_schema)
    write_json('synthetic_examples.json',{'warning':'All examples are synthetic reconstructions, not captured traffic. Never sent or executed.', 'examples':examples})
    write_json('evidence.json',EVIDENCE)

    note = '''本目录静态重建了本 APK 的 WebSocket 外层 Protocol、9个已证 types 值、发送封装及16个合成例子。没有抓包、执行目标或访问业务后端。不是原始 Rust/Dart 源码，也不是完整服务器契约。

外层格式
实际命名字段为 types:i32、data_content:String、from:String、to:String、fp:String、qos:bool。序列化顺序固定为 types,data_content,from,to,fp,qos；输出紧凑JSON文本。四个String为空时省略，types/qos始终输出，布尔值用JSON true/false。内存偏移0x00/0x18/0x30/0x48/0x60/0x68只是本构建Rust布局，不是JSON字节位置。
入站命名对象缺少字段时采用types=0、四String=""、qos=false；这不会给缺少fp的入站包生成新UUID。已知字段重复进入错误路径；未知字段通过JSON跳值解码器忽略；根值后面的非空白数据会报错。底层另有数组/序列解码路径，本目录的Schema仅描述已确认的命名JSON对象，数组完整契约未展开。

已证外层 types
1：心跳发送。worker0x1e1110→sender0x1eb3d4→构造器0x1c5d3c→直接发送0x1eb854，data_content="💓"。UTF8机器字0x93929ff0对应f0 9f 92 93；from克隆SDK全局+0x160保存的String、to为空、qos=false、fp为新UUID。周期与超时由独立生命周期分析负责。
2：入站业务。data_content是包含JSON的String。Rust二次解析，只有内层msg_type=101、102、113、114、115、116、117进入已审查Flutter转发路径。
3：客户端主动退出请求。wsLogout对应异步poll0x1cec94调用默认Protocol构造器，原始指令0xced1c写入常量3、0xced20写入对象types字段（+0x60），随后0xced44调用通用发送器。data_content/from/to均为空并省略、qos=false、fp新建。发送后进入停止/清理；没有据此确定服务器回复。
4：QoS ACK。发送构造器交换from/to，data_content复制被确认包fp，ACK本身fp新建、qos=false。接收入站ACK的具体匹配规则见下段。
6：登录发送。原始wsLogin输入String被原样放入data_content，不在构造器内再次JSON解析；本APP Dart上游输入是JWT。默认from/to为空并省略、qos=false、fp新建。Future<int>的0/3/203是本地启动/发送状态，不是服务器登录code。
50：入站登录响应。二次JSON解析data_content，code:i32、user_id:String、data:String三字段必需。code=0进入成功分支，非零进入失败分支。此处data仍是String，不能写成对象；user_id/data没有在已审查分支中确认直接送入Flutter。
51：入站心跳响应。已审查处理分支读取本地当前时间并转换epoch秒，更新心跳时间状态；没有读取data_content作为服务器时间。
52：入站服务端错误分支。分支及日志语义已确认，payload契约和业务回调尚未确认。
54：入站被踢指令，进入连接清理处理。未确认此处把data_content转入Flutter事件编码器。
原始代码中的完整枚举成员名称未恢复。没有把其他types值认定为协议不支持；这里只列实际已证分支/构造值。

两次JSON与Flutter层
types2实际层次是：外层JSON -> data_content String -> jsonDecode得到{msg_type,msg_content} -> Rust过滤数字 -> WsEvent事件整数4，第二个String承载原始data_content -> Dart再次jsonDecode/Message.fromJson。
types2、内层msg_type=101等数字、WsEvent事件整数4是三个不同字段；外层ACK types4也与WsEvent的4不同。FRB包装器控制结果4、Future轮询状态、wsLogin整数返回和服务端code也不能混合。
内层7种含义：101单张牌图像/识别，102实时JPEG预览帧，113新一轮接收开始，114单设备接收完成，115离线，116在线，117升降牌打开/等待洗牌。payload详细消费形态来自message_semantics目录，目录内协议catalog保留对应说明。113在Dart分支不读取msg_content；102/114..117通过动态toString使用内容，不应据此把服务端字段一律定为必需String。

指纹与QoS
fp在已审查路径用于消息去重、跟踪和确认，不是已证的硬件设备指纹。默认/ACK/心跳构造器从16随机字节设置UUID版本4与variant位，然后格式化为小写8-4-4-4-12共36字符；入站fp只是String，没有在这些解码器确认UUID格式校验。
入站qos=true首先检查fp去重。新fp记录后生成ACK并继续types分发；重复fp会再次ACK后直接丢弃业务重复消息。types50带qos时先检查内层code，非零跳过该ACK处理块；畸形qos登录响应还有panic边界，不能宣称所有错误包均被安全忽略。
必须区分ACK两方向：发送ACK的data_content=received.fp，而ACK自身fp是新UUID；但0x1e0cf4接收ACK时用ACK外层fp（param_2+0x48）删除两个发送跟踪结构条目，没有读取data_content作为确认键。两边代码存在关联方式差异；本次没有服务器源码/真实流量，不能推定服务端一定镜像本客户端的ACK构造，也不能仅凭此直接断言线上故障。
0x1eb5a4通用发送器克隆Protocol，调用0x1eb854；只有本地成功且qos=true，再检查fp并将原Protocol加入发送跟踪结构。0x1eb278登录走直接发送器。0x1eb854检查连接门控、调用0x1c6ce0序列化、送入0x1b3bf8 socket队列。序列化/入队成功并不表示认证或业务处理成功。

合成示例与Schema
synthetic_examples.json包含16个明确synthetic=true的示例，附message对象和按外层字段顺序生成的wire_json_text。身份、UUID、JWT、图像路径/数据均是合成或占位符，没有发送。例子展示嵌套JSON中的转义，图像占位数据不可当有效JPEG使用。types51/52/54的最小命名对象仅展示本地解码器形态，不是已证服务器完整包。
入站Schema允许未知命名字段，反映跳值行为；出站Schema只允许六个字段，并约束String出现时非空。Schema default是说明，不会自动执行原生默认赋值，重复JSON键/尾部字节错误也不由对象Schema表达。业务Schema只列被转发的7种msg_type；未声明其他服务端类型无效。

可信边界与复现
evidence.json使用绝对文件路径、精确行号、片段、文件SHA256以及必要Rust Ghidra/ELF地址。Ghidra地址=Rust ELF虚拟地址+0x100000；Dart libapp.so地址属于另一文件。反编译伪C类型受Ghidra恢复误差影响，结构布局与关键值通过对应原始ARM64指令/字面量独立核对。
raw_protocol_instructions.asm.txt由本机LLVM只读反汇编生成。脚本直接验证6条入站types比较机器字，复核constructor/ACK字段写入、UUID格式常量及所有证据片段。已有原始APK/AOT/Ghidra产物均不修改。
重新运行：python3 <LOCAL_APP>/scripts/ws_protocol_extract.py。脚本仅写ws_protocol目录，不加载目标库、不发网络请求；需要现有LLVM及分析文件。心跳周期、超时、重连与重发窗口细节在独立任务中处理。
'''
    (OUT / 'WebSocket协议说明.txt').write_text(note)
    # Check every precise evidence line and file hash after constructing outputs.
    ref_count = 0
    for group in EVIDENCE.values():
        for r in group['references']:
            path = Path(r['file'])
            assert hashlib.sha256(path.read_bytes()).hexdigest() == r['sha256']
            if 'line' in r:
                assert path.read_text().splitlines()[r['line']-1].strip() == r['excerpt']
            ref_count += 1
    manifest = {'method':'Static local source/ELF reads plus LLVM disassembly; no target execution/network',
        'inputs':[{'file':p,'sha256':h} for p,h in sorted(INPUTS.items())],
        'verified':{'evidence_groups':len(EVIDENCE),'precise_evidence_references':ref_count,
                    'raw_inbound_type_comparisons':6,'known_outer_type_values':[1,2,3,4,6,50,51,52,54],
                    'known_inner_type_values':[101,102,113,114,115,116,117],
                    'synthetic_examples_round_trip':len(examples),'uuid_hex_alphabet':True},
        'script':str(Path(__file__).resolve()),
        'outputs':[{'file':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                   for p in sorted(OUT.iterdir()) if p.is_file() and p.name!='evidence_manifest.json']}
    write_json('evidence_manifest.json',manifest)
    print(json.dumps(manifest['verified'],ensure_ascii=False))


if __name__ == '__main__':
    main()
