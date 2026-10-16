#!/usr/bin/env python3
"""Reproduce the static ARM64 Rust/FRB/Dart event audit. Never runs target code."""

from _paths import app_root, workspace_root
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

ROOT = workspace_root()
OUT = ROOT / 'APP/analysis/ws_event_contract'
NEW = 'APP/analysis/ws_event_contract/native_pseudocode/functions/'
HEART = 'APP/analysis/ws_heartbeat/native_pseudocode/functions/'
LOGIN = 'APP/analysis/login_flow/native_pseudocode/functions/'
AOT = 'APP/analysis/aot_dump/asm/'
GENERATED = AOT + 'distinguish/src/rust/frb_generated.dart'
MAIN = AOT + 'distinguish/pages/main/main_page.dart'
RUST = ROOT / 'APP/unpacked/lib/arm64-v8a/librust_lib_distinguish.so'
DART = ROOT / 'APP/unpacked/lib/arm64-v8a/libapp.so'


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class Binary:
    def __init__(self, path, expected_sha):
        self.path = path
        self.sha256 = sha(path)
        assert self.sha256 == expected_sha, f'Unexpected input: {path}'
        self.stream = path.open('rb')
        self.elf = ELFFile(self.stream)
        assert self.elf.little_endian and self.elf['e_machine'] == 'EM_AARCH64'
        self.loads = [s for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD']

    def data(self, va, size):
        for s in self.loads:
            if s['p_vaddr'] <= va and va + size <= s['p_vaddr'] + s['p_filesz']:
                start = s['p_offset'] + va - s['p_vaddr']
                self.stream.seek(start)
                return self.stream.read(size)
        raise ValueError(f'No file-backed mapping at {va:#x}')

    def word(self, va):
        return struct.unpack('<I', self.data(va, 4))[0]

    def direct_branches(self):
        found, coverage = [], []
        for s in self.loads:
            if not s['p_flags'] & 1:
                continue
            lo, hi = s['p_vaddr'], s['p_vaddr'] + s['p_filesz']
            start = (lo + 3) & ~3
            data = s.data()
            coverage.append({'elf_start': hex(lo), 'elf_end_exclusive': hex(hi),
                             'file_offset': hex(s['p_offset']), 'file_backed_bytes': s['p_filesz'],
                             'memory_bytes': s['p_memsz'], 'aligned_words': (hi - start) // 4})
            for va in range(start, hi - 3, 4):
                word = struct.unpack_from('<I', data, va - lo)[0]
                opcode = word & 0xfc000000
                if opcode not in (0x94000000, 0x14000000):
                    continue
                imm = word & 0x3ffffff
                if imm & 0x2000000:
                    imm -= 0x4000000
                found.append((va, va + (imm << 2), 'BL' if opcode == 0x94000000 else 'B'))
        return found, coverage


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--objdump', default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    raw_dir = OUT / 'raw_llvm'
    raw_dir.mkdir(exist_ok=True)
    rust = Binary(RUST, '0af3f1f12e57e9b5f2d409343421c1fa21b0bcffe7860a30cf972a1265399847')
    dart = Binary(DART, '40d890193daa716defe2eec6cd2959bdbf7f7cf8345f8213b1747e54863a5a55')
    evidence = []

    def src(id_, relative, start=None, end=None, needle=None, before=2, after=3):
        path = ROOT / relative
        lines = path.read_text().splitlines()
        if start is None:
            matches = [i for i, l in enumerate(lines) if needle in l]
            assert matches, (relative, needle)
            index = matches[0]
            start, end = max(1, index + 1 - before), min(len(lines), index + 1 + after)
        assert 1 <= start <= end <= len(lines)
        excerpt = '\n'.join(lines[start-1:end])
        if needle:
            assert needle in excerpt, (id_, needle)
        evidence.append({'id': id_, 'kind': 'local_source', 'file': str(path),
                         'sha256': sha(path), 'start_line': start, 'end_line': end,
                         'excerpt': excerpt})

    specs = [
        ('native_event_layout_and_send', HEART+'001ec7f0.c', 57, 84, 'FUN_001b4058'),
        ('native_event_prefix', NEW+'001b4058.c', 20, 38, '*puStack_88 = param_2'),
        ('native_event_encode_order', NEW+'001e3088.c', 15, 50, 'FUN_001c692c'),
        ('native_string_encoding', NEW+'001c692c.c', 19, 59, '*(int *)(param_2[1] + uVar5)'),
        ('event_sink_registration', NEW+'001c5ad8.c', 74, 78, 'pppiVar6[2] = param_1'),
        ('transport_monitor_pending_closed_false', HEART+'001a51f0.c', 40, 84, 'bVar3 == 2'),
        ('transport_event_10', HEART+'001a51f0.c', 85, 94, 'local_60 = 10'),
        ('chat_event_4', HEART+'001c5f58.c', 80, 120, 'iVar2 - 0x71U < 5'),
        ('outer_52_54_dispatch', HEART+'001e99a0.c', 196, 248, 'FUN_001e2ea0'),
        ('outer_2_chat_dispatch', HEART+'001e99a0.c', 251, 263, 'FUN_001c5f58'),
        ('auth_response_parse_and_code_zero', HEART+'001e99a0.c', 340, 403, 'if ((int)local_108 == 0)'),
        ('auth_success_state_and_daemons', HEART+'001e99a0.c', 473, 531, 'FUN_001e2d2c(uVar9,1)'),
        ('auth_failure_and_drop', HEART+'001e99a0.c', 532, 566, 'FUN_001e303c'),
        ('auth_response_required_fields', 'APP/analysis/deep_rust/login_response.schema.json', 5, 22, '"user_id"'),
        ('qos_auth_prepass', HEART+'001e99a0.c', 585, 631, 'FUN_001c6e5c'),
        ('qos_duplicate_ack_and_drop', HEART+'001e99a0.c', 632, 704, 'FUN_001eb5a4'),
        ('kick_full_stop', HEART+'001e2ea0.c', 16, 45, 'FUN_001e8b4c'),
        ('internal_disconnect_notice', HEART+'001e1e9c.c', 18, 61, 'FUN_001b3b14'),
        ('transport_bool_true_sender', HEART+'001e8de4.c', None, None, 'FUN_001b3b14'),
        ('disconnect_receiver', HEART+'001a5430.c', None, None, 'FUN_001eab5c'),
        ('disconnect_reconnect_local_ops', HEART+'001eab5c.c', 48, 104, 'FUN_001bfa3c'),
        ('close_helper_gate', HEART+'001e8b4c.c', 42, 63, 'FUN_001e2c04'),
        ('init_ws_saved_string', NEW+'001d327c.c', 839, 858, 'ppppppuVar32[0x29] = local_2d40'),
        ('login_saved_string', LOGIN+'001cf0e0.c', 127, 156, '*(undefined8 *)(puVar7 + 0x110)'),
        ('logout_type3_attempt', HEART+'001cec94.c', 61, 78, 'FUN_001eb5a4'),
        ('logout_clear_token_and_stop', HEART+'001cec94.c', 119, 149, 'FUN_001e2ea0'),
        ('init_app_logging', NEW+'001c6b14.c', 14, 28, 'FUN_001fbb5c'),
        ('sdk_default_constructor_binding', NEW+'001dbef8.c', 8, 12, 'FUN_001dbaf0'),
        ('sdk_default_strings', NEW+'001dbaf0.c', 99, 110, 'puVar6[0x27] = 0'),
        ('sdk_default_reconnect_period', NEW+'001dbaf0.c', 143, 148, 'puVar6[0x1d] = 0'),
        ('sdk_default_flags', NEW+'001dbaf0.c', 166, 176, '*(undefined2 *)(puVar6 + 0x56) = 0'),
        ('heartbeat_period_default', HEART+'001e253c.c', 75, 82, 'lVar2 = 0x1e'),
        ('reconnect_period_default', HEART+'001ec69c.c', None, None, 'lVar1 = 3'),
        ('frb_function_ids', NEW+'001c64b0.c', 20, 119, '"create_event_stream"'),
        ('is_content_ws_wrapper', NEW+'001aff28.c', 39, 48, 'FUN_001b8174'),
        ('is_content_ws_worker_schedule', 'APP/analysis/deep_rust/functions/001b8174.c', 25, 32, 'FUN_001a96d8'),
        ('dart_stream_decoder_selection', GENERATED, 838, 864, '0x520e6c'),
        ('dart_decode_ws_event', GENERATED, 902, 953, '0x520ed8'),
        ('dart_decode_string', GENERATED, 954, 982, 'sse_decode_list_prim_u_8_strict'),
        ('dart_init_ws_one_string', GENERATED, 1135, 1162, '0x52aee4'),
        ('dart_event_subscription', MAIN, 9296, 9313, '0x527460'),
        ('dart_event4_consumer', MAIN, 10379, 10420, 'jsonDecode'),
        ('dart_event10_consumer', MAIN, 11335, 11363, 'wsLogin'),
        ('dart_stream_prefix_read', AOT+'flutter_rust_bridge/src/codec/sse.dart', 189, 210, 'getUint8'),
        ('dart_stream_prefix_zero_dispatch', AOT+'flutter_rust_bridge/src/codec/base.dart', 28, 60, '0x4a916c'),
    ]
    for id_, path, start, end, needle in specs:
        src(id_, path, start, end, needle)

    # ELF address -> exact expected instruction word. No target function executes.
    words = {
        0xa5260: 0x36000495, 0xa5264: 0x52800148, 0xa526c: 0xb90033e8,
        0xc6090: 0x5101c509, 0xc6094: 0x7100153f, 0xc60a0: 0x52800088,
        0xc60d8: 0x7101951f, 0xc60e0: 0x7101991f, 0xc616c: 0x52800088,
        0xec898: 0x2a1f03e0, 0xb40a0: 0x39000135, 0xe30ac: 0xb9403016,
        0xe3114: 0xb8356af6, 0xe9e6c: 0x7100c91f, 0xe9f48: 0x7100d11f,
        0xe9f50: 0x7100d91f, 0xea338: 0x34000be8, 0xea510: 0x390ac6c8,
        0xea600: 0x390ac6c8, 0xa70f4: 0x390a96bf, 0xe8e98: 0x52800021,
        0xcf27c: 0x3d804740, 0xcf280: 0xf9009348, 0xced1c: 0x52800068,
        0xced20: 0xb90083e8, 0xcedc8: 0xf900931f, 0xcedcc: 0xa911231f,
        0xdbcbc: 0xa911227f, 0xdbcc0: 0xa913a27f, 0xdbcc4: 0xa916227f,
        0xdbc74: 0x6f00e401, 0xdbc88: 0x3c89f2a1, 0xdbc94: 0x3cc982a6,
        0xdbca8: 0x3c829266, 0xdbd44: 0xf900767f,
    }
    # BL destinations are decoded from the original instruction, not from decompiler labels.
    bls = {
        0xa5280: 0xec7f0, 0xc60c8: 0xec7f0, 0xc6194: 0xec7f0,
        0xec89c: 0xb4058, 0xb40dc: 0xe3088, 0xe3140: 0xc692c, 0xe315c: 0xc692c,
        0xec8b0: 0xfbf6c, 0xec8bc: 0xa9798,
        0xe9ec4: 0xc6e5c, 0xe9fe0: 0xe2ea0, 0xea028: 0xc5f58,
        0xea3b8: 0xe8b4c, 0xea3cc: 0xec290, 0xea3e0: 0xe2d2c,
        0xea644: 0xec290, 0xea648: 0xb3e58, 0xea6b4: 0xe1b0c,
        0xea6c8: 0xdd640, 0xea6dc: 0xdef28, 0xea6f0: 0xe2d2c, 0xea710: 0xe303c,
        0xe8e9c: 0xb3b14, 0xa5484: 0xb39d8, 0xa549c: 0xeab5c,
        0xa7130: 0xe9794, 0xa7154: 0xe1e9c, 0xd46a8: 0xe9794, 0xd46cc: 0xe1e9c,
        0xcf6ac: 0xd327c, 0xcf2cc: 0xeaf88, 0xced14: 0xc5ce4,
        0xced44: 0xeb5a4, 0xcee1c: 0xe2ea0,
    }
    dart_words = {0x52748c: 0xf8407064, 0x527490: 0xf100109f,
                  0x5274ac: 0x7100201f, 0x5274b4: 0xb8413061,
                  0x527efc: 0xf100289f, 0x527f18: 0x7100501f,
                  0x520ec8: 0xf8007001, 0x520ed0: 0xb800f001,
                  0x520ed8: 0xb8013001, 0x51f64c: 0xd2800023,
                  0x52aee4: 0xd2800083}
    dart_bls = {0x51f390: 0x51f420, 0x51f3b4: 0x62e174, 0x520e98: 0x520f84,
                0x520ea8: 0x520efc, 0x520eb8: 0x520efc, 0x520ec0: 0x520ef0,
                0x5274bc: 0x493ba4, 0x5274e8: 0x52a198, 0x527f34: 0x4ab08c,
                0x52a8a0: 0x52ace8, 0x52aeb4: 0x4ab2b8, 0x52aee8: 0x4a98b8,
                0x4a9098: 0x4a9640, 0x4a90cc: 0x4a90e4,
                0x51f6cc: 0x51f6f8, 0x51f6dc: 0x4ab2b8}
    raw_checks = []
    for binary, word_specs, bl_specs in [(rust, words, bls), (dart, dart_words, dart_bls)]:
        for va, expected in sorted(word_specs.items()):
            word = binary.word(va)
            assert word == expected, f'{binary.path.name} {va:#x}: {word:08x} != {expected:08x}'
            raw_checks.append({'binary': binary.path.name, 'elf_va': hex(va),
                               'bytes_le': binary.data(va, 4).hex(), 'word_hex': f'{word:08x}',
                               'check': 'exact_instruction_word'})
        for va, target in sorted(bl_specs.items()):
            word = binary.word(va)
            assert word & 0xfc000000 == 0x94000000, f'Not BL at {va:#x}'
            imm = word & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            assert va + (imm << 2) == target, (hex(va), hex(va + (imm << 2)), hex(target))
            raw_checks.append({'binary': binary.path.name, 'elf_va': hex(va),
                               'bytes_le': binary.data(va, 4).hex(), 'word_hex': f'{word:08x}',
                               'check': 'BL_decoded_destination', 'target_elf': hex(target)})

    # Keep and freshly byte-check the prior CObject evidence without editing it.
    prior_path = ROOT / 'APP/analysis/deep_rust/flutter_event_encoding.json'
    prior = json.loads(prior_path.read_text())
    timing_path = ROOT / 'APP/analysis/ws_heartbeat/heartbeat_lifecycle.json'
    timing = json.loads(timing_path.read_text())
    login_path = ROOT / 'APP/analysis/login_flow/native_login_flow.json'
    prior_login = json.loads(login_path.read_text())
    cobject_raw = []
    for group, instructions in prior['instruction_evidence'].items():
        if group in ['cobject_external_uint8', 'post_registration', 'post_call']:
            for line in instructions:
                match = re.match(r'\s*([0-9a-f]+):\s*([0-9a-f]{8})\s', line)
                if match:
                    va, word = int(match[1], 16), int(match[2], 16)
                    assert rust.word(va) == word
                    cobject_raw.append({'group': group, 'instruction': line,
                                        'elf_va': hex(va), 'bytes_le': rust.data(va,4).hex()})

    branches, coverage = rust.direct_branches()
    calls = [{'elf_va': hex(va), 'ghidra_va': hex(va + 0x100000), 'opcode': op,
              'bytes_le': rust.data(va,4).hex()} for va, target, op in branches if target == 0xec7f0]
    assert [(int(c['elf_va'],16), c['opcode']) for c in calls] == [
        (0xa5280,'BL'), (0xc60c8,'BL'), (0xc6194,'BL')]
    relas, rela_entries = [], []
    for section in rust.elf.iter_sections():
        if isinstance(section, RelocationSection) and section.is_RELA():
            for rel in section.iter_relocations():
                rela_entries.append(rel)
                if rel['r_addend'] == 0xec7f0:
                    relas.append({'section': section.name, 'offset_elf': hex(rel['r_offset']),
                                  'type': rel['r_info_type'], 'addend': hex(rel['r_addend'])})
    assert not relas
    wanted = {0x1a34b0:0xb0744, 0x1a34e8:0xb07d4, 0x1a58a8:0xdbef8}
    bindings = []
    for offset,target in wanted.items():
        matches=[rel for rel in rela_entries if rel['r_offset']==offset and rel['r_addend']==target]
        assert len(matches)==1 and matches[0]['r_info_type']==1027
        bindings.append({'relocation_offset_elf':hex(offset),'type':'R_AARCH64_RELATIVE',
                         'addend_target_elf':hex(target)})

    snapshots = []
    ranges = [('event10',rust,0xa5258,0xa5284),('chat_event4',rust,0xc608c,0xc6198),
              ('stream_sink_save',rust,0xc5b80,0xc5b94),('event_sse',rust,0xe3088,0xe3160),
              ('event_post',rust,0xec878,0xec8c4),('auth_outer_switch',rust,0xe9e68,0xe9f58),
              ('auth_code_compare',rust,0xea324,0xea348),('auth_failure',rust,0xea3b0,0xea3e8),
              ('auth_success',rust,0xea638,0xea718),('error52_log_drop',rust,0xea294,0xea320),
              ('sdk_defaults',rust,0xdbc70,0xdbd98),('init_ws_string_save',rust,0xd340c,0xd3438),
              ('login_string_save',rust,0xcf274,0xcf288),('logout_attempt',rust,0xced14,0xced48),
              ('logout_clear',rust,0xcedc0,0xcede0),('dart_event_decoder',dart,0x520e90,0x520ee0),
              ('dart_subscription',dart,0x51f390,0x51f3c0),('dart_event4_consumer',dart,0x52748c,0x5274f0),
              ('dart_event10_consumer',dart,0x527efc,0x527f38)]
    for label,binary,lo,hi in ranges:
        output = subprocess.check_output([args.objdump,'-D','--triple=aarch64',
                                         f'--start-address={lo:#x}',f'--stop-address={hi:#x}',str(binary.path)],text=True)
        p=raw_dir/(label+'.asm')
        p.write_text(output)
        snapshots.append({'id':label,'binary':binary.path.name,'elf_start':hex(lo),
                          'elf_end_exclusive':hex(hi),'raw_bytes_sha256':hashlib.sha256(binary.data(lo,hi-lo)).hexdigest(),
                          'file':str(p),'sha256':sha(p)})

    limited_paths=[]
    for path in [HEART+'001e99a0.c',HEART+'001e2ea0.c',HEART+'001eab5c.c',
                 HEART+'001e1e9c.c',HEART+'001e8b4c.c',HEART+'001a5430.c',
                 HEART+'001a5ec8.c',NEW+'001d327c.c']:
        p=ROOT/path
        text=p.read_text()
        assert 'FUN_001ec7f0(' not in text and 'FUN_001b4058(' not in text
        limited_paths.append({'file':str(p),'sha256':sha(p),'line_count':len(text.splitlines()),
                              'check':'No explicit call to known WsEvent emitter/serializer in this complete decompilation',
                              'direct_callees_ghidra':sorted(set(re.findall(r'FUN_([0-9a-f]{8})\(',text)) - {p.stem})})

    examples=[]
    for value,s1,s2 in [(10,'',''),(4,'','{"msg_type":101}')]:
        b1,b2=s1.encode(),s2.encode()
        packet=b'\0'+struct.pack('<I',value)+struct.pack('<I',len(b1))+b1+struct.pack('<I',len(b2))+b2
        assert struct.unpack_from('<I',packet,1)[0]==value
        examples.append({'synthetic':True,'event_integer':value,'first_string':s1,'second_string':s2,
                         'serialized_hex':packet.hex(),'byte_length':len(packet),
                         'note':'Independent byte-layout example; not captured runtime traffic and does not run target codec'})

    matrix=[
        {'trigger':'transport bool channel Ready(true)','native_function':'0x1a51f0','event_integer':10,
         'first_string':'','second_string':'','dart_consumer':'MainPage 0x527460 → event10 → wsLogin(static JWT)',
         'status':'confirmed','meaning':'Transport connected notification; occurs before types50 authentication success.'},
        {'trigger':'outer types2 + inner integer msg_type in 101,102,113..117','native_function':'0x1c5f58',
         'event_integer':4,'first_string':'','second_string':'Original data_content UTF-8 String, moved intact',
         'dart_consumer':'MainPage event4 reads field_13 → jsonDecode → Message.fromJson', 'status':'confirmed'},
        {'trigger':'types50 valid response with code==0 (not rejected as duplicate)','native_function':'0x1e99a0',
         'event_integer':None,'strings':None,'local_effect':'SDK+0x2b1=true (twice), stop auto-relogin; create internal disconnect channel; start heartbeat, receive/send QoS; set SDK+0x2a5=true; drop response strings',
         'status':'limited_negative_evidence','dart_consumer':'No WsEvent construction observed in audited branch.'},
        {'trigger':'types50 valid response with code!=0','native_function':'0x1e99a0',
         'event_integer':None,'strings':None,'local_effect':'Call gated close helper, stop auto-relogin, set SDK+0x2a5=false, drop response strings',
         'status':'limited_negative_evidence','dart_consumer':'No WsEvent construction observed in audited branch; cannot claim runtime has no notification through any mechanism.'},
        {'trigger':'types50 malformed response','native_function':'0x1e99a0','event_integer':None,
         'local_effect':'Non-QoS dispatch logs/drops failed parse; QoS prepass unwrap/panic path can be reached.',
         'status':'limited_negative_evidence'},
        {'trigger':'types52','native_function':'0x1e99a0','event_integer':None,'strings':None,
         'local_effect':'Conditional logging then Protocol cleanup; no bound error payload parsing/event forwarding.',
         'status':'limited_negative_evidence'},
        {'trigger':'types54','native_function':'0x1e99a0 → 0x1e2ea0','event_integer':None,'strings':None,
         'local_effect':'Full local stop, including heartbeat/QoS/relogin/internal channels and SDK+0x2b1=false.',
         'status':'limited_negative_evidence'},
        {'trigger':'transport bool channel Ready(false) / channel closed tag2','native_function':'0x1a51f0',
         'event_integer':None,'strings':None,'local_effect':'False: conditional log only; closed: cleanup receiver/future.',
         'status':'limited_negative_evidence'},
        {'trigger':'initial transport failure / ongoing socket worker termination','native_function':'0x1d327c / 0x1a5ec8',
         'event_integer':None,'strings':None,'local_effect':'Clear SDK+0x2a5, remove transport channel sender, stop heartbeat and send true to internal disconnect channel if present; receiver 0x1a5430 invokes 0x1eab5c and starts auto-relogin.',
         'status':'limited_negative_evidence'}
    ]
    result={
        'scope':'Static extraction only; no APK/library execution, no business-server access. Parent reports and prior artifacts remain untouched.',
        'inputs':[{ 'file':str(b.path),'sha256':b.sha256} for b in [rust,dart]],
        'addressing':{'rust':'Ghidra = ELF virtual address + 0x100000','dart':'Blutter AOT address equals ELF virtual address in libapp.so'},
        'contract':{'native_layout':[{'offset':'0x00','representation':'Rust String capacity,pointer,UTF-8 length','dart_property':'field_f'},
                                     {'offset':'0x18','representation':'Rust String capacity,pointer,UTF-8 length','dart_property':'field_13'},
                                     {'offset':'0x30','representation':'32-bit raw event integer; Dart decoder uses getUint32, original Rust signedness not recovered','dart_property':'field_7 (unboxed Dart int)'}],
                    'original_field_names':'Unrecovered; field_f/field_13/field_7 are AOT memory labels, not original source names.',
                    'encoding':'FRB action byte0 + LE u32 event_integer + LE u32 String1 byte_length + String1 UTF8 + LE u32 String2 byte_length + String2 UTF8; no terminator/padding.',
                    'decoder':'SseCodec reads u8 then SimpleDecoder handles action0; selected sse_decode_ws_event reads getUint32 and two strings in the same order.',
                    'port_post':'Known emitter reads registered sink context, serializes action0, creates external Uint8 Dart_CObject and posts via stored Dart_PostCObject callback.',
                    'registration':'createEventStream stores sink Arc at global Ghidra 0x2b4430+0x10 and Dart port at +0x18; emitter panics if sink missing/lock poisoned/post fails.',
                    'consumer':'MainPage.initState calls createEventStream then listen with closure0x527460. This listener consumes only event4 and event10 in its observed outer branches.',
                    'distinctions':['FRB action0 is not an application WsEvent integer.','FRB function id4 means init_ws and is separate from WsEvent integer4.','Inner msg_type101..117 is distinct from outer Protocol.types and WsEvent integer.','WsEvent+0x30 is an integer field, not proven Rust enum discriminant.']},
        'event_matrix':matrix,
        'auth_response_storage':{'confirmed':'Response code branches; user_id/data strings are parsed and eventually dropped by 0x1e303c; no write of those response strings to saved JWT/URL/from string fields observed in this dispatcher.',
                                 'not_proven':'Original response business intent, unused field source names beyond prior schema, any separate runtime observer or inlined alternative emitter.'},
        'configuration':[
            {'entry':'init_app','frb_function_id':3,'observed_arguments':'No SDK config argument; FRB control/port metadata only','effect':'Logging/tracing initialization and backtrace/panic setup via 0x1c6b14; no period writes observed in audited path.'},
            {'entry':'create_event_stream','frb_function_id':1,'observed_arguments':'FRB StreamSink handle serialized as String','effect':'Registers/replaces global event sink and port.'},
            {'entry':'init_ws','frb_function_id':4,'observed_arguments':'One String','effect':'Clones argument into SDK+0x138/capacity,+0x140/pointer,+0x148/length, then connects transport; no heartbeat/relogin period argument.'},
            {'entry':'ws_login','frb_function_id':6,'observed_arguments':'One String (Dart caller uses saved JWT)','effect':'Saves string into SDK+0x110/capacity,+0x118/pointer,+0x120/length; connected path sends types6, disconnected path waits for connection then sends. Future<int> is local send/queue status, not response code.'},
            {'entry':'ws_logout','frb_function_id':7,'observed_arguments':'None','effect':'Attempts types3 send, ignores result, clears saved login string to (0,1,0), calls local full stop. Does not establish server logout receipt or WebSocket Close-frame transmission.'},
            {'field':'SDK+0x30 heartbeat period','default_raw':0,'effective_default_seconds':30,'evidence':'Zero lane copied by constructor SIMD sequence; getter0x1e253c substitutes30. No overwriting entry argument in audited init/login/logout paths.'},
            {'field':'SDK+0xe8 auto-relogin period','default_raw':0,'effective_default_seconds':3,'evidence':'Constructor stores xzr; getter0x1ec69c substitutes3. Units cross-checked in prior heartbeat lifecycle artifact.'}
        ],
        'default_zero_simd_proof':{'sdk_field_range':'SDK+0x30..0x37','instructions':['0xdbc74 MOVI v1.2d,#0','0xdbc88 STUR q1,[x21,#0x9f]','0xdbc94 LDUR q6,[x21,#0x98]','0xdbca8 STUR q6,[x19,#0x29]'],
                                   'byte_overlap':'Loaded q6 bytes7..14 are zero; when stored at SDK+0x29 those bytes map to SDK+0x30..0x37. Padding bytes are not assumed initialized.'},
        'finite_negative_evidence':{'method':'Decode aligned AArch64 B/BL words in every file-backed PF_X PT_LOAD of this Rust ELF; scan every RELA addend for exact known emitter entry; inspect complete listed decompilations.',
                                    'coverage':coverage,'file_backed_bytes_scanned':sum(c['file_backed_bytes'] for c in coverage),
                                    'aligned_words_scanned':sum(c['aligned_words'] for c in coverage),'all_direct_branch_word_count':len(branches),
                                    'known_emitter_target_elf':'0xec7f0','direct_call_sites':calls,'RELA_entries_scanned':len(rela_entries),
                                    'RELA_exact_target_matches':relas,'complete_decompilation_checks':limited_paths,
                                    'limits':['Scan finds direct B/BL only; BR/BLR, computed pointers, inlined or alternative serializers, arbitrary pointers without RELA, and relocation to interior code addresses are not exhaustively resolved.',
                                              'PF_X scan includes any embedded data and is not a proof every word is reachable code; validated matching sites have source and LLVM context.',
                                              'Only file-backed executable segments of this current ARM64 library; not other ABI libraries, Dart isolates, versions, or runtime server behavior.',
                                              'No exact RELA addend to emitter entry excludes only that relocation representation, not all indirect reachability.',
                                              'The finite finding is: reviewed auth/error/kick/close paths do not construct/post WsEvent through the known emitter. It is not a universal claim that the app cannot notify authentication failure or closure.']},
        'is_content_ws_scope':{'frb_function_id':5,'business_arguments':[],
                               'reviewed_chain':'GH 0x1aff28 → 0x1b8174 → scheduler 0x1a96d8 → RELA worker 0x1b06b4 → 0x1b8348 → getter 0x1e2c04',
                               'status':'confirmed_static',
                               'predicate':'Normal return reads SDK+0x2a5 transport flag under its read lock. Does not read SDK+0x2b1 auth flag or compare host/URL. Dart serializes no business arguments. Uninitialized bridge and poisoned lock error paths are not normalized to false.',
                               'additional_evidence_directory':str(ROOT/'analysis/connection_preview_closure/is_content_ws')},
        'unknowns':['Original names of the WsEvent integer and two String fields.','Whether another unreviewed mechanism reports authentication/52/54/closure at runtime.','Server behavior and execution timing/delivery guarantees.','Actual WebSocket Close frame on gated close-helper paths.','Any runtime mutation of periods outside audited entry paths.'],
        'synthetic_encoding_examples':examples,'source_evidence':evidence,'raw_instruction_checks':raw_checks,
        'raw_llvm_snapshots':snapshots,'relocation_bindings':bindings,
        'prior_cobject_evidence':{'file':str(prior_path),'sha256':sha(prior_path),'memory_fields':prior['dart_cobject'],
                                 'freshly_verified_instruction_count':len(cobject_raw),'instructions':cobject_raw},
        'prior_period_units_evidence':{'file':str(timing_path),'sha256':sha(timing_path),
                                       'facts':[f for f in timing['facts'] if f['id'] in ['heartbeat_period','heartbeat_schedule','auto_relogin_schedule']]},
        'prior_transport_monitor_binding':{'file':str(login_path),'sha256':sha(login_path),
                                           'json_pointer':'/connection_event10',
                                           'channel_chain':prior_login['connection_event10']['boolean_channel_chain'],
                                           'task_binding':prior_login['connection_event10']['task_binding'],
                                           'evidence_ids':prior_login['connection_event10']['evidence']},
        'verification':{'passed':True,'source_excerpt_count':len(evidence),'exact_word_and_BL_check_count':len(raw_checks),
                        'llvm_snapshot_count':len(snapshots),'synthetic_layout_examples':len(examples)}
    }
    (OUT/'event_contract.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    (OUT/'event_dispatch_pseudocode.txt').write_text(PSEUDO)
    (OUT/'事件契约说明.txt').write_text(EXPLANATION.format(
        source_count=len(evidence),raw_count=len(raw_checks),snapshot_count=len(snapshots),
        scanned_bytes=result['finite_negative_evidence']['file_backed_bytes_scanned'],
        scanned_words=result['finite_negative_evidence']['aligned_words_scanned'],rela_count=len(rela_entries)))
    print(json.dumps({'output':str(OUT),'verification':result['verification'],
                      'emitter_direct_calls':calls,'scanned_bytes':result['finite_negative_evidence']['file_backed_bytes_scanned'],
                      'rela_count':len(rela_entries)},ensure_ascii=False))


PSEUDO = '''Reconstructed readable pseudocode; not original Rust/Dart source.
Addresses below are Ghidra for Rust, original AOT addresses for Dart.

// Known global emitter 0x1ec7f0, codec 0x1b4058 -> 0x1e3088
post_ws_event(value, string1, string2):
    sink = read(global_0x2b4430).registered_sink_or_panic()
    bytes = u8(0) + u32le(value) + string_utf8_with_u32le_length(string1)
             + string_utf8_with_u32le_length(string2)
    post_Dart_CObject_external_Uint8(sink.port, bytes).unwrap()

// Transport monitor 0x1a51f0: its bool channel is not types50 authentication.
poll_transport_notice():
    match receiver.poll():
        Pending(tag3): return Pending
        Closed(tag2): release_receiver_and_finish()
        Ready(false): conditional_log_only()
        Ready(true): post_ws_event(10, "", "")

// Dispatcher 0x1e99a0; preserves the actual QoS prepass and duplicate gate.
receive_protocol(p):
    if p.qos:
        if p.types == 50:
            r = parse_login_response(p.data_content).unwrap() // malformed can panic
            if r.code != 0: goto dispatch // bypass normal dedup/ACK prepass
        if receive_qos_seen(p.fp):
            send_ack(p)
            drop(p)
            return // no authentication/business dispatch of duplicate
        receive_qos_record(p.fp)
        send_ack(p)
    dispatch:
    match p.types:
        2:
            m = parse_generic_json(p.data_content)
            n = require_integer(m["msg_type"]) // missing/wrong type may panic
            if n in [101,102,113,114,115,116,117]:
                post_ws_event(4, "", move(p.data_content))
            else: drop(p.data_content)
        50:
            r = parse_login_response(p.data_content)
            if invalid(r): conditional_log_and_drop()
            else if r.code == 0:
                sdk.flag_0x2b1 = true // repeated assignment in observed branch
                stop_auto_relogin()
                register_internal_disconnect_channel()
                spawn_internal_disconnect_receiver()
                start_heartbeat()
                start_receive_qos()
                start_send_qos()
                sdk.flag_0x2a5 = true
                drop(r.user_id_and_data_strings)
                // No post_ws_event call observed in this audited branch.
            else:
                gated_close_helper()
                stop_auto_relogin()
                sdk.flag_0x2a5 = false
                drop(r.user_id_and_data_strings)
                // No post_ws_event call observed in this audited branch.
        52:
            conditional_log()
            drop(p) // No bound error-message forwarding observed.
        54:
            full_local_stop() // No post_ws_event call observed.
        others:
            other_protocol_handlers_or_drop() // outside this readable subset

transport_failed_or_terminated(): // 0x1d327c / 0x1a5ec8
    sdk.flag_0x2a5 = false
    remove_transport_bool_sender()
    stop_heartbeat()
    if internal_disconnect_sender_present(): send_internal_bool(true)

internal_disconnect_receiver(): // 0x1a5430 -> 0x1eab5c
    match receiver.poll():
        Pending(tag3): return Pending
        Closed(tag2): release_and_finish()
        Ready(_): local_cleanup(); restart_auto_relogin()
    // Internal bool channel is distinct from the FRB WsEvent stream.

// Dart MainPage.initState 0x51f028 -> listener 0x527460
subscription = createEventStream().listen((event):
    if event.field_7 == 4:
        message = Message.fromJson(jsonDecode(event.field_13))
        dispatch_message_by_inner_msg_type(message)
    else if event.field_7 == 10:
        wsLogin(savedJWT) // initiates authentication after transport connection
)

// Configuration writes, distinct from server authentication response.
initApp(): install_logging_and_backtrace_configuration()
initWs(oneString): sdk.string_0x138 = clone(oneString); connect_transport()
wsLogin(jwtString): sdk.string_0x110 = clone(jwtString); queue_or_send_type6()
wsLogout(): attempt_type3_send_ignoring_result(); sdk.string_0x110 = "";
            full_local_stop()
// Constructor zeroes SDK+0x30 / SDK+0xe8; getters substitute 30s / 3s.
// No period argument/write in the audited init/login/logout entry paths.
// Cleanup does not prove a WebSocket Close frame was transmitted.
'''

EXPLANATION = '''Rust → FRB → Dart 事件契约与初始化配置静态审计

本次只读取当前 APK 的 ARM64 ELF、已有反编译工件和 Blutter AOT，补充伪代码来自独立只读 Ghidra 项目。未执行 APK/目标库，未访问业务服务器，也未修改既有报告或工件。Rust 地址为 Ghidra 地址；对应 ELF 虚拟地址减 0x100000。Dart AOT 地址等于 libapp.so 的 ELF 虚拟地址。

已确认的闭环
1. WsEvent 原生内存布局为 +0x00 String1、+0x18 String2、+0x30 四字节事件整数。生成编码器先写整数，再写两个 String；外围 0x1b4058 添加 FRB action byte 0。String 写四字节 UTF-8 字节长度，再写原始字节，无零结尾或对齐。Dart 0x520e6c 的 sse_decode_ws_event 依次读取 getUint32 和两个 String，写 field_7、field_f、field_13。这里的 AOT field 标签不是原始属性名，+0x30 也没有被证明是 Rust enum discriminant。
2. createEventStream 注册 sink/port 到全局 0x2b4430。0x1ec7f0 使用同一个全局上下文，以 external Uint8 Dart_CObject 发送序列化字节；未注册 sink、锁 poison 或 post 失败有 panic 路径。MainPage.initState 0x51f390 调 createEventStream，0x51f3b4 listen，监听闭包为 0x527460，订阅存入状态 field_17。流注册、原生发送、生成解码和业务监听已串联，不再只依赖字符串符号猜测。
3. 连接监视器 0x1a51f0 收到 bool true 构造事件整数10、String1=""、String2=""。0x1e8de4 的 transport 成功路径送 bool true。Dart event10 分支 0x527f34 调 wsLogin(saved JWT)。因此10代表传输连接成功并触发认证，不代表 types50.code==0 的认证成功。
4. 外层 types2 进入 0x1c5f58，检查 data_content 中整数 msg_type 为101、102、113..117，构造事件整数4、String1=""、String2=原始 data_content。Dart event4 从 field_13（第二个String）读取 JSON，调用 jsonDecode 和 Message.fromJson。未被接受的 msg_type 只释放；缺失/类型错误可能 panic。内层 msg_type、外层 types、WsEvent integer 和 FRB action/function id 是不同层次。

认证、错误、被踢与关闭：有限负证据
5. types50 成功分支依据解析响应 code==0，写 SDK+0x2b1=true（分支中重复一次），停止自动重登，建立内部断连 bool 通道，启动心跳、接收/发送 QoS，再置 SDK+0x2a5=true。响应 user_id/data 的 String 最终由 0x1e303c 释放；已审查分发函数没有将这些响应 String 保存到 JWT、URL 或 from String 字段，也没有构造/调用已知 WsEvent 发送器。不能把本地标志写入或启动心跳改写成 Dart 认证成功事件。
6. code!=0 分支调用有门控的关闭辅助函数、停止自动重登、置 SDK+0x2a5=false、释放响应。types52 只条件日志并释放 Protocol，没有发现绑定错误内容的解析/事件构造。types54 调 0x1e2ea0 全量本地停止，包括心跳/QoS/重登与相关通道、认证标志清零。上述已审查分支均未构造已知 WsEvent 整数或两个 String，因此无法给它们分配未经证实的事件码。
7. QoS prepass 会先解析 types50：非零 code 绕过常规 ACK/去重进入分发；零 code 按正常 QoS 去重，重复包 ACK 后丢弃，不进入认证分发。malformed types50 在非 QoS 分发可日志/丢弃，在 QoS prepass 有 unwrap/panic 路径。认证成功结论须加“响应有效且没有在去重门控被丢弃”。
8. transport 初始失败和正在运行的 socket worker 结束，会清 SDK+0x2a5、撤销 transport bool sender、停止心跳，并在内部断连通道存在时发 bool true。内部通道接收器 0x1a5430 调 0x1eab5c 清理并重启自动重登；这条 bool 通道不是 FRB WsEvent 流。事件10监视器的 false 值只日志，closed tag2 只释放；未观察到失败/关闭的 WsEvent 构造。关闭辅助函数受连接标志门控，已确认本地清理不能证明 WebSocket Close 帧实际发出。

扫描边界
9. 当前 Rust ELF 所有 PF_X PT_LOAD 文件区共 {scanned_bytes} 字节、{scanned_words} 个四字节对齐字，逐字解码直接 B/BL，精确目标 ELF 0xec7f0 只有三处 BL：0xa5280、0xc60c8、0xc6194；无直接 B。全部 {rela_count} 项 RELA 中没有 addend 精确指向该函数入口。完整反编译检查范围包括 dispatcher、full stop、disconnect/reconnect、internal notice/receiver、close helper、init connect worker 和 transport worker。
10. 该扫描只覆盖当前库、直接 B/BL 与 RELA 精确入口表示；不穷尽 BR/BLR、计算函数指针、无重定位的指针、指向函数内部的重定位、内联/另一序列化器、其它 ABI/版本或运行时行为。可执行段里的数据字也会被扫描，故命中站点另用 LLVM 和源上下文核验。准确表述是“已审查路径没有通过已知发送器构造/投递认证失败、52、54或关闭事件”，不是“整个 APP 绝对不能通知这些情况”。

init/login/logout 配置
11. init_app 的 FRB id3 没有 SDK 配置参数，审查路径初始化 logging/tracing 和 backtrace/panic。create_event_stream 的 id1 参数是 FRB sink handle。init_ws 的 id4 只有一个 String；0x1d327c 克隆并写 SDK+0x138(capacity)、+0x140(pointer)、+0x148(length)，再连接 transport。MainPage 调用参数由保存的地址 String 做 substring 得到，未把心跳周期作为参数。
12. ws_login 的 id6 只有一个 String，Dart 使用已保存 JWT；0x1cf0e0 写 SDK+0x110/+0x118/+0x120，连接存在时发送 types6，否则等连接成功再送。Future<int> 是本地发送/排队结果，不是服务端 types50.code。ws_logout 的 id7 没有参数；0x1cec94 尝试发送 types3，忽略发送结果，清空保存 JWT String 为(0,1,0)，全量本地停止。无法证明服务端收到退出或 Close 帧发出。
13. SDK lazy constructor 的 RELA 指向0x1dbef8，再到0x1dbaf0。+0xe8 重登周期原值0；+0x30 心跳周期也为0，已核验不对齐 SIMD 写入的零字节重叠：q1全部零，存[x21+0x9f]，载q6=[x21+0x98]，再存[SDK+0x29]，q6 bytes7..14 对应 SDK+0x30..0x37，均为零，不把 padding 当已初始化。getter 分别以0回退30秒/3秒，单位沿用已验证心跳工件。已审查入口没有暴露周期参数或重写这两项；不排除其它未审查路径运行时修改。
14. isContentWs 的 id5已补齐：Dart未序列化任何业务参数；异步vtable经RELA绑定worker 0x1b06b4，再调用0x1b8348/getter0x1e2c04，正常返回仅读取SDK+0x2a5连接标志，不读认证标志或比较host/URL。补充原ELF与导出证据见connection_preview_closure/is_content_ws；错误路径不能概括为false。

产物与复现
event_contract.json 包含已确认/有限负证据/未知项、{source_count} 段带哈希行号的来源、{raw_count} 个原 ELF 指令/BL 检查、{snapshot_count} 段 LLVM 快照、扫描覆盖区和具体限制、合成编码例。event_dispatch_pseudocode.txt 为可读重建伪代码，非原始源码。native_pseudocode/ 为独立导出的 Ghidra 伪代码，根和日志记录本次导出范围。
在项目根目录运行：python3 APP/scripts/ws_event_contract_extract.py
依赖 Python pyelftools 与 /opt/homebrew/opt/llvm/bin/llvm-objdump；可用 --objdump 指定路径。脚本固定输入 ELF SHA256，检查所有来源片段、原始指令字和 BL 目标、RELA 绑定，重建本目录工件，不运行目标代码。未知包括原字段名、其它运行时通知机制、真实服务器行为、交付/时序保证和周期外部修改。
'''


if __name__ == '__main__':
    main()
