#!/usr/bin/env python3
"""Extract and verify static reconnect evidence. Never loads or executes the target ELF."""

from _paths import app_root, workspace_root
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

ROOT = workspace_root()
OUT = ROOT/'APP/analysis/reconnect_preview_failure/reconnect'
RUST = ROOT/'APP/unpacked/lib/arm64-v8a/librust_lib_distinguish.so'
EXPECTED_SHA = '0af3f1f12e57e9b5f2d409343421c1fa21b0bcffe7860a30cf972a1265399847'
TABLE = ROOT/'APP/analysis/ghidra/librust_lib_distinguish.so/functions.tsv'
PRIOR = [ROOT/'APP/analysis/ws_heartbeat/native_pseudocode/functions',
         ROOT/'APP/analysis/login_flow/native_pseudocode/functions',
         ROOT/'APP/analysis/ws_event_contract/native_pseudocode/functions',
         ROOT/'APP/analysis/deep_rust/functions', ROOT/'APP/analysis/deep_rust/lifecycle/functions']


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class Binary:
    def __init__(self):
        assert sha(RUST) == EXPECTED_SHA
        self.f = RUST.open('rb')
        self.elf = ELFFile(self.f)
        assert self.elf.little_endian and self.elf['e_machine'] == 'EM_AARCH64'
        self.loads = [s for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        self.relas = [(s.name, r) for s in self.elf.iter_sections()
                      if isinstance(s, RelocationSection) and s.is_RELA()
                      for r in s.iter_relocations()]

    def read(self, va, size):
        s = next(s for s in self.loads if s['p_vaddr'] <= va and
                 va + size <= s['p_vaddr'] + s['p_filesz'])
        self.f.seek(s['p_offset'] + va - s['p_vaddr'])
        return self.f.read(size)

    def word(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]


def target(word, va):
    if word & 0x7c000000 != 0x14000000:
        return None
    imm = word & 0x3ffffff
    if imm & 0x2000000:
        imm -= 0x4000000
    return va + 4 * imm


def functions():
    rows = []
    for line in TABLE.read_text().splitlines()[1:]:
        a, name, size, external, thunk = line.split('\t')
        if external == 'false':
            rows.append((int(a, 16) - 0x100000, int(size), name, thunk))
    rows.sort()
    return {a: {'reported_body_byte_count': size, 'name': name, 'thunk': thunk,
                'next_entry': rows[i+1][0] if i+1 < len(rows) else a+size}
            for i, (a, size, name, thunk) in enumerate(rows)}


def verify():
    path = OUT/'reconnect_flow.json'
    d = json.loads(path.read_text())
    b = Binary()
    for e in d['source_evidence']:
        p = Path(e['file'])
        assert sha(p) == e['sha256'], e['id']
        ls = p.read_text().splitlines()
        assert '\n'.join(ls[e['start_line']-1:e['end_line']]) == e['excerpt'], e['id']
    for e in d['raw_instruction_checks']:
        a = int(e['elf_va'], 16)
        assert b.read(a, 4).hex() == e['bytes_le']
        assert f'{b.word(a):08x}' == e['word_hex']
        if e['check'] in ['BL_decoded_destination', 'B_decoded_destination']:
            assert b.word(a) & 0xfc000000 == (0x94000000 if e['check'].startswith('BL') else 0x14000000)
            assert target(b.word(a), a) == int(e['target_elf'], 16)
    for e in d['relocation_bindings']:
        rs = [r for _, r in b.relas if r['r_offset'] == int(e['relocation_offset_elf'], 16)]
        assert len(rs) == 1 and rs[0]['r_info_type'] == 1027
        assert rs[0]['r_addend'] == int(e['addend_target_elf'], 16)
    for e in d['raw_data_checks']:
        assert b.read(int(e['elf_va'], 16), e['size']).hex() == e['bytes_le'], e['id']
    for s in d['raw_llvm_snapshots']:
        assert sha(s['file']) == s['sha256']
        raw = b.read(int(s['elf_start'], 16), int(s['elf_end_exclusive'], 16)-int(s['elf_start'], 16))
        assert hashlib.sha256(raw).hexdigest() == s['raw_bytes_sha256']
    for e in d['artifact_manifest']:
        assert sha(e['file']) == e['sha256'], e['file']
    # Recompute the whole-executable-segment direct branch inventory independently.
    inv, stats = scan(b)
    assert inv == d['finite_scan']['direct_B_BL_target_inventory']
    assert stats == d['finite_scan']['coverage']
    # Exact raw constants that establish the empty Close control mapping.
    assert b.read(0x443b0,16) == struct.pack('<QQ', 0x8000000000000004, 0x8000000000000001)
    assert b.word(0xc0ae4) == 0x52800108  # MOV W8,#8, after control-subtype-zero comparisons.
    assert b.word(0xe4b84) == 0x0f000420  # MOVI V0.2S,#1 -> FIN/RSV header low 4 bytes.
    assert d['close_frame']['header_known_bytes'] == '010000000100??00'
    assert d['close_frame']['determined_first_wire_byte'] == '88'
    report = {'passed': True, 'reconnect_json_sha256': sha(path),
              'source_excerpt_count': len(d['source_evidence']),
              'raw_instruction_check_count': len(d['raw_instruction_checks']),
              'relocation_binding_count': len(d['relocation_bindings']),
              'raw_data_check_count': len(d['raw_data_checks']),
              'llvm_snapshot_count': len(d['raw_llvm_snapshots']),
              'artifact_manifest_count': len(d['artifact_manifest']),
              'whole_executable_segment_direct_branch_inventory_recomputed': True,
              'target_code_executed': False, 'business_server_contacted': False,
              'scope': '静态文件SHA、全文摘录、ELF字节、直接BL/B目标、RELA、完整区间指令快照和有限扫描；不证明运行时调度或发包送达。'}
    (OUT/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))


SCAN_TARGETS = [0xe1e9c, 0xeab5c, 0xec290, 0xe8b4c, 0xeaf88, 0xeb278,
                0xa51f0, 0xa556c, 0xa5430, 0xa5cd0, 0xa5ec8, 0xd327c,
                0xe49e0, 0xc0a94]


def scan(b):
    inventory = {hex(t): [] for t in SCAN_TARGETS}
    coverage = []
    for s in b.loads:
        if not s['p_flags'] & 1:
            continue
        start, length = s['p_vaddr'], s['p_filesz']
        data = b.read(start, length)
        first = (-start) % 4
        words = 0
        for off in range(first,len(data)-3,4):
            words += 1
            w = struct.unpack_from('<I',data,off)[0]
            t = target(w,start+off)
            if t in SCAN_TARGETS:
                inventory[hex(t)].append({'elf_va':hex(start+off),
                    'kind':'BL' if w & 0x80000000 else 'B', 'word_hex':f'{w:08x}'})
        coverage.append({'segment_elf_start':hex(start),
                         'segment_elf_end_exclusive':hex(start+length),
                         'file_backed_bytes':length,'aligned_words_inspected':words,
                         'pf_x':True})
    return inventory, coverage


def extract(objdump):
    OUT.mkdir(parents=True,exist_ok=True)
    b = Binary()
    fns = functions()
    copied = OUT/'prior_pseudocode/functions'; copied.mkdir(parents=True,exist_ok=True)
    sources = []

    def source(id_, path, start=1, end=None):
        ls = path.read_text().splitlines(); end = end or len(ls)
        assert 1 <= start <= end <= len(ls)
        sources.append({'id':id_,'file':str(path),'sha256':sha(path),
                        'start_line':start,'end_line':end,'excerpt':'\n'.join(ls[start-1:end])})

    def cpath(gh):
        name=f'{gh:08x}.c'
        for directory in [OUT/'native_pseudocode/functions',OUT/'socket_core_pseudocode/functions']:
            p=directory/name
            if p.exists():return p
        p=next((d/name for d in PRIOR if (d/name).exists()),None)
        assert p is not None,name
        q=copied/name
        if not q.exists() or sha(q)!=sha(p):shutil.copyfile(p,q)
        return q

    methods = {
        'reconnect_transport_poll':0x1a5ec8, 'initial_transport_poll':0x1d327c,
        'outbound_forward':0x1adca8, 'inbound_reader':0x1b29b0,
        'stream_poll_next':0x1b7100, 'fused_reader':0x1b202c,
        'io_wouldblock_adapter':0x1c12f4, 'websocket_core_read':0x1e35bc,
        'channel_poll_next':0x1b6ed4, 'sink_ready':0x1b770c,
        'sink_flush':0x1b7488, 'sink_close':0x1b7204,
        'sink_start_send':0x1af590,'message_to_frame':0x1e4eec,
        'guarded_close':0x1e8b4c,'close_none_frame':0x1e49e0,
        'write_pending_frame':0x1e547c,'encode_write_frame':0x1e3388,
        'frame_buffer':0x1b30d0,'frame_format_bytes':0x1c0a94,
        'add_client_mask':0x24431c,'transport_write':0x1c2d74,
        'transport_flush':0x1c2c0c,'handshake_poll':0x1b231c,
        'handshake_state_machine':0x1b33ec,
        'connect_task_constructor1':0x1a2058,'connect_task_constructor2':0x1a3748,
        'connect_runtime1':0x1dcdb4,'connect_runtime2':0x1d2bb4,
        'connect_executor1':0x197204,'connect_executor2':0x19616c,
        'connect_poll_bridge':0x1a4464,'spawn_connect':0x1bff5c,
        'connect_or_send_login':0x1eaf88,'spawn_deferred_login':0x1bf6c4,
        'deferred_login_monitor':0x1a556c,'initial_flutter_monitor':0x1a51f0,
        'internal_disconnect_monitor':0x1a5430,'spawn_flutter_monitor':0x1bf894,
        'spawn_internal_monitor':0x1bfdb4,'flutter_monitor_bridge':0x1a43b0,
        'internal_monitor_bridge':0x1a45bc,
        'set_transport_notifier':0x1e9588,'transport_success_notify':0x1e8de4,
        'drop_transport_notifier':0x1e9794,'set_outbound_sender':0x1e9378,
        'transport_ended_notify':0x1e1e9c,'internal_sender_option':0x1e2838,
        'restart_relogin':0x1eab5c,'relogin_timer_poll':0x1a5cd0,
        'relogin_tick':0x1ec068,'relogin_period_getter':0x1ec69c,
        'stop_relogin':0x1ec290,'start_relogin_task':0x1bfa3c,
        'relogin_poll_bridge':0x1a4318,'stop_heartbeat':0x1e13c8,
        'heartbeat_check':0x1e1270,'heartbeat_timestamp_setter':0x1e207c,
        'heartbeat_start':0x1e1b0c,'heartbeat_send':0x1e1110,
        'server_protocol_dispatch':0x1e99a0,'send_login_protocol':0x1eb278,
        'local_login_saves_jwt':0x1eb3d4,'native_full_stop':0x1e2ea0,
        'connection_getter':0x1e2c04,'connection_setter':0x1e2d2c,
        'server_response_parser':0x1e303c,
    }
    for id_,gh in methods.items():source('full_'+id_,cpath(gh))
    # Explicit path slices supplement the complete methods, so the early-return proof
    # is reviewable without reading thousands of decompiler temporary assignments.
    focused = [
        ('new_worker_connected_gate_and_saved_url',0x1a5ec8,803,910),
        ('new_worker_ws_wss_default_ports',0x1a5ec8,1096,1113),
        ('new_worker_handshake_failure_early_return',0x1a5ec8,2702,2793),
        ('new_worker_transport_success',0x1a5ec8,2870,2990),
        ('new_worker_select_and_cleanup',0x1a5ec8,3020,3164),
        ('initial_worker_notify_channels',0x1d327c,839,882),
        ('initial_worker_handshake_failure_early_return',0x1d327c,1214,1310),
        ('initial_worker_transport_success',0x1d327c,1380,1493),
        ('initial_worker_transport_cleanup',0x1d327c,3200,3280),
        ('types50_success_monitor_and_restart_services',0x1e99a0,501,531),
        ('types50_reject_close_stop_clear_order',0x1e99a0,533,553),
        ('types54_full_stop',0x1e99a0,227,250),
        ('types51_timestamp_only',0x1e99a0,156,196),
        ('empty_close_header_construction',0x1e49e0,46,90),
        ('close_opcode_and_fin_encoder',0x1c0a94,42,112),
    ]
    for id_,gh,start,end in focused:source(id_,cpath(gh),start,end)
    dart=ROOT/'APP/analysis/aot_dump/asm/distinguish/pages/main/main_page.dart'
    source('dart_event_subscription',dart,9296,9313)
    source('dart_event10_calls_login_with_jwt',dart,11335,11363)

    raw = []
    seen = set()

    def ins(a,label,expected=None,t=None):
        w=b.word(a)
        if expected is not None:assert w==expected,(hex(a),hex(w),hex(expected))
        key=(a,t)
        if key in seen:return
        seen.add(key)
        e={'binary':RUST.name,'elf_va':hex(a),'bytes_le':b.read(a,4).hex(),
           'word_hex':f'{w:08x}','check':'exact_instruction_word','label':label}
        if t is not None:
            assert target(w,a)==t,(hex(a),hex(t))
            e['check']='BL_decoded_destination' if w&0x80000000 else 'B_decoded_destination'
            e['target_elf']=hex(t)
        raw.append(e)

    def calls(a,t,label):
        end=fns[a]['next_entry']; found=[]
        for va in range(a,end,4):
            if target(b.word(va),va)==t:
                ins(va,label,t=t);found.append(hex(va))
        assert found,(hex(a),hex(t),label)
        return found

    pairs=[(0xa5ec8,0xe1e9c,'transport-established cleanup notify'),
           (0xd327c,0xe1e9c,'init-established cleanup notify'),
           (0xa5ec8,0xe9794,'transport cleanup drops one-shot notifier'),
           (0xa5ec8,0xe9378,'transport success stores outbound sender'),
           (0xa5ec8,0xe8de4,'transport success delivers true'),
           (0xd327c,0xe8de4,'init transport success delivers true'),
           (0xd327c,0xbf894,'init creates Flutter transport monitor'),
           (0xa5ec8,0xb231c,'new WebSocket handshake'),
           (0xa5ec8,0xadca8,'outbound forward poll'),
           (0xa5ec8,0xb29b0,'inbound reader poll'),
           (0xe1e9c,0xe13c8,'cleanup stops heartbeat'),
           (0xe1e9c,0xb3b14,'cleanup notifies existing internal sender'),
           (0xa5430,0xeab5c,'internal disconnect monitor starts relogin'),
           (0xa51f0,0xec7f0,'initial transport monitor emits event10'),
           (0xa556c,0xeb278,'deferred monitor sends JWT login only'),
           (0xeaf88,0xe2c04,'login branches on current transport snapshot'),
           (0xeaf88,0xbf6c4,'spawn JWT wait-connect monitor'),
           (0xeaf88,0xbff5c,'spawn new connection attempt'),
           (0xeaf88,0xeb278,'connected branch sends login on existing sender'),
           (0xec068,0xe8b4c,'tick attempts close without await'),
           (0xec068,0xeaf88,'tick clones saved JWT and calls login'),
           (0xa5cd0,0xec69c,'timer reads fixed seconds period'),
           (0xa5cd0,0xec068,'timer immediate/repeated tick'),
           (0xeab5c,0xe2d2c,'restart clears transport first'),
           (0xeab5c,0xe2838,'restart removes internal sender'),
           (0xeab5c,0xec290,'restart stops old timer'),
           (0xeab5c,0xbfa3c,'restart spawns replacement timer'),
           (0xe99a0,0xec290,'auth response stops relogin'),
           (0xe99a0,0xe8b4c,'auth rejection queues close before flag clear'),
           (0xe99a0,0xbfdb4,'auth success installs internal monitor'),
           (0xe99a0,0xe2ea0,'types54 full stop'),
           (0xe8b4c,0xe2c04,'close transport gate'),
           (0xe8b4c,0xb3bf8,'close queues exact Message variant'),
           (0xadca8,0xb6ed4,'forward polls outbound queue'),
           (0xadca8,0xb770c,'forward passes queued message via sink poll-ready'),
           (0xadca8,0xb7488,'forward sink poll-flush'),
           (0xadca8,0xb7204,'forward sink poll-close'),
           (0xb770c,0xaf590,'sink poll-ready starts sending queued Message'),
           (0xb7488,0xaf590,'sink poll-flush starts sending queued Message'),
           (0xb7204,0xaf590,'sink poll-close starts sending queued Message'),
           (0xaf590,0xe4eec,'sink converts message to Frame'),
           (0xe4eec,0xe49e0,'Message variant4 selects Close constructor'),
           (0xe49e0,0xe547c,'Close frame write or flush attempt'),
           (0xe547c,0xe3388,'write-pending encodes a Frame'),
           (0xe3388,0xb30d0,'Frame buffered write'),
           (0xe3388,0x14431c,'role==1 adds mask'),
           (0xb30d0,0xc0a94,'Frame header/payload serialization'),
           (0xe49e0,0xc2d74,'Close flushes remaining transport buffer'),
           (0xe49e0,0xc2c0c,'Close transport flush'),
           (0xb29b0,0xe99a0,'received message enters SDK protocol dispatch'),
           (0xb202c,0xe35bc,'fused wrapper polls core read'),
           (0xb202c,0xc12f4,'read converts WouldBlock into Pending'),
           (0xa4464,0xa5ec8,'new-connect async poll bridge'),
           (0x97204,0xa4464,'new-connect executor1'),
           (0x9616c,0xa4464,'new-connect executor2'),
           (0xa43b0,0xa51f0,'initial monitor poll bridge'),
           (0xa45bc,0xa5430,'internal monitor poll bridge'),
           (0xa4724,0xa556c,'deferred JWT monitor poll bridge'),
           (0x99624,0xa4724,'deferred JWT monitor executor1'),
           (0x96554,0xa4724,'deferred JWT monitor executor2'),
           (0xbf6c4,0xdccbc,'deferred JWT runtime1'),
           (0xbf6c4,0xd2d84,'deferred JWT runtime2'),
           (0xdccbc,0xa3bac,'deferred JWT task constructor1'),
           (0xd2d84,0xa3308,'deferred JWT task constructor2'),
           (0xa4318,0xa5cd0,'auto-relogin timer poll bridge'),
           (0xe1270,0xe1e9c,'heartbeat timeout stops keepalive and internally notifies'),
           (0xe13c8,0xe207c,'heartbeat stop resets timestamp to zero'),
           (0xe1b0c,0xe13c8,'heartbeat restart first stops old tasks/reset timestamp')]
    call_map=[]
    for a,t,label in pairs:
        call_map.append({'caller_entry_elf':hex(a),'target_elf':hex(t),'label':label,
                         'branch_sites':calls(a,t,label)})
    words={0xa6dc0:0x52800028,0xa6dc8:0x390a96a8,
           0xa6a78:0xf1000aff,0xa6a7c:0x54000b21,
           0xd3fd0:0xf1000b7f,0xd3fd4:0x54000b41,
           0xa6018:0x910a96a8,0xa6020:0x39400108,0xa6038:0x360004a8,
           0xa70f4:0x390a96bf,0xe1720:0xaa1f03e1,
           0xd4328:0x52800028,0xd4330:0x390a9688,
           0xe4a20:0xb24107e8,0xe4a24:0x5280002a,0xe4a28:0x3903eaaa,
           0xe4a34:0xaa1f03fa,0xe4a38:0xaa1f03f7,0xe4a3c:0x5280003b,
           0xe4b84:0x0f000420,0xe4b98:0xa9376fba,0xe4b9c:0xf81803b7,
           0xe4ba0:0x7818c3aa,0xe4ba4:0xbc1883a0,0xe4ba8:0x3818f3bf,
           0xc0ab8:0x7940380a,0xc0ad0:0x53083d2a,0xc0ad4:0x360000c9,
           0xc0ad8:0x7100055f,0xc0ae0:0x3500192a,0xc0ae4:0x52800108,
           0xc0b00:0x39406268,0xc0bac:0x3900058a,0xc0bb0:0x3900018d}
    for a,w in words.items():ins(a,'selected state/Close/opcode instruction',expected=w)
    ins(0xa6bdc,'handshake failure bypasses established cleanup and returns Ready',t=0xa7208)
    ins(0xd4138,'init handshake failure bypasses established cleanup and returns Ready',t=0xd474c)

    reloc_specs=[(0x1a2968,0xbacdc,0x97204),(0x1a2e68,0xbacf4,0x9616c),
                 (0x1a2f58,0xbaccc,0x99624),(0x1a2d78,0xbace0,0x96554),
                 (0x1a2c38,0xbacbc,0x9636c),(0x1a2c88,0xbacc8,0x9673c),
                 (0x1a2a58,0xbacc0,0x986ec),(0x1a3098,0xbace8,0x98504),
                 (0x1a2af8,0xbacf0,0x98d44),(0x1a2aa8,0xbad08,0x988d4)]
    bindings=[]
    for offset,thunk,worker in reloc_specs:
        matches=[r for _,r in b.relas if r['r_offset']==offset]
        assert len(matches)==1 and matches[0]['r_addend']==thunk
        assert matches[0]['r_info_type']==1027
        ins(thunk,'task-table relocation thunk to executor',t=worker)
        bindings.append({'relocation_offset_elf':hex(offset),'type':'R_AARCH64_RELATIVE',
                         'addend_target_elf':hex(thunk),'thunk_branch_target_elf':hex(worker)})

    raw_dir=OUT/'raw_llvm';raw_dir.mkdir(exist_ok=True)
    snapshots=[]
    snap_entries={gh-0x100000 for gh in methods.values()}
    snap_entries.add(0xa4724)
    snap_entries.update([0xa3bac,0xa3308,0xdccbc,0xd2d84])
    snap_entries.update(worker for _,_,worker in reloc_specs)
    snap_entries.update(thunk for _,thunk,_ in reloc_specs)
    for a in sorted(snap_entries):
        assert a in fns,hex(a)
        end=fns[a]['next_entry']
        p=raw_dir/f'{a:08x}.asm'
        out=subprocess.run([objdump,'-D','--triple=aarch64',f'--start-address={hex(a)}',
                            f'--stop-address={hex(end)}',str(RUST)],check=True,capture_output=True,text=True).stdout
        p.write_text(out)
        snapshots.append({'binary':RUST.name,'elf_start':hex(a),'elf_end_exclusive':hex(end),
                          'file':str(p),'sha256':sha(p),'raw_bytes_sha256':hashlib.sha256(b.read(a,end-a)).hexdigest(),
                          'ghidra_reported_body_byte_count':fns[a]['reported_body_byte_count'],
                          'range_note':'连续入口到下一已知函数入口，包含可能的未分配间隙；不以Ghidra body字节总数推算末地址。'})

    inv,coverage=scan(b)
    d={
      'scope':{'kind':'仅静态逆向','target_code_executed':False,'business_server_contacted':False,
               'addressing':'Ghidra VA = ELF VA + 0x100000；JSON原指令与RELA地址为ELF VA。',
               'normal_path_precondition':'所列时序假设锁/poison/分配/unwrap等helper正常返回；Close入队失败可panic并在后续stop timer/清flag之前中断，不是finally保证。'},
      'input':{'binary':str(RUST),'sha256':EXPECTED_SHA,'function_table':str(TABLE),'function_table_sha256':sha(TABLE)},
      'confirmed':{
        'connection_worker':'conn=false 时重登连接worker读取SDK保存URL(+0x138/+0x140/+0x148)，重新构建请求并走ws/wss、DNS/TCP、可选TLS与WebSocket握手状态机。实际poll开头再次检查conn，若已为true可直接结束。',
        'initial_failure':'初次init poll1d327c以及重登连接poll1a5ec8的握手失败分支均释放错误/URL/临时出站Message channel等资源后直接Ready退出，绕过e1e9c内部断线通知。不是撤掉SDK保存的bool transport notifier：失败分支未调e9794，故1a51f0/1a556c通常仍Pending，直到后续e9588替换sender或e9794/fullstop撤sender。',
        'established_end':'已经成功建立连接的forward或reader完成/错误/EOF分支清conn、移除一次性transport notifier，再e1e9c停止heartbeat，并仅在SDK internal sender存在时发true。',
        'timer_start':'types50.code0创建internal channel及1a5430 monitor。该monitor收到bool0或1均调用eab5c。eab5c清conn、删除internal sender、停止heartbeat/QoS/旧relogin，启动新relogin任务并保存handle。',
        'period':'1a5cd0先立即ec068，然后固定周期poll tick；SDK+0xe8=0时ec69c返回3。Duration参数的nanos=0，故默认3秒；现有已审查初始化参数没有修改它。',
        'timer_tick':'ec068先guarded close helper，再clone SDK+0x110保存的JWT→eaf88；不等待Close完成。eaf88按当时conn取值：false建立新连接+JWT等待任务，true在当前sender发送types6。',
        'jwt':'本地wsLogin入口保存输入String到SDK+0x110；自动重登直接复用该String。关闭/EOF/心跳超时自身不清JWT；公开logout在本地清空JWT再full-stop。这里没有JWT刷新/HTTP获取调用。',
        'auth':'types50解析成功且code0写auth=true，停止relogin、安装internal monitor并重启heartbeat/QoS，设置conn=true。user_id/data解析为局部String，业务处理后e303c释放，未确认写入SDK。transport event10本身不是认证成功。',
        'auth_reject':'types50解析成功而code非0按close→stoprelogin→conn=false顺序执行；此分支未建立internal channel。排队Close以后是否能再次启动timer取决于当时仍存在的internal sender/monitor或已排队通知。',
        'fullstop':'types54调用e2ea0：conn=false、删除internal sender和transport notifier、停止relogin/QoS/heartbeat，然后guarded close(通常因conn已false不入队)，auth=false；不等价于保证发送Close。',
        'state_restore':'transport建立先写conn=true并存outbound sender，再发一次true通知；auth=true来自后续types50.code0；user_id/data仅确认局部String解析后由e303c释放，未确认写入SDK。普通断线未显式清auth；fullstop清auth。停止QoS任务本身未清其map。心跳停止e13c8尾部调用e207c(SDK,0)，清last_time(+0x48)，发送会在0时初始化当前epoch秒；不是保留旧心跳时间戳。'
      },
      'notification_layers':[
        {'poll_ghidra':'0x1a51f0','channel':'init_ws的一次性transport通知','when_installed':'init_ws poll1d327c','pending_tag':3,'closed_tag':2,
         'true':'WsEvent事件整数10，两空String；Dart监听随后wsLogin(staticJWT)','false':'仅日志；没有该分支的Flutter事件','auth_meaning':'只表示transport建立'},
        {'poll_ghidra':'0x1a556c','channel':'eaf88 conn=false的一次性transport通知','when_installed':'eaf88→bf6c4','pending_tag':3,'closed_tag':2,
         'true':'clone捕获JWT→eb278→types6，不发event10','false':'仅日志，不发送types6','closed':'释放捕获JWT并退出'},
        {'poll_ghidra':'0x1a5430','channel':'SDK内部断线通知','when_installed':'types50.code0→e2838+bfdb4','pending_tag':3,'closed_tag':2,
         'true_or_false':'均eab5c启动/替换重登timer','closed':'退出','flutter_event':'本路径没有确认WsEvent生产'}],
      'scenario_matrix':[
        {'scenario':'首次握手失败','condition':'尚未认证成功；没有先前relogin timer/internal sender','timeline':['init worker握手返回错误','清临时出站Message channel及请求资源','worker Ready退出，SDK bool transport notifier保留','init monitor通常继续Pending；未来替换/撤sender才可能closed2退出'],
         'result':'该失败路径不自动创建relogin timer，不产生event10，Dart因此不由该事件调用wsLogin。'},
        {'scenario':'已有relogin timer的一次握手失败','condition':'之前由断线internal monitor创建timer且未被stop','timeline':['timer tick→eaf88(false)→new handshake','握手错误早退','本连接任务未停止独立timer','后续固定tick继续'],
         'result':'允许下一次尝试；后续eaf88(false)的e9588替换bool notifier可使上一等待JWT monitor读closed释放JWT。没有指数退避或总次数限制的已审查poll逻辑。'},
        {'scenario':'认证成功后的正常/异常断线','condition':'internal sender与monitor仍在，且该send能成功排队','timeline':['已建立worker收发一方结束/错误/EOF','conn=false→drop transport notifier→e1e9c','internal bool true','1a5430→eab5c','删除internal sender并停止旧服务','新timer immediate tick→eaf88(false)','新握手成功→1a556c→types6保存JWT','types50.code0→stop timer并恢复auth/heartbeat/QoS'],
         'result':'闭合自动重连与重登录链；成功恢复需要服务端再次code0。'},
        {'scenario':'已建立transport但首次认证code非0','condition':'尚无types50.code0建立的internal sender','timeline':['guarded close可能排队','stop timer(若存在)','conn=false','异步Close/write/EOF→transport cleanup','internal sender不存在，e1e9c无bool通知'],
         'result':'没有该审查链再次启动timer的证据。'},
        {'scenario':'重连后的认证拒绝','condition':'断线monitor已在eab5c删除旧internal sender，尚未新认证成功；忽略尚未处理的旧队列/race','timeline':['relogin timer存在','transport建立→deferred JWT sends6','types50.code非0→stop timer→conn=false','Close/EOF cleanup发现无internal sender'],
         'result':'本地timer可停止；不能把认证失败写成始终继续或永远停止。若历史internal通知仍排队/旧sender仍存在可再次启动。'},
        {'scenario':'同一已认证连接上的后续登录拒绝','condition':'先前code0的internal sender尚存在','timeline':['close在conn清零前排队','当场stop relogin','conn=false','若Close被异步消费/连接结束','e1e9c可通知internal monitor','eab5c可重新start timer'],
         'result':'stop以后再次start的条件链已确认；依赖sender存在/成功通知与异步调度，不保证发生。'},
        {'scenario':'心跳超时','condition':'已启动heartbeat checker，elapsed达到period+5；默认35秒阈值/2秒检查周期','timeline':['e1270检查→e1e9c','stop heartbeat并将last_time重置0','e1e9c发internal true(若存在)','monitor→eab5c清conn、删除internal sender→timer'],
         'result':'超时先停止心跳并通知内部monitor；conn清零在monitor消费后，不在e1270当场执行。eab5c先清conn后guarded close，通常不在此发Close。'},
        {'scenario':'types54被踢/主动logout','condition':'fullstop顺序；无预先排队旧internal通知/race','timeline':['types54→e2ea0；或logout先尝试types3并清JWT再e2ea0','删除internal sender/transport notifier','停止timer/QoS/heartbeat，清conn/auth','后续worker cleanup没有新的internal sender可通知'],
         'result':'不显式启动重连；不能静态排除已排队/正在运行任务的竞态。types54本身不清保存JWT，logout清空。'}],
      'close_frame':{'input_constant_elf':'0x443b0','input_qwords':['0x8000000000000004','0x8000000000000001'],
        'chain':['e8b4c(conn true + outbound Option)','b3bf8(queue)','adca8','b770c/b7488/b7204','af590','e4eec variant4','e49e0(None)','e547c','e3388','b30d0','c0a94','transport write/flush'],
        'header_known_bytes':'010000000100??00','header_note':'Frame+0x18 FIN1、+0x19..1b RSV0、+0x1c control bit1、+0x1d subtype0、+0x1f初值mask0；+0x1e是此variant未使用槽，不断言整个qword。',
        'payload_length':0,'opcode':8,'determined_first_wire_byte':'88',
        'mask_condition':'core+0xf8==1时e3388调用24431c增加4字节mask；未执行目标以观察随机值。',
        'delivery_limit':'确定Message→Close(None)构造、opcode编码及transport write/flush尝试；不保证conn门控通过、通道存在、队列被消费、写入完成、对端收取或完成关闭握手。'},
      'read_terminal':{'fused_wrapper':'b202c：标记+0x131后下一次返回16(EOF)，17(Pending)在读任务返回true；其他错误先返回一次并标fused，再EOF。内部c12f4把WouldBlock转换Pending而非断线。',
         'close_vs_eof':'core e35bc对底层Frame None：写closedstate4；先前closing-state满足(mask&6)==2走错误码3，否则错误码8。读取已closedstate4走错误码4。b202c对3/4折为EOF；8等错误先报告再fuse。这里只用数字/判定，不将未恢复的错误枚举名当证据。',
         'cleanup_join':'b29b0 EOF/终止以及adca8 forward结束/失败都使已建立transport select结束并进入统一cleanup。',
         'business_message':'b29b0收到Message转换bytes→e99a0；消息业务types与poll/错误variant的数字不是同一命名空间。'},
      'inferences':[
        '若一次握手跨后续timer tick且conn仍false，eaf88可再次spawn；新worker启动时仍false则通过gate。所审查gate没有独立inflight检查，因此多个连接尝试在途是有条件可能，不证明具体调度或实际数量。',
        '已有timer且未被stop时，独立连接worker早退后下一tick仍可新尝试，这是已闭合任务关系上的静态时序推断。',
        'code非0 stop后的异步Close→cleanup→旧internal monitor可start属于有条件时序，不保证具体调度。',
        '由于tick不await Close，conn仍true时存在把types6送旧sender、稍后才cleanup的时序窗口；未测量实际发生概率。'],
      'unknowns':[
        '锁poison、分配失败、发送队列unwrap失败可panic，正常路径后续清理不保证执行；未执行目标验证发生条件。',
        '异步任务取消是否立即终止已排队/正在执行的通知、具体调度race和在途消息数量。',
        '业务服务器对保存JWT过期/刷新、重复登录、Close与重握手的实际政策，以及服务端是否继续接受原JWT。',
        'OS/DNS/TCP/TLS异常的所有具体错误枚举与每种平台触发条件；本工件闭合统一失败/EOF出口而非全错误枚举表。',
        '队列写出、对端收到Close和收到types6的实际时刻；恢复完成需要新types50.code0，不由本地return0/event10保证。'],
      'source_evidence':sources,'raw_instruction_checks':raw,'raw_llvm_snapshots':snapshots,
      'relocation_bindings':bindings,'direct_call_map':call_map,
      'raw_data_checks':[{'id':'queued_close_none_object','binary':RUST.name,'elf_va':'0x443b0','size':16,'bytes_le':b.read(0x443b0,16).hex(),'check':'exact_static_bytes'}],
      'finite_scan':{'coverage':coverage,'direct_B_BL_target_inventory':inv,
        'rela_entries_inspected':len(b.relas),'method':'整个PF_X文件映射按4字节对齐扫描，仅解直接B/BL；RELA只检查精确目标entry/thunk绑定，不模拟运行时重定位或寄存器。',
        'exclusions':['未将BLR/BR寄存器目标、计算跳表、函数指针别名、堆/栈数据流全部穷举','C伪代码类型与变量名可能失真；控制分支用原ELF关键比较/BL、完整区间hash互证','握手失败没有通知的结论针对两poll完整已审查失败分支，不推广到未审查task或所有外部网络状态。']},
      'prior_artifacts':[{'file':str(p),'sha256':sha(p)} for p in [
        ROOT/'APP/analysis/ws_heartbeat/heartbeat_lifecycle.json',
        ROOT/'APP/analysis/login_flow/native_login_flow.json',
        ROOT/'APP/analysis/ws_event_contract/event_contract.json']],
      'prior_correction':{'artifact':'APP/analysis/ws_heartbeat/heartbeat_lifecycle.json',
        'superseded_fact_id':'stale_heartbeat_after_relogin',
        'reason':'先前旧事实未覆盖e13c8尾部行350：它e207c(SDK,0)重置last_time；本轮完整方法与原BL检查明确纠正，不修改旧文件。'},
    }
    (OUT/'reconnect_flow.json').write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
    write_text(d)
    # Freeze every new decompiler source/status and generated explanation, not earlier agent work.
    manifest=[]
    for p in sorted(OUT.rglob('*')):
        if p.is_file() and p.name not in ['reconnect_flow.json','verification.json'] and p.suffix!='.log':
            manifest.append({'file':str(p),'sha256':sha(p),'bytes':p.stat().st_size})
    d['artifact_manifest']=manifest
    (OUT/'reconnect_flow.json').write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
    verify()


def write_text(d):
    lines=['Rust断线、重连与认证恢复：本轮静态闭合说明',
           '目标库 SHA256 '+EXPECTED_SHA,
           '地址：Ghidra=ELF+0x100000。仅读ELF、反编译与AOT；未运行APK/库，也未联系业务服务器。',
           '', '一、关键确认']
    for k,v in d['confirmed'].items():lines.append(k+'：'+v)
    lines.extend(['','二、三个通知层（通道poll编码与业务types数字分开）'])
    for x in d['notification_layers']:lines.append(json.dumps(x,ensure_ascii=False))
    lines.extend(['','三、按条件的时序；不是运行时实测'])
    for x in d['scenario_matrix']:
        lines.extend([x['scenario']+'；条件：'+x['condition'],' → '.join(x['timeline']),x['result'],''])
    lines.extend(['四、空Close与EOF边界',json.dumps(d['close_frame'],ensure_ascii=False,indent=2),
                  json.dumps(d['read_terminal'],ensure_ascii=False,indent=2),'','五、推断与未知'])
    for x in d['inferences']:lines.append('推断：'+x)
    for x in d['unknowns']:lines.append('未知：'+x)
    lines.extend(['','六、证据与复现',
       'reconnect_flow.json存完整方法摘录、原文件SHA与行号、原ELF BL/B/指令/常量字节、10项RELA、可复核扫描范围。',
       'native_pseudocode与socket_core_pseudocode为本轮只读独立Ghidra项目导出；prior_pseudocode为已完成前轮方法的冻结副本。',
       'raw_llvm/*.asm为完整连续入口区间。函数body byte count可能非连续，区间采用当前函数入口至下一入口并明示未分配gap边界。',
       'python3 APP/scripts/reconnect_flow_extract.py --verify；重提取用同脚本无--verify。',
       '有限扫描：'+json.dumps(d['finite_scan']['coverage'],ensure_ascii=False),
       '仅B/BL直接目标及精确RELA绑定；没有穷尽BLR/BR、computed jump和指针别名。',
       '', '七、精确来源索引'])
    for e in d['source_evidence']:
        lines.append(f"{e['id']}：{e['file']}:{e['start_line']}..{e['end_line']} SHA256={e['sha256']}")
    (OUT/'中文说明.txt').write_text('\n'.join(lines)+'\n')
    pseudo='''以下是按证据重建的可读伪代码；名称用于解释，不是恢复的Rust源码。省略锁/poison/Arc引用计数，但不省略通知与await界限。

init_ws(url):
    save SDK.url
    transport_notify = new_bool_channel()
    spawn initial_flutter_monitor(transport_notify.receiver) // 1a51f0
    attempt = establish_ws(saved_url) // 1d327c handshake states
    if attempt.failed:
        dispose request/error/temporary outbound Message channel refs
        // SDK.saved bool transport_notifier remains; monitor can stay Pending
        return Ready // 不进入established cleanup，无internal-disconnect通知
    install_outbound_sender(attempt.sender)
    SDK.connected = true
    deliver_one_shot_transport(true)
    await established_read_or_forward_end()
    established_cleanup()

initial_flutter_monitor(receiver):
    loop poll receiver:
        Pending3 -> suspend
        Closed2 -> dispose, finish
        false -> log only
        true -> send_to_Dart WsEvent(integer=10,string1="",string2="")
    // Dart event10 branch: wsLogin(Utils.savedJwt);不代表服务端已认证

native_wsLogin(jwt):
    SDK.savedJwt = clone(jwt) // local-login entry
    return connect_or_send_login(jwt) // local return0/3/203;不是types50.code

connect_or_send_login(jwt): // eaf88
    if SDK.connected == false:
        notify = new_bool_channel()
        replace SDK.transport_notifier(notify.sender)
        spawn deferred_login_monitor(captured_jwt=jwt,receiver=notify.receiver)
        guarded_close_queue() // 此刻conn false通常no-op
        spawn transport_connect_worker()
        return 0 // 不await握手，也不await认证
    return send_login_protocol(clone(jwt)) // types6 on existing outbound sender

transport_connect_worker(): // bfF5c -> task RELA -> executor -> a4464 -> a5ec8
    if SDK.connected == true: return Ready
    request = clone SDK.url under lock
    attempt = DNS/TCP/optional_TLS/WebSocket_handshake(request)
    if attempt.failed:
        dispose request/error/temporary outbound Message channel refs
        // SDK.saved bool notifier not removed here; replacement/fullstop may close it later
        return Ready // 不stop独立relogin timer，也不internal-notify
    SDK.connected = true
    install_outbound_sender(attempt.sender)
    deliver_one_shot_transport(true)
    await select(outbound_forward_done_or_error, inbound_reader_EOF_or_error)
    established_cleanup()

deferred_login_monitor(jwt, receiver): // 1a556c，不是1a51f0
    loop poll receiver:
        Pending3 -> suspend
        Closed2 -> free captured JWT; finish
        false -> log only
        true -> send_login_protocol(clone(jwt)) // types6；无event10

established_cleanup():
    SDK.connected = false
    drop SDK.transport_notifier
    stop_heartbeat()
    if SDK.internal_disconnect_sender exists:
        try_send_bool(true) // e1e9c；通道失败/不存在不自动spawn timer
    dispose socket task state

types50(login_response):
    if parser rejects: log/drop; return // 不等同code!=0
    if response.code == 0:
        SDK.auth = true
        // user_id/data are parsed local Strings; no confirmed SDK assignment
        stop_relogin()
        ch = new_bool_channel()
        SDK.internal_disconnect_sender = ch.sender
        spawn internal_disconnect_monitor(ch.receiver) // 1a5430
        restart heartbeat & QoS tasks
        SDK.connected = true
        release response.user_id/data local Strings // e303c after business handling
    else:
        guarded_close_queue() // conn clear前排Close；没有await
        stop_relogin()
        SDK.connected = false
        // 不新建internal sender；如果旧notify还存在/排队可后来restart

internal_disconnect_monitor(receiver):
    loop poll receiver:
        Pending3 -> suspend
        Closed2 -> finish
        received false or true -> restart_relogin()

restart_relogin(): // eab5c
    SDK.connected = false
    drop SDK.internal_disconnect_sender
    guarded_close_queue() // flag已false通常no-op
    stop heartbeat & QoS receive & QoS send
    stop_relogin()
    handle = spawn fixed_interval_relogin_timer()
    save handle in SDK+0xf8

fixed_interval_relogin_timer():
    period_seconds = SDK+0xe8 or 3
    immediately relogin_tick()
    loop await fixed_interval_tick(period_seconds,nanoseconds=0):
        relogin_tick()
    // 已审查poll无指数退避或总尝试次数限制
    // 不await每tick的新连接；若握手仍Pending/conn false，后续tick可spawn更多尝试

relogin_tick(): // ec068
    guarded_close_queue() // 不await关闭、也不在这里直接清connected
    jwt = clone SDK.savedJwt (+0x110) under lock
    connect_or_send_login(jwt)
    // 当前connected真假决定走新握手或旧sender；不能写每tick必定重新握手

guarded_close_queue(): // e8b4c
    if SDK.connected == false: return
    if SDK.outbound_sender is absent: return
    try_send Message(variant4, None=0x8000000000000001)
    // 消费后 adca8->b770c/b7488/b7204->af590->e4eec->e49e0
    // ->Frame(FIN1,opcode8,payload empty)->write/flush attempt
    // 不保证队列被消费或对端收到Close

full_stop(): // types54、logout最终到此
    SDK.connected = false
    drop internal_disconnect_sender and transport_notifier
    stop relogin, QoS send/receive, heartbeat
    guarded_close_queue() // 此时flag已false通常no-op
    SDK.auth = false
    // types54不清JWT；logout先尝试types3、清保存JWT后才full_stop

边界：以上正常路径未穷举已排队/已调度通知的取消竞态。握手失败分支不能推广成全部连接异常；异常/EOF清理需要先成功建立，自动重连还需要internal sender/monitor存在或已有timer。重登local return、event10、connected=true均不替代types50.code0认证。
'''
    (OUT/'可读重建伪代码.txt').write_text(pseudo)


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--verify',action='store_true')
    parser.add_argument('--objdump',default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    args=parser.parse_args()
    verify() if args.verify else extract(args.objdump)
