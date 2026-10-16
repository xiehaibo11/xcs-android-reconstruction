#!/usr/bin/env python3
"""Rebuild a bounded static native authentication failure audit.

Reads prior Ghidra exports and uses llvm-objdump to read the original ELF.
Does not load, link, call or execute target APK/native/Dart code.
"""

from _paths import app_root, workspace_root
from pathlib import Path
from functools import lru_cache
import hashlib
import json
import re
import shutil
import struct
import subprocess

BASE = app_root()
OUT = BASE / 'analysis/reconnect_preview_failure/authentication'
RUST = BASE / 'unpacked/lib/arm64-v8a/librust_lib_distinguish.so'
LLVM = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
EXPECTED_SHA = '0af3f1f12e57e9b5f2d409343421c1fa21b0bcffe7860a30cf972a1265399847'
LOGIN = BASE / 'analysis/login_flow/native_pseudocode/functions'
HEART = BASE / 'analysis/ws_heartbeat/native_pseudocode/functions'
DEEP = BASE / 'analysis/deep_rust/lifecycle/functions'
FUNCS = BASE / 'analysis/deep_rust/functions'
SOURCES = {
    'public_ws_login': LOGIN/'001cf0e0.c',
    'i32_reply': LOGIN/'001b4130.c',
    'dart_port_send': LOGIN/'001b0630.c',
    'login_gate': LOGIN/'001eaf88.c',
    'login_construct': LOGIN/'001eb278.c',
    'login_connection_waiter': LOGIN/'001a556c.c',
    'init_connection_event10_waiter': LOGIN/'001a51f0.c',
    'local_send': DEEP/'001eb854.c',
    'inbound_dispatch': DEEP/'001e99a0.c',
    'login_response_parser': HEART/'001c6e5c.c',
    'login_response_visitor': FUNCS/'001ca468.c',
    'response_i32_parser': FUNCS/'001c942c.c',
    'response_string_parser': FUNCS/'001ca2f8.c',
    'response_sequence_string': FUNCS/'001c9b8c.c',
    'response_drop': HEART/'001e303c.c',
    'gated_close': HEART/'001e8b4c.c',
    'timeout_check': HEART/'001e1270.c',
    'timeout_action': HEART/'001e1e9c.c',
    'heartbeat_stop': HEART/'001e13c8.c',
    'heartbeat_start': HEART/'001e1b0c.c',
    'last_heartbeat_set': HEART/'001e207c.c',
    'internal_monitor': HEART/'001a5430.c',
    'internal_monitor_set': HEART/'001e2838.c',
    'disconnect': LOGIN/'001eab5c.c',
    'relogin_attempt': HEART/'001ec068.c',
    'relogin_poll': HEART/'001a5cd0.c',
    'relogin_period': HEART/'001ec69c.c',
    'relogin_stop': HEART/'001ec290.c',
    'task_cancel': HEART/'00218fe0.c',
    'connection_notification_clear': HEART/'001e9794.c',
    'full_stop': DEEP/'001e2ea0.c',
    'public_logout': HEART/'001cec94.c',
    'noop_helper': HEART/'001eca5c.c',
}
RANGES = [
    ('three_bool_monitors',0xa51f0,0xa5768),
    ('heartbeat_and_relogin_polls',0xa5a18,0xa5ec8),
    ('i32_result_serializer',0xb4130,0xb41f4),
    ('public_wslogin_poll',0xcf0e0,0xcf4cc),
    ('response_parser_wrapper',0xc6e5c,0xc6fc0),
    ('response_i32_parser',0xc942c,0xc960c),
    ('response_sequence_string',0xc9b8c,0xc9d00),
    ('response_string_and_visitor',0xca2f8,0xcad98),
    ('heartbeat_timeout_and_stop',0xe1270,0xe207c),
    ('last_heartbeat_set',0xe207c,0xe236c),
    ('internal_sender_and_full_stop',0xe2838,0xe31e0),
    ('gated_close',0xe8b4c,0xe8de4),
    ('auth_dispatch_disconnect_login',0xe99a0,0xeb3d4),
    ('send_relogin_stop_and_period',0xeb854,0xec7f0),
    ('task_cancel',0x118fe0,0x1190b8),
]


@lru_cache(maxsize=None)
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(p, line):
    return {'file':str(p), 'line':line, 'excerpt':p.read_text().splitlines()[line-1], 'sha256':sha(p)}


def anchors(name, needles):
    p = SOURCES[name]
    lines = p.read_text().splitlines()
    result = []
    for needle in needles:
        matches = [i+1 for i,s in enumerate(lines) if needle in s]
        assert matches, (name,needle)
        result.extend(ref(p,i) for i in matches)
    return sorted({r['line']:r for r in result}.values(),key=lambda r:r['line'])


def offset(data, a):
    ph = struct.unpack_from('<Q',data,32)[0]
    size, count = struct.unpack_from('<HH',data,54)
    for i in range(count):
        typ,flags,off,va,pa,fs,ms,align = struct.unpack_from('<IIQQQQQQ',data,ph+i*size)
        if typ == 1 and va <= a < va+fs:
            return off+a-va
    raise ValueError(hex(a))


def parse_raw(p, data):
    result = []
    for n,s in enumerate(p.read_text().splitlines(),1):
        m = re.match(r'^\s*([0-9a-f]+):\s*([0-9a-f]{8})\s+(.+)',s)
        if not m:
            continue
        a,w = int(m[1],16), int(m[2],16)
        off = offset(data,a)
        raw = data[off:off+4]
        assert raw == w.to_bytes(4,'little'), (hex(a),s)
        r = ref(p,n)
        r.update(elf_file=str(RUST),elf_sha256=sha(RUST),elf_virtual_address=hex(a),
                 file_offset=hex(off),raw_bytes_hex=raw.hex(),instruction_word_hex=f'{w:08x}',instruction=m[3])
        if w&0xfc000000 == 0x94000000:
            imm = w&0x3ffffff
            if imm&0x2000000:
                imm -= 0x4000000
            t = a+imm*4
            assert int(re.search(r'\bbl\s+0x([0-9a-f]+)',m[3])[1],16) == t
            r['bl_target'] = hex(t)
        result.append(r)
    return result


def main():
    assert sha(RUST) == EXPECTED_SHA
    OUT.mkdir(parents=True,exist_ok=True)
    cdir,rawdir = OUT/'complete_native_bodies',OUT/'raw_llvm'
    cdir.mkdir(exist_ok=True); rawdir.mkdir(exist_ok=True)
    groups = {}
    for name,p in SOURCES.items():
        assert p.is_file(),p
        dest = cdir/p.name
        shutil.copyfile(p,dest)
        assert sha(dest) == sha(p)
        groups[name] = {'file':str(p),'sha256':sha(p),'line_count':len(p.read_text().splitlines()),
                        'copied_complete_ghidra_body':str(dest),'copied_sha256':sha(dest),
                        'body_kind':'complete prior Ghidra decompilation; reconstructed variable types are not original Rust source'}
    raw = []
    ranges = []
    data = RUST.read_bytes()
    for name,start,end in RANGES:
        p = rawdir/(name+'.asm.txt')
        r = subprocess.run([LLVM,'-d',f'--start-address={start}',f'--stop-address={end}',str(RUST)],capture_output=True,text=True,check=True)
        p.write_text(r.stdout)
        rows = parse_raw(p,data)
        assert rows
        raw.extend(rows)
        ranges.append({'name':name,'start':hex(start),'end_exclusive':hex(end),'file':str(p),'sha256':sha(p),
                       'word_count':len(rows),'extent_note':'audited address range; may include padding or adjacent helper instructions; not a claimed original function symbol size'})
    # An allocation/formatting helper appearing widely in C is literally RET.
    p = rawdir/'noop_helper.asm.txt'
    r = subprocess.run([LLVM,'-d','--start-address=0xeca5c','--stop-address=0xeca60',str(RUST)],capture_output=True,text=True,check=True)
    p.write_text(r.stdout)
    noops = parse_raw(p,data); assert len(noops)==1 and noops[0]['instruction'].strip()=='ret'
    raw.extend(noops)
    by_addr = {int(r['elf_virtual_address'],16):r for r in raw}
    # Raw Close(None) payload verified by android_surface's independent sender/frame audit.
    const_addr = 0x443b0
    off = offset(data,const_addr)
    b = data[off:off+16]
    assert struct.unpack('<QQ',b) == (0x8000000000000004,0x8000000000000001)
    control = {'elf_file':str(RUST),'elf_sha256':sha(RUST),'elf_virtual_address':hex(const_addr),
               'file_offset':hex(off),'raw_bytes_hex':b.hex(),'qword_hex':['8000000000000004','8000000000000001'],
               'interpretation':'outbound tungstenite Message variant4 Close(None); cross-layer send/frame proof supplied by transport sibling audit; queueing is not evidence of peer receipt'}
    evidence = {
        'jwt_write_and_reply':anchors('public_ws_login',['+ 0x110','+ 0x118','+ 0x120','FUN_001eaf88','FUN_001b4130','FUN_001b0630']),
        'reply_format':anchors('i32_reply',['*puStack_48 = param_2','puStack_48 + 1','local_40 = 5']),
        'connect_or_send':anchors('login_gate',['FUN_001e2c04','FUN_001e9588','FUN_001bf6c4','FUN_001bff5c','return 0','FUN_001eb278']),
        'deferred_login':anchors('login_connection_waiter',['bVar3 == 3','bVar3 == 2','(bVar3 & 1) == 0','FUN_001eb278']),
        'event10_separate':anchors('init_connection_event10_waiter',['(bVar3 & 1) == 0','local_60 = 10','FUN_001ec7f0']),
        'local_send_result':anchors('local_send',['FUN_001e2c04','uVar18 = 0xcb','FUN_001c6ce0','uVar18 = 500','uVar18 = 0x1f5','FUN_001b3bf8','uVar18 = 0;','uVar18 = 3;','return uVar18']),
        'login_type6':anchors('login_construct',['local_40 = 6','FUN_001eb854']),
        'auth_dispatch':anchors('inbound_dispatch',['(int)local_1c0 != 0x32','FUN_001c6e5c','(int)local_108 == 0','+ 0x2b1','FUN_001ec290','FUN_001e8b4c','FUN_001e2d2c','FUN_001e303c','(int)local_180 != 0','FUN_00294b88']),
        'response_schema':anchors('login_response_visitor',['FUN_001e83c0(DAT_00145418','FUN_001e83c0(&DAT_0014633c','FUN_001e83c0("data"','FUN_001c942c','FUN_001ca2f8','param_1[6]','param_1[3]']),
        'i32_bounds':anchors('response_i32_parser',['local_50 >> 0x1f','local_50 == (long)(int)local_50','param_1[1] = (int)local_50']),
        'string_type':anchors('response_string_parser',['bVar1 != 0x22','FUN_00207760','param_1[2] = local_48']),
        'sequence_shape':anchors('login_response_visitor',['bVar1 == 0x5b','FUN_001c942c','FUN_001c9b8c']),
        'sequence_string':anchors('response_sequence_string',['bVar2 == 0x5d','FUN_001ca2f8']),
        'gated_close':anchors('gated_close',['FUN_001e2c04','(uVar6 & 1) == 0','puVar5 + 0x1d0','_DAT_001443b0','FUN_001b3bf8']),
        'timeout':anchors('timeout_check',['FUN_001e236c','FUN_001e253c','lVar4 + 5','FUN_001e1e9c']),
        'timeout_action':anchors('timeout_action',['FUN_001e13c8','param_1[4] & 1','FUN_001b3b14']),
        'heartbeat_reset':anchors('heartbeat_stop',['FUN_00218fe0','*plVar9 = 0','FUN_001e207c(param_1,0)']),
        'monitor_disconnect':anchors('internal_monitor',['cVar4 ==','FUN_001eab5c']),
        'disconnect_relogin':anchors('disconnect',['FUN_001e2d2c(local_48,0)','FUN_001e2838','FUN_001e8b4c','FUN_001e13c8','FUN_001dd2a0','FUN_001deb88','FUN_001ec290','FUN_001bfa3c','puVar5 + 0xf8']),
        'relogin_attempt':anchors('relogin_attempt',['FUN_001e8b4c','+ 0x100','[0x108]','+ 0x110','FUN_001eaf88']),
        'relogin_poll':anchors('relogin_poll',['FUN_001ec69c','FUN_002248c0','goto LAB_001a5e40','FUN_001ec068']),
        'relogin_default':anchors('relogin_period',['param_1 + 2','lVar1 = 3','lVar7 != 0']),
        'relogin_stop':anchors('relogin_stop',['param_1 + 0x18','FUN_00218fe0','*plVar8 = 0']),
        'notification_clear':anchors('connection_notification_clear',['param_1 + 0x28','param_1 + 0x30']),
        'full_stop':anchors('full_stop',['FUN_001e2d2c','FUN_001ec290','FUN_001e13c8','+ 0x2b1']),
        'explicit_logout':anchors('public_logout',['local_f0 = 3','FUN_001eb5a4','+ 0x110','+ 0x118','+ 0x120','FUN_001e2ea0']),
        'noop':anchors('noop_helper',['return;']),
    }
    # Complete-branch finite negative checks, not claims about arbitrary indirect/runtime behavior.
    inbound = SOURCES['inbound_dispatch'].read_text().splitlines()
    fail = '\n'.join(inbound[531:553])
    assert all(s in fail for s in ['FUN_001e8b4c','FUN_001ec290','FUN_001e2d2c(uVar9,0)'])
    assert not any(s in fail for s in ['0x110','0x2b1','FUN_001e13c8','FUN_001e2ea0','FUN_001ec7f0'])
    for n in ['gated_close','relogin_stop','disconnect','relogin_attempt']:
        t = SOURCES[n].read_text()
        assert '0x2b1' not in t and 'FUN_001e2ea0' not in t
    assert 'return 0;' in SOURCES['login_gate'].read_text()
    # Exact critical BL and constant/flag words are also independently checked from ELF bytes.
    key = [by_addr[a] for a in [0xea3e0,0xea510,0xea600,0xea6f0,0xea958,0xea9c8,0xeac00,0xe2f30,0xe2fa4]]
    calls = [r for r in raw if r.get('bl_target') in [
        '0xeaf88','0xeb278','0xeb854','0xe8b4c','0xec290','0xe2d2c','0xe13c8','0xe1e9c',
        '0xeab5c','0xbfa3c','0xec068','0xb4130','0xb0630','0xc6e5c','0x194b88','0x118fe0']]
    facts = [
        {'id':'local_result_is_not_auth','status':'confirmed','description_zh':'wsLogin正常返回路径先保存原生JWT，再给Dart返回action0+i32本地结果；未等待服务端types50。0=连接任务已启动或文本入队；203=低层初次transport检查为0；3=序列化/发送等最终错误。局部500/501合并成3。','evidence':['jwt_write_and_reply','reply_format','connect_or_send','local_send_result']},
        {'id':'saved_jwt_before_failure','status':'confirmed','description_zh':'SDK+0x110/118/120为保存JWT的Rust String(capacity,pointer,length)，wsLogin在任何发送结果之前覆写；int3/203及服务端拒绝不回滚旧JWT。不能据此断言JWT有效。','evidence':['jwt_write_and_reply','local_send_result','auth_dispatch']},
        {'id':'connect_false_branch','status':'confirmed','description_zh':'transport为false时安装连接通知bool sender，启动携带输入JWT的等待future与连接future，立即返回0。登录等待poll1a556c收到true才发送types6；false只记录失败；Pending/通道结束是future状态，不是wsLogin 3/203或服务端code。','evidence':['connect_or_send','deferred_login']},
        {'id':'event10_distinct','status':'confirmed','description_zh':'init连接事件monitor poll1a51f0的true分支发event10空字符串通知；与eaf88的JWT等待poll1a556c不同。它们都不是types50认证结果回调。','evidence':['event10_separate','deferred_login']},
        {'id':'response_schema','status':'confirmed','description_zh':'types50.data_content是内层JSON文本；对象分支要求code:i32,user_id:String,data:String，后两者以局部String解析和释放。visitor另有JSON数组序列分支，静态顺序为[code,user_id,data]；这是反序列化能力，不证明服务端实际使用数组。不能把data写成对象，不能推定服务端业务错误编号枚举。','evidence':['auth_dispatch','response_schema','i32_bounds','string_type','sequence_shape','sequence_string']},
        {'id':'code_nonzero_order','status':'confirmed','description_zh':'正常解析的code!=0分支在所调用helper正常返回的条件下，依次记录错误、gated_close、停止当前autorelogin、transport=false，然后释放响应。此分支不清auth/JWT，不直接停keepalive/QoS或清内部断线sender，也不直接发Dart错误事件。Close队列发送失败可panic，不能保证此时后续stop/clear已执行。','evidence':['auth_dispatch','gated_close','relogin_stop']},
        {'id':'reject_qos_and_malformed','status':'confirmed','description_zh':'qos=true的types50先解析code；非0绕过普通去重/ACK流程，进入业务拒绝分支。该预解析失败调用unwrap panic路径；qos=false业务解析失败记录日志并drop，不应合并为code!=0拒绝。重复的qos=true成功响应可跳过业务分支。','evidence':['auth_dispatch']},
        {'id':'success_transition','status':'confirmed','description_zh':'code0正常业务分支写auth=true两次，停止autorelogin，安装内部断线bool monitor，重建心跳两任务与QoS任务，最后transport=true；无确认的服务端code直接传Dart路径。','evidence':['auth_dispatch']},
        {'id':'close_is_gated','status':'confirmed','description_zh':'close helper先读transport；false直接返回。true且出站sender存在时排队Close(None)，并不清transport标记。认证拒绝先close再clear，因而可排队；普通disconnect/fullstop先clear再close，通常门控退出。入队不等于旧socket已完全关闭或对端收到帧。','evidence':['gated_close','auth_dispatch','disconnect_relogin','full_stop']},
        {'id':'timeout_indirect_restart','status':'confirmed','description_zh':'心跳时间差>=period+5(默认35秒)触发timeout action：停止两个keepalive并清last-heartbeat +0x48，尝试向现有内部monitor sender发true。monitor存在且收到值时才进入disconnect，清transport/移除monitor、停QoS/旧重登、启动新重登任务。monitor缺失/通道失败不能保证启动重登。','evidence':['timeout','timeout_action','heartbeat_reset','monitor_disconnect','disconnect_relogin']},
        {'id':'relogin_loop','status':'confirmed','description_zh':'autorelogin默认3秒，初次立即执行，无已证退避/次数上限。每次先gated_close，再读锁克隆原生保存JWT并调用login_gate；忽略本地返回值，不取新token、不刷新JWT。读到transport=false启动新的连接任务；读到true则仍向当前sender投递types6，可能已排队Close，存在异步时序条件。','evidence':['relogin_poll','relogin_default','relogin_attempt','connect_or_send']},
        {'id':'relogin_stop_not_await','status':'confirmed','description_zh':'stop autorelogin对现存任务调用cancel helper并移除+0xf8句柄，不等待整个future结束。code0与code!=0都会调用它。常规disconnect先删除内部sender，重连code0才重建；因此通常重连认证拒绝后，此timer停止且Closecleanup没有现存内部sender可再启动timer。只有旧channel仍在/已有通知尚可被消费等条件，才可能再走disconnect；不能仅以曾经成功认证推定持续重试，也不作系统永远不再重试的全局结论。','evidence':['relogin_stop','task_cancel','auth_dispatch','monitor_disconnect','disconnect_relogin']},
        {'id':'jwt_clear_positive_control','status':'confirmed','description_zh':'显式wsLogout尝试types3后将JWT String置(0,1,0)并fullstop，fullstop清transport/auth与任务。types54调用fullstop但未确认清保存JWT。这与认证拒绝及Dart HTTP401清Utils.jwt是不同路径。','evidence':['explicit_logout','full_stop','auth_dispatch']},
        {'id':'sender_fields_are_distinct','status':'confirmed','description_zh':'SDK+0x1d0/+0x1d8是出站Message sender的Option/值；1e9794(SDK+0x1c0)清块内+0x28/+0x30即SDK+0x1e8/+0x1f0连接通知bool sender，不能混同。','evidence':['gated_close','notification_clear']},
        {'id':'noop_does_not_notify','status':'confirmed','description_zh':'发送/解析C体中的1eca5c虽在诸多错误路径出现，原ELF在0xeca5c只有RET，不是Dart错误回调或event10。','evidence':['noop']},
    ]
    # Add cancellation proof used in one fact.
    evidence['task_cancel'] = anchors('task_cancel',['uVar5 & 0x22','uVar5 | 0x20','uVar5 | 0x24','*puVar4 = uVar6'])
    transitions = [
        {'trigger':'wsLogin int3/203','transport':'unchanged by these result-return branches','auth':'retained','jwt':'new input already saved','relogin_task':'not directly started/stopped by return code','dart':'action0 normal integer response; not a service rejection'},
        {'trigger':'types50 code!=0','transport':0,'auth':'retained','jwt':'retained','relogin_task':'existing handle cancellation requested and removed; no direct new task; normal reconnect denial has no monitor sender and does not restart this timer','heartbeat_qos':'not directly stopped in this branch','internal_monitor':'not modified by this direct branch; normally already absent after preceding disconnect'},
        {'trigger':'heartbeat timeout action only','transport':'unchanged in action itself','auth':'retained','jwt':'retained','heartbeat':'tasks cancellation requested, handles removed, epoch0','internal_monitor':'sendtrue if present; conditional continuation'},
        {'trigger':'internal bool monitor receives nonclosed/nonpending value','transport':0,'auth':'retained','jwt':'retained','heartbeat_qos':'stop requested','internal_monitor':'sender removed','relogin_task':'old cancel requested; new handle stored+0xf8'},
        {'trigger':'autorelogin iteration sees transport0','auth':'retained','jwt':'cloned saved value','socket_action':'launch connect future; deferred types6 after true connection notification','local_return':0,'return_consumed':False},
        {'trigger':'autorelogin iteration sees transport1','auth':'retained','jwt':'cloned saved value','socket_action':'Close(None) may already be queued, then types6 via current sender; cannot guarantee wire order or successful reauthentication','local_return':'0/3/203 path result discarded'},
        {'trigger':'types50 code0','transport':1,'auth':1,'jwt':'retained, not replaced by response user_id/data','relogin_task':'old canceled and removed','heartbeat_qos':'started/restarted','internal_monitor':'new sender installed'},
        {'trigger':'explicit wsLogout','transport':0,'auth':0,'jwt':'cleared (capacity0,pointer1,length0)','relogin_task':'stop requested','heartbeat_qos':'stop requested'},
        {'trigger':'types54 server kick','transport':0,'auth':0,'jwt':'retained in audited fullstop call','relogin_task':'stop requested','heartbeat_qos':'stop requested'},
    ]
    payload = {
        'scope':'Static original local APK/ELF and prior decompilation only. No target execution, backend request, live server response or key use.',
        'library':str(RUST),'library_sha256':sha(RUST),
        'address_convention':{'Rust':'ELF VA = Ghidra function/label address - 0x100000'},
        'facts':facts,'state_transitions':transitions,'evidence_index':evidence,
        'login_response_static_formats':{'object':{'code':'required i32','user_id':'required String','data':'required String'},
                                         'sequence':{'order':['code:i32','user_id:String','data:String'],'status':'statically accepted parser format, not an observed server message'}},
        'complete_body_inventory':groups,'raw_ranges':ranges,'native_raw_checks':raw,
        'critical_flag_instructions':key,'critical_direct_calls':calls,'close_control_data':control,
        'external_cross_checks':{
            'transport_connect_cleanup':str(BASE/'analysis/reconnect_preview_failure/reconnect/reconnect_flow.json'),
            'prior_flags':str(BASE/'analysis/connection_preview_closure/state_audit/state_audit.json'),
            'prior_async_bindings':str(BASE/'analysis/ws_heartbeat/heartbeat_lifecycle.json'),
            'prior_full_bridge_and_login':str(BASE/'analysis/login_flow/native_login_flow.json'),
            'dart_http_401':'Parent Dart HTTP audit; clearDart JWT must not be equated with native savedJWT clearing without bridge call evidence'},
        'confidence_limits':[
            'Ghidra types/local variable names are reconstructed; LLVM bytes, immediate constants and direct BLs independently verified.',
            'Task handles prove local cancellation request and removal, not await/join completion or peer network receipt.',
            'Transition matrix assumes the relevant mutex/RwLock and helper calls return normally. Lock poison and Close queue unwrap can panic before later stop/clear statements; this is not a fully guaranteed cleanup finally block.',
            'Async interleavings determine whether an existing old channel or already queued notification restarts autorelogin. A normal disconnect removes the sender and normal rejected reauthentication does not recreate it; prior successful login alone is insufficient. No observed runtime trace.',
            'No valid live JWT, nonzero server-code enum, server policy or actual backend implementation is available.',
            'Dart negative callback result is bounded to reviewed auth dispatch and wsLogin result path; no global impossibility claim for unrelated navigation/HTTP/interceptors.',
            'Transport worker handshake, EOF/error/Close opcode mechanics are delegated and cross-referenced, not inferred from auth helper alone.',
        ],
        'verification':{'status':'PASS','complete_body_count':len(groups),'fact_count':len(facts),'state_transition_count':len(transitions),
                        'source_reference_count':sum(len(v) for v in evidence.values()),'raw_range_count':len(ranges)+1,
                        'machine_word_count':len(raw),'bl_target_count':sum('bl_target'in r for r in raw),
                        'critical_direct_call_count':len(calls),'close_control_data_bytes':len(b),
                        'checks':['ELF SHA256','PT_LOAD VA to file-offset mapping','all selected LLVM instruction words against original bytes','sign-extended BL target decode','copied complete C SHA256','source anchor existence','bounded failure-branch state-retention checks','RET helper','Close control 16-byte constants']},
    }
    (OUT/'authentication_failure.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    text = '\n'.join(f"{i+1}. {f['description_zh']}\n   证据组：{', '.join(f['evidence'])}" for i,f in enumerate(facts))
    text = '原生认证失败与心跳超时后续流程（静态还原）\n\n以下状态恢复表和顺序均以锁、helper正常返回为前提；panic可在后续清理前中断。\n\n' + text + '\n\n可信边界：\n' + '\n'.join(payload['confidence_limits']) + '\n\n全部地址使用ELF VA；Ghidra地址加0x100000。完整反编译body在complete_native_bodies/；机器指令在raw_llvm/。每条证据带绝对路径、精确行号、SHA256；原ELF指令附VA、文件偏移、little-endian bytes、word和BL目标。\n'
    (OUT/'中文说明.txt').write_text(text)
    pseudo = '''人工重建伪代码；不是原始Rust源码。省略锁/分配/释放细节，异常路径保留语义边界。
普通转换假设helper正常返回；poison或队列unwrap panic可在其后stop/clear前中断。

async public_wsLogin(inputJwt) -> Future<int>:
    SDK.savedJwt = clone(inputJwt)       // +110/+118/+120; before any result
    localCode = login_gate(inputJwt)
    reply_to_Dart(action=0, i32=localCode) // no wait for types50

login_gate(jwt) -> int:
    if not SDK.transport:
        (tx, rx) = boolChannel()
        SDK.connectionNotify = tx
        spawn login_connection_waiter(jwt, rx) // poll a556c
        gated_close()                    // normally no-op because false
        spawn connect_task(SDK)          // poll a5ec8; sibling transport audit
        return 0
    return send_protocol(types=6, data_content=jwt)

login_connection_waiter(jwt, rx):
    loop:
        notification = await rx.next()
        if channel_closed: release jwt; return
        if notification == false: log connection failure
        else: send_protocol(types=6, data_content=clone(jwt)) // int ignored

// init_ws event10 monitor(a51f0) is another task; true -> Dart WsEvent(10,"","").

local_send(protocol) -> int:
    if not SDK.transport: return 203
    if serialization_error: return 3
    if transport_changed_to_false: log intermediate500; return 3
    if sender_lock_poison: log intermediate501; return 3
    if sender_missing: log intermediate500; return 3
    if queue_send_error: return 3
    return 0                            // queue accepted; no server result

on_inbound(protocol):
    if protocol.qos and protocol.types == 50:
        preliminary = parseLoginResponse(protocol.data_content)
        if parse_error: panic_unwrap()  // not a ordinary code!=0 rejection
        if preliminary.code != 0: goto auth_dispatch // skips dedup/ACK
    if protocol.qos: normal_dedup_ack_gate()
    if protocol.types != 50: other_dispatch()
auth_dispatch:
    response = parseLoginResponse(protocol.data_content)
    if parse_error: log; release parse error; return
    // object required keys code:i32, user_id:String, data:String;
    // visitor also accepts sequence [code,user_id,data]; no observed server format implied
    if response.code == 0:
        SDK.auth = true                 // compiler emits two locked assignments
        stop_relogin_task()
        install_internal_disconnect_monitor()
        start_keepalive_two_tasks()     // first calls stop_keepalive -> epoch0
        start_qos_tasks()
        SDK.transport = true
    else:
        log response.code
        gated_close()                   // checked BEFORE transport=false
        stop_relogin_task()
        SDK.transport = false
        // no savedJwt/auth reset, no direct stop keepalive/QoS, no Dart auth error event
    release response.user_id and response.data

gated_close():
    if not SDK.transport: return
    if SDK.outboundMessageSender.present:
        SDK.outboundMessageSender.send(Message.Close(None))
        // send failure may panic before caller's later cleanup; enqueue does not prove actual old socket closure

heartbeat_timeout_check():
    if epochSecondsNow() - SDK.lastHeartbeatEpoch >= heartbeatPeriod()+5:
        timeout_action()

timeout_action():
    stop_keepalive_two_tasks()           // cancel+remove handles; epoch=0
    if SDK.internalDisconnectSender.present:
        send_bool(true)                  // if received by a5430 -> disconnect()
    // absent/closed channel does not guarantee a relogin task

disconnect():
    SDK.transport = false
    remove internalDisconnectSender
    gated_close()                       // normally no-op after clear
    stop_keepalive_two_tasks()           // epoch0 again
    stop_qos_tasks()
    stop_relogin_task()
    SDK.reloginHandle = spawn auto_relogin() // +f8
    // SDK.auth and savedJwt retained

auto_relogin():
    attempt_relogin()                    // immediate first iteration
    repeat every configuredSeconds or default3:
        attempt_relogin()

attempt_relogin():
    gated_close()                       // if transport true, may enqueue Close
    with read_lock(SDK.savedJwt):
        login_gate(clone(SDK.savedJwt))  // result ignored; no JWT refresh
    // login_gate checks transport again: false starts connect; true uses current sender

stop_relogin_task():
    if handle present:
        request_task_cancel(handle)
        remove_and_drop_handle()        // no await/join here

// Auth denial directly stops the current loop. Normal disconnect has already removed the
// internal sender; only successful reauthentication recreates it. Thus normal reconnect
// denial stops this timer path, and Closecleanup has no current internal sender to restart it.
// A channel still existing or a previously queued notification still consumable can restart
// a loop; previous login success alone is insufficient. Callback ordering is not a live trace.
// HTTP401 -> Dart Utils.jwt="" is an independent path, not native savedJWT erasure.
// Explicit wsLogout is a positive counterexample: try types3 -> savedJwt=(0,1,0) -> fullstop.
'''
    (OUT/'重建伪代码.txt').write_text(pseudo)
    # Manifest is written last, after all generated prose, including the current script hash.
    inputs = list(SOURCES.values())+[RUST,Path(__file__).resolve()]
    for p in [BASE/'analysis/ws_heartbeat/heartbeat_lifecycle.json',BASE/'analysis/login_flow/native_login_flow.json',BASE/'analysis/connection_preview_closure/state_audit/state_audit.json']:
        if p.is_file(): inputs.append(p)
    manifest = {'inputs':[{'file':str(p),'sha256':sha(p)} for p in sorted(set(inputs))],
                'artifacts':[{'file':str(p),'sha256':sha(p)} for p in sorted(OUT.rglob('*')) if p.is_file() and p.name!='source_manifest.json']}
    (OUT/'source_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(payload['verification'],ensure_ascii=False))


if __name__ == '__main__':
    main()
