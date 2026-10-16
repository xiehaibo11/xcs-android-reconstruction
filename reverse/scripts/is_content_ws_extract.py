#!/usr/bin/env python3
"""Static FRB id5 closure extraction/verification; does not execute target code."""

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
OUT = ROOT/'APP/analysis/connection_preview_closure/is_content_ws'
NATIVE = OUT/'native_pseudocode/functions'
AOT = ROOT/'APP/analysis/aot_dump/asm/distinguish'
RUST = ROOT/'APP/unpacked/lib/arm64-v8a/librust_lib_distinguish.so'
DART = ROOT/'APP/unpacked/lib/arm64-v8a/libapp.so'
INPUT_SHA = {
    RUST.name:'0af3f1f12e57e9b5f2d409343421c1fa21b0bcffe7860a30cf972a1265399847',
    DART.name:'40d890193daa716defe2eec6cd2959bdbf7f7cf8345f8213b1747e54863a5a55'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Binary:
    def __init__(self,path):
        self.path=path
        assert sha(path)==INPUT_SHA[path.name]
        self.handle=path.open('rb')
        self.elf=ELFFile(self.handle)
        assert self.elf.little_endian and self.elf['e_machine']=='EM_AARCH64'
        self.loads=[s for s in self.elf.iter_segments() if s['p_type']=='PT_LOAD']

    def read(self,va,size):
        s=next(s for s in self.loads if s['p_vaddr']<=va and va+size<=s['p_vaddr']+s['p_filesz'])
        self.handle.seek(s['p_offset']+va-s['p_vaddr'])
        return self.handle.read(size)

    def word(self,va):
        return struct.unpack('<I',self.read(va,4))[0]

    def relas(self):
        return [(s.name,r) for s in self.elf.iter_sections() if isinstance(s,RelocationSection) and s.is_RELA() for r in s.iter_relocations()]


def verify():
    p=OUT/'is_content_ws.json'
    d=json.loads(p.read_text())
    binaries={b.path.name:b for b in [Binary(RUST),Binary(DART)]}
    for e in d['source_evidence']:
        path=Path(e['file'])
        assert sha(path)==e['sha256'],path
        ls=path.read_text().splitlines()
        assert '\n'.join(ls[e['start_line']-1:e['end_line']])==e['excerpt'],e['id']
    for c in d['raw_instruction_checks']:
        b=binaries[c['binary']];va=int(c['elf_va'],16);word=b.word(va)
        assert b.read(va,4).hex()==c['bytes_le'] and f'{word:08x}'==c['word_hex'],c
        if c['check']=='BL_decoded_destination':
            assert word&0xfc000000==0x94000000
            imm=word&0x3ffffff
            if imm&0x2000000:imm-=0x4000000
            assert va+4*imm==int(c['target_elf'],16),c
    relas=binaries[RUST.name].relas()
    for c in d['relocation_bindings']:
        matches=[r for _,r in relas if r['r_offset']==int(c['relocation_offset_elf'],16)]
        assert len(matches)==1
        assert matches[0]['r_info_type']==1027 and matches[0]['r_addend']==int(c['addend_target_elf'],16)
    table=d['task_table_layout']
    table_va=int(table['elf_base'],16)
    table_bytes=binaries[RUST.name].read(table_va,32)
    assert table_bytes.hex()==table['file_bytes_hex']
    assert struct.unpack_from('<Q',table_bytes,8)[0]==table['size_qword']==8
    assert struct.unpack_from('<Q',table_bytes,16)[0]==table['alignment_qword']==8
    # Decode the constructor's ADRP+ADD pair independently of objdump text.
    adrp=binaries[RUST.name].word(0xa9724)
    add=binaries[RUST.name].word(0xa9728)
    page_delta=((adrp>>29)&3)|(((adrp>>5)&0x7ffff)<<2)
    if page_delta&(1<<20):page_delta-=1<<21
    assert (0xa9724&~0xfff)+(page_delta<<12)+((add>>10)&0xfff)==table_va
    for s in d['raw_llvm_snapshots']:
        assert sha(s['file'])==s['sha256']
        data=binaries[s['binary']].read(int(s['elf_start'],16),int(s['elf_end_exclusive'],16)-int(s['elf_start'],16))
        assert hashlib.sha256(data).hexdigest()==s['raw_bytes_sha256']
    assert d['determination']['normal_return_formula']=='Dart bool = (SDK byte at +0x2a5 read under lock != 0)'
    assert d['determination']['user_parameter_count']==0
    # Negative argument evidence is a complete generated serialization closure,
    # not a check for strings in an arbitrary neighboring excerpt.
    serial=next(e['excerpt'] for e in d['source_evidence'] if e['id']=='dart_empty_id5_serializer')
    assert 'sse_encode_String' not in serial and 'r3 = 5' in serial
    native=next(e['excerpt'] for e in d['source_evidence'] if e['id']=='actual_body')
    assert 'FUN_001e2c04' in native and 'FUN_001b3f34(auStack_50,0,uVar1)' in native
    getter=next(e['excerpt'] for e in d['source_evidence'] if e['id']=='connected_getter')
    assert '+ 0x2a5' in getter and '+ 0x2b1' not in getter
    normal=json.loads((ROOT/'APP/analysis/login_flow/native_login_flow.json').read_text())
    assert sha(d['prior_login_return_evidence']['file'])==d['prior_login_return_evidence']['sha256']
    assert normal['ws_login_return']['not_authentication_result']==d['prior_login_return_evidence']['not_authentication_result']
    report={'passed':True,'scope':'Static SHA/line/excerpt/ELF word/BL/RELA/snapshot checks only',
            'contract_json_sha256':sha(p),'source_excerpt_count':len(d['source_evidence']),
            'raw_instruction_check_count':len(d['raw_instruction_checks']),
            'relocation_binding_count':len(d['relocation_bindings']),
            'llvm_snapshot_count':len(d['raw_llvm_snapshots']),
            'task_table_bytes_and_constructor_address_verified':True,
            'target_code_executed':False,'business_server_contacted':False}
    (OUT/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))


def extract(objdump):
    OUT.mkdir(parents=True,exist_ok=True)
    rust,dart=Binary(RUST),Binary(DART)
    sources=[]

    def source(id_,path,start=1,end=None):
        ls=path.read_text().splitlines()
        end=end or len(ls)
        sources.append({'id':id_,'file':str(path),'sha256':sha(path),'start_line':start,
                        'end_line':end,'excerpt':'\n'.join(ls[start-1:end])})

    def aot(id_,relative,va):
        path=AOT/relative;ls=path.read_text().splitlines()
        index=next(i for i,l in enumerate(ls) if f'// ** addr: {va:#x},' in l)
        end=next(i for i in range(index+1,len(ls)) if ls[i]=='  }')
        source(id_,path,index,end+1)

    for id_,name in [('id5_wrapper','001aff28'),('id5_schedule','001b8174'),
                     ('port_only_task_constructor','001a96d8'),('vtable_worker','001b06b4'),
                     ('actual_body','001b8348'),('connected_getter','001e2c04'),
                     ('bool_serializer','001b3f34'),('bool_result_sender','001b0630'),
                     ('post_result_helper','001e74e4'),('runtime_schedule_modes','001b09fc')]:
        source(id_,NATIVE/(name+'.c'))
    for id_,file,va in [('dart_no_input_api','src/rust/api/simple.dart',0x4aad80),
                       ('dart_task_configuration','src/rust/frb_generated.dart',0x4aae00),
                       ('dart_empty_id5_serializer','src/rust/frb_generated.dart',0x4aaed8),
                       ('dart_bool_decoder','src/rust/frb_generated.dart',0x4aafb4),
                       ('startgames_entry','pages/main/main_page.dart',0x4aac98),
                       ('startgames_connection_callback','pages/main/main_page.dart',0x4aaffc),
                       ('startgames_login_then_callback','pages/main/main_page.dart',0x4abf98),
                       ('startgames_send','pages/main/main_page.dart',0x4abe28),
                       ('startgames_http_get','service/games_service.dart',0x4abe90)]:
        aot(id_,file,va)
    source('transport_sets_connected_before_auth',ROOT/'APP/analysis/deep_rust/functions/001a5ec8.c',2890,2916)
    source('auth_success_separate_flag',ROOT/'APP/analysis/ws_heartbeat/native_pseudocode/functions/001e99a0.c',374,403)
    source('frb_id5_dispatch',ROOT/'APP/analysis/ws_event_contract/native_pseudocode/functions/001c64b0.c',72,88)

    words={
        0xa970c:0x52800100,0xa9710:0x52800101,0xa9720:0xf9000014,
        0xa9724:0xd00007c2,0xa9728:0x9113c042,
        0xb06c4:0xf9400014,0xb8388:0x2a0003e1,0xb8394:0x2a1f03e0,
        0xb83ac:0x52800088,0xe2c44:0x394a9009,0xe2c48:0x910a9408,
        0xe2c4c:0x350002a9,0xe2c50:0x39400100,
        0xb3f7c:0x39000115,0xb3fd0:0x39000514,
        0xa6dc0:0x52800028,0xa6dc8:0x390a96a8,
        0xea510:0x390ac6c8,
    }
    bls={0xaff68:0xb8174,0xb81b8:0xa96d8,0xa9730:0xb09fc,
         0xb06e0:0xb8348,0xb8384:0xe2c04,0xb8398:0xb3f34,
         0xb83a8:0xb0630,0xb0670:0xfbf6c,0xb067c:0xe74e4,
         0xe74f4:0xa9798}
    dart_words={0x4aaf58:0xd28000a3,0x4aafd4:0xb5000060,
                0x4aafd8:0x9100c2c1,0x4aafe0:0x910082c1,
                0x4ab028:0x372000a0}
    dart_bls={0x4aad38:0x4aad80,0x4aadcc:0x4aae00,
              0x4aaf14:0x4a9dd8,0x4aaf5c:0x4a98b8,0x4aafd0:0x4a9640,
              0x4ab034:0x4abe28,0x4ab044:0x4ab08c,0x4ab070:0x6738c8,
              0x4abfc4:0x4abe28,0x4abe48:0x4abe90,0x4abec8:0x457e8c}
    raw=[]
    for b,ws,bs in [(rust,words,bls),(dart,dart_words,dart_bls)]:
        for a,w in ws.items():
            assert b.word(a)==w,(b.path.name,hex(a),hex(b.word(a)),hex(w))
            raw.append({'binary':b.path.name,'elf_va':hex(a),'bytes_le':b.read(a,4).hex(),
                        'word_hex':f'{w:08x}','check':'exact_instruction_word'})
        for a,target in bs.items():
            w=b.word(a);assert w&0xfc000000==0x94000000,(hex(a),hex(w))
            imm=w&0x3ffffff
            if imm&0x2000000:imm-=0x4000000
            assert a+4*imm==target,(hex(a),hex(a+4*imm),hex(target))
            raw.append({'binary':b.path.name,'elf_va':hex(a),'bytes_le':b.read(a,4).hex(),
                        'word_hex':f'{w:08x}','check':'BL_decoded_destination','target_elf':hex(target)})
    bindings=[]
    for offset,target in [(0x1a3508,0xb06b4)]:
        match=[r for _,r in rust.relas() if r['r_offset']==offset]
        assert len(match)==1 and match[0]['r_info_type']==1027 and match[0]['r_addend']==target
        bindings.append({'relocation_offset_elf':hex(offset),'type':'R_AARCH64_RELATIVE',
                         'addend_target_elf':hex(target),'table_base_elf':'0x1a34f0','slot_offset':'0x18'})
    assert rust.read(0x1a34f8,8)==struct.pack('<Q',8)
    assert rust.read(0x1a3500,8)==struct.pack('<Q',8)
    snapshots=[];raw_dir=OUT/'raw_llvm';raw_dir.mkdir(exist_ok=True)
    ranges=[('id5_wrapper',rust,0xaff28,0xaffc8),('id5_scheduler',rust,0xb8174,0xb8248),
            ('port_task_constructor',rust,0xa96d8,0xa9798),('id5_worker',rust,0xb06b4,0xb0744),
            ('actual_body',rust,0xb8348,0xb8460),('connected_getter',rust,0xe2c04,0xe2d28),
            ('bool_serializer',rust,0xb3f34,0xb4058),('bool_result_post',rust,0xb0630,0xb06b4),
            ('transport_connected_set',rust,0xa6dc0,0xa6dd0),
            ('dart_no_input_and_serializer',dart,0x4aad80,0x4aaf78),
            ('dart_bool_decoder',dart,0x4aafb4,0x4aaffc),('startgames_branch',dart,0x4ab024,0x4ab074),
            ('startgames_login_then',dart,0x4abf98,0x4abfe0),('startgames_http',dart,0x4abe90,0x4abed8)]
    for name,b,lo,hi in ranges:
        text=subprocess.check_output([objdump,'-D','--triple=aarch64',f'--start-address={lo:#x}',
                                      f'--stop-address={hi:#x}',str(b.path)],text=True)
        p=raw_dir/(name+'.asm');p.write_text(text)
        snapshots.append({'id':name,'binary':b.path.name,'elf_start':hex(lo),'elf_end_exclusive':hex(hi),
                          'file':str(p),'sha256':sha(p),'raw_bytes_sha256':hashlib.sha256(b.read(lo,hi-lo)).hexdigest()})
    login_path=ROOT/'APP/analysis/login_flow/native_login_flow.json'
    login=json.loads(login_path.read_text())['ws_login_return']
    d={'scope':'Static ARM64 FRB id5 closure audit; independent read-only Ghidra export; no target execution/server contact.',
       'inputs':[{'file':str(b.path),'sha256':sha(b.path)} for b in [rust,dart]],
       'addressing':{'rust':'Ghidra = ELF virtual address + 0x100000','dart':'AOT address equals ELF virtual address'},
       'determination':{'status':'confirmed','frb_function_id':5,'api':'isContentWs()',
                        'user_parameter_count':0,'request_user_payload_bytes':0,
                        'normal_return_formula':'Dart bool = (SDK byte at +0x2a5 read under lock != 0)',
                        'native_valid_bool_values':[0,1],
                        'read_moment':'When the scheduled worker executes getter, not necessarily when Dart invokes the API.',
                        'connection_state_offset':'0x2a5','connection_lock_offset':'0x29c','connection_poison_offset':'0x2a4',
                        'authentication_state_offset_not_read':'0x2b1',
                        'host_url_matching':False,
                        'qualification':'Normal getter/serialization/post success path; lock poison or other failures do not establish a false result.'},
       'native_chain':[{'ghidra':'0x1aff28','role':'FRB id5 dispatcher wrapper → 0x1b8174'},
                       {'ghidra':'0x1b8174','role':'No user argument decoding; schedules handler+port via 0x1a96d8'},
                       {'ghidra':'0x1a96d8','role':'Allocates8 aligned8, stores Dart port only, submits data/vtable0x2a34f0 to runtime scheduler0x1b09fc'},
                       {'ghidra':'0x1b06b4','role':'Callable vtable slot+0x18 resolved by RELA; reads stored port, calls0x1b8348, then frees port task'},
                       {'ghidra':'0x1b8348','role':'Actual API body; lazily gets global SDK0x2b4508, reads getter0x1e2c04, serializes action0+bool, posts normal reply. No separate async poll or authentication wait in this body.'},
                       {'ghidra':'0x1e2c04','role':'Read lock/poison handling, returns only SDK byte+0x2a5'},
                       {'ghidra':'0x1b3f34','role':'Serializes two bytes: action0 then original bool byte'},
                       {'ghidra':'0x1b0630','role':'Vec→Dart_CObject via0x1fbf6c, post helper0x1e74e4→0x1a9798'}],
       'dart_contract':{'task':'NormalTask<bool,...>; executeNormal → Future<bool>',
                        'serializer':'Complete closure0x4aaed8 creates empty SseSerializer and pdeCallFfi(funcId5); no host/String encoding.',
                        'decoder':'Configured sse_decode_bool0x4aafb4 reads getUint8; zero→false, nonzero→true after standard action0 handling.',
                        'wire_examples':[{'synthetic':True,'value':False,'hex':'0000'},{'synthetic':True,'value':True,'hex':'0001'}]},
       'start_games_implication':{'status':'confirmed','entry':'onStartGames0x4aac98',
                                 'discarded_host_substring':'Caller computes URL substring, but isContentWs wrapper does not accept/forward it. This computation does not establish host validation.',
                                 'true_branch':'0x4ab034 sendStartGamesReq immediately → GamesService.startGamesReq0x4abe90 → HTTP GET /api/zhuo/start_games at0x4abec8.',
                                 'false_branch':'0x4ab044 wsLogin(saved JWT); register Future.then0x4ab070 with callback0x4abf98; callback0x4abfc4 calls sendStartGamesReq.',
                                 'login_return_unused':'then callback signature(dynamic,int), body does not load integer argument or branch on it. It sends HTTP on normal completion regardless of local integer0/3/203.',
                                 'authentication_wait':'No wait for types50.code==0 or SDK+0x2b1 observed in either branch; waiting on local wsLogin Future is distinct from server authentication success.',
                                 'state_flag_limit':'Transport connect worker can set+0x2a5=true before authentication response; getter is a stored flag snapshot, not live ping, server authorization, or target-host matching.'},
       'prior_login_return_evidence':{'file':str(login_path),'sha256':sha(login_path),'json_pointer':'/ws_login_return',
                                      'confirmed_values':login['confirmed_values'],'not_authentication_result':login['not_authentication_result']},
       'known_limits':['Full generic runtime queue/dequeue dispatch internals are not exhaustively reconstructed; passed task table and resolved callable body are verified. This does not block the API boolean formula.',
                       'No guarantee this stored connection flag mirrors socket liveness at every instant; asynchronous scheduling and concurrent state updates can race.',
                       'Exceptions, post failure, Future error handlers, and actual server response/timing are not dynamically tested.',
                       'Only this APK ARM64 build; no claim for other versions/ABIs.'],
       'source_evidence':sources,'raw_instruction_checks':raw,'relocation_bindings':bindings,
       'task_table_layout':{'elf_base':'0x1a34f0','file_bytes_hex':rust.read(0x1a34f0,32).hex(),
                            'size_qword':8,'alignment_qword':8,'callable_slot':'0x18','callable_ghidra':'0x1b06b4'},
       'raw_llvm_snapshots':snapshots}
    (OUT/'is_content_ws.json').write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
    (OUT/'is_content_ws说明.txt').write_text(EXPLANATION)
    (OUT/'reconstructed_is_content_ws.txt').write_text(PSEUDO)
    verify()


EXPLANATION='''isContentWs 实际工作体与布尔条件（静态闭合）

确定结论：当前 APK 的 isContentWs() 没有业务参数。正常完成时 Dart 返回 bool = (工作体读取 SDK+0x2a5 的 byte !=0)。该字段是保存的传输连接标志，读取受 SDK+0x29c 读锁与 +0x2a4 poison 检查保护；不读取 SDK+0x2b1 认证标志，也不比较 host/URL。锁 poison 等异常路径不能被当作 false 返回。异步任务在实际执行 getter 时取快照，不是调用瞬间的活性探测。

任务链闭合
Rust 地址为 Ghidra 地址，ELF 地址减0x100000。Dart AOT 地址等于 libapp.so ELF地址。
id5 dispatcher 0x1c64b0 → wrapper0x1aff28 →0x1b8174 →构造0x1a96d8。构造只分配8字节、align8，保存 Dart port，提交 data 与任务表0x2a34f0给 runtime0x1b09fc。表的+0x18有RELA：ELF0x1a3508 R_AARCH64_RELATIVE addend0xb06b4，指向工作入口0x1b06b4；该入口调用0x1b8348，并释放任务内存。0x1b8348从全局SDK0x2b4508调用0x1e2c04，随后0x1b3f34(action0,bool)编码，0x1b0630经Dart_CObject和post helper返回。该body没有独立的等待认证future/poll条件。通用runtime排队/出队及所有BLR内部没有穷尽重建；明确已验证传入的任务表、重定位的可调用入口和实际工作体，此边界不阻塞上述布尔公式。

原始关键指令
ELF0xb8384 BL0xe2c04；0xb8388 MOVw1,w0；0xb8394 MOVw0,wzr；0xb8398 BL0xb3f34。
getter ELF0xe2c48 ADDx8,x0,#0x2a5，0xe2c50 LDRBw0,[x8]；+0x2a4非零进入panic分支。serializer0xb3f7c写action byte，0xb3fd0写bool byte，正常两字节结果分别00 00/00 01。Dart0x4aafd0读取getUint8，0x4aafd4按零/非零转false/true。

参数纠正
完整 Dart simple.isContentWs 0x4aad80 只取得RustLib API，并调用 crateApiSimpleIsContentWs。生成序列化闭包0x4aaed8创建空SseSerializer，0x4aaf58设置funcId5，0x4aaf5c pdeCallFfi；没有sse_encode_String或业务参数写入。Rust任务数据也只有port。onStartGames虽然先做URL substring，紧邻的isContentWs调用并没有消费/传输这个String；不能把寄存器里残留结果视为输入host，更不能据此认定做了地址匹配。

onStartGames 的实际异步顺序
连接flag true：0x4ab034直接sendStartGamesReq → GamesService.startGamesReq → HTTP GET /api/zhuo/start_games。
连接flag false：0x4ab044 wsLogin(saved JWT)，0x4ab070登记Future.then；该then回调0x4abf98直接调用sendStartGamesReq。回调没有加载或判断传入的int结果。本地wsLogin Future正常完成后，无论本地结果0/3/203，均进入这个HTTP调用；Future异常的运行效果没有动态验证。
该等待不是服务端types50.code==0认证成功。connect worker已在ELF0xa6dc0/0xa6dc8写+0x2a5=1，认证响应的+0x2b1写入属于另一分支。故true只证明所读flag，false分支也只等本地login调用返回，不等服务端auth；不能把设备控制触发条件写成“连接且认证成功”。

证据与复现
is_content_ws.json包含完整短函数/完整AOT方法片段、SHA256、精确行号、原ELF指令与BL目标、RELA、任务表字节、14段LLVM快照及已确认/限制。native_pseudocode为12个根函数与直接callee（共44个）的独立只读Ghidra导出；未修改旧项目/证据。verification.json保存验证结果，reconstructed_is_content_ws.txt为人工重建，不是原始源码。
在项目根目录：python3 APP/scripts/is_content_ws_extract.py
独立验证已存证据：python3 APP/scripts/is_content_ws_extract.py --verify
依赖pyelftools和LLVM objdump，--objdump可指定路径。脚本固定两个ELF SHA，核对source哈希/行号片段、原字节、BL、RELA和快照；只运行分析工具，不执行APK/目标native，不联系业务服务器。其他版本、实时socket活性、调度竞态和服务端结果不由静态证据保证。
'''

PSEUDO='''// Manually reconstructed from this APK. Not original source.
Future<bool> isContentWs():
    // FRB funcId5, no user args; submit task containing Dart port only.
    worker():
        sdk = lazy_global_sdk()
        acquire_read_lock(sdk + 0x29c)
        if sdk.byte_0x2a4 != 0: panic_poisoned_lock()
        connected_byte = sdk.byte_0x2a5
        release_read_lock()
        post_normal_reply([action0, connected_byte])
    Dart_decoder(): return getUint8_after_action_prefix() != 0

void onStartGames():
    compute_url_substring() // result is not serialized to isContentWs
    isContentWs().then((connected):
        if connected:
            sendStartGamesReq() // HTTP GET /api/zhuo/start_games
        else:
            wsLogin(savedJWT).then((ignored_local_int):
                sendStartGamesReq()
            )
    )
// Neither branch reads authentication flag+0x2b1 or waits for types50.code==0.
// Local login Future completion and server authentication are separate.
'''


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify',action='store_true')
    parser.add_argument('--objdump',default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    args=parser.parse_args()
    if args.verify:verify()
    else:extract(args.objdump)
