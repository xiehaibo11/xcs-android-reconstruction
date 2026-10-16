#!/usr/bin/env python3
"""Static HTTP failure and Dart reconnect-observer evidence; no target execution."""

from _paths import app_root, workspace_root
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

APP = app_root()
ASM = APP / 'analysis/aot_dump/asm'
LIB = APP / 'unpacked/lib/arm64-v8a/libapp.so'
OUT = APP / 'analysis/reconnect_preview_failure/dart_http'
LLVM = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
LIB_SHA = '40d890193daa716defe2eec6cd2959bdbf7f7cf8345f8213b1747e54863a5a55'
SELECTED = {
    0x42c230: 'post', 0x457e8c: 'get', 0x42c3d4: 'handle_exception',
    0x42c428: 'parse_exception', 0x42cc54: 'handle_response',
    0x45280c: 'app_dio_constructor', 0x42cf24: 'dio_fetch',
    0x42cd58: 'dio_post_adapter', 0x458030: 'dio_get_adapter',
    0x42cde8: 'dio_request',
    0x451c78: 'error_wrapper_factory', 0x42e6c0: 'error_chain_install',
    0x42e7c8: 'error_wrapper', 0x42ed04: 'error_enqueued_task',
    0x42ede4: 'handler_future_return', 0x42eee0: 'handler_constructor',
    0x67f76c: 'error_handler_next', 0x42e91c: 'cancel_listener',
    0x67f7ec: 'response_error_tearoff', 0x67f810: 'response_error_closure',
    0x67f850: 'response_error_body', 0x68d200: 'request_jwt_header',
    0x51f028: 'main_init', 0x52a76c: 'main_config_then_init_ws',
    0x52af54: 'main_init_ws_catch', 0x527460: 'main_ws_event_listener',
    0x52a398: 'main_ws_login_then', 0x556974: 'main_dispose',
    0x48f830: 'login_response_updates_dart_jwt',
}
PATHS = [
    'distinguish/common/http/http_client.dart',
    'distinguish/common/http/app_dio.dart',
    'distinguish/common/http/response_interceptors.dart',
    'distinguish/common/http/request_interceptors.dart',
    'dio/src/dio_mixin.dart', 'distinguish/pages/main/main_page.dart',
    'distinguish/pages/login/login_page.dart',
]
HEADER = re.compile(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def elf_reader():
    raw = LIB.read_bytes()
    assert sha(raw) == LIB_SHA
    with LIB.open('rb') as stream:
        elf = ELFFile(stream)
        sections = [(s['sh_addr'], s['sh_offset'], s['sh_size'])
                    for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']
    def read(address, length=4):
        base, offset, _ = next(s for s in sections if s[0] <= address and address+length <= s[0]+s[2])
        offset += address-base
        return raw[offset:offset+length], offset
    return read


CLAIMS = [
    {'id': 'ordinary_exception', 'status': 'confirmed_static',
     'description': 'GET/POST await Dio then handleResponse; catch matches Exception, returns handleException(ok=false, exception). Non-Exception is rethrown.',
     'methods': ['post', 'get', 'handle_exception', 'parse_exception']},
    {'id': 'status_only_ok', 'status': 'confirmed_static',
     'description': 'handleResponse uses HTTP200<=status<300 for ok=true; it does not inspect body.success. Non2xx is ok=false if it reaches this wrapper.',
     'methods': ['handle_response']},
    {'id': '401_redirect', 'status': 'confirmed_static',
     'description': 'Installed ResponseInterceptors.onError requires status401 AND Dart equality data[code]==401; clears Dart Utils.jwt static0xba4 and offAll(LoginPage), without invoking handler.next on this branch.',
     'methods': ['app_dio_constructor', 'response_error_body', 'response_error_tearoff', 'response_error_closure']},
    {'id': '401_pending', 'status': 'conditional_static_inference',
     'description': 'When matched401 branch and offAll return normally, the newly allocated handler completer remains incomplete. Wrapper returns its future; no fallback completion or outer timeout is present in listed bodies. GET/POST can remain pending.',
     'methods': ['dio_fetch', 'dio_post_adapter', 'dio_get_adapter', 'dio_request', 'error_chain_install', 'error_wrapper_factory', 'error_wrapper', 'error_enqueued_task', 'handler_future_return', 'handler_constructor', 'error_handler_next', 'cancel_listener']},
    {'id': '401_token_split', 'status': 'confirmed_bounded_static',
     'description': 'This HTTP interceptor only clears Dart JWT. Listed branch has no wsLogout call or native SDK JWT setter. Native token lifetime must be assessed separately; route removal does not prove native logout.',
     'methods': ['response_error_body', 'main_dispose']},
    {'id': 'subsequent_http_headers', 'status': 'confirmed_static',
     'description': 'Each HTTP request interpolates Bearer plus current Utils.jwt; after interceptor clear, subsequent requests may have empty token suffix until a later login replaces it.',
     'methods': ['request_jwt_header']},
    {'id': 'event10_local_completion', 'status': 'confirmed_static',
     'description': 'Main event10 calls wsLogin(Utils.jwt).then; callback ignores integer and logs ws login success on any normal local completion. This log is not server authentication success.',
     'methods': ['main_ws_event_listener', 'main_ws_login_then']},
    {'id': 'dart_initial_connect_error', 'status': 'confirmed_bounded_static',
     'description': 'Main config response invokes initWs(host).catchError; error callback logs and returns null. Neither this callback nor stream listen installs reconnect/relogin logic; native worker must provide it.',
     'methods': ['main_config_then_init_ws', 'main_init_ws_catch', 'main_init']},
    {'id': 'dart_jwt_replacement', 'status': 'confirmed_bounded_static',
     'description': 'In all53 business annotated assembly files, exact StoreStaticField(0xba4) occurrences are login response0x48fa8c and HTTP401 interceptor0x67f940. Login response replaces Dart JWT; aliases/native state are outside this exact-field scan.',
     'methods': ['login_response_updates_dart_jwt', 'response_error_body']},
]

TEXT = '''HTTP失败与Dart连接观察者补充说明

1. 普通错误不是一律Future reject。
HttpClient.post0x42c230和get0x457e8c await Dio，正常响应交给handleResponse0x42cc54。
catch只匹配Exception，调用handleException0x42c3d4，分配HttpResponse，写ok=false和exception。
data没有赋值；分配器快路径以Dart NULL寄存器初始化字段，所以正常data保持null。
非Exception rethrow；_parseException自身也可能因不满足String?等动态类型约束而抛出。
不能保证每一类错误都成功包装，不能把所有结束预览失败描述为未捕获异步异常。

2. HTTP 2xx只意味着ok=true，包装器不检查业务success。
HTTP401若实际到达handleResponse则返回无权限、ok=false；其他非2xx返回请求异常。
正常Dio错误链先经过ResponseInterceptors.onError，存在另一条特殊401路径。

3. 特殊401分支有两个同时满足的条件。
HTTP statusCode==401且响应data['code']==401（Dart相等比较）：清Dart Utils.jwt(static0xba4)，
GetNavigation.offAll(LoginPage)，直接return null，不调用handler.next/resolve/reject。
HTTP401但业务code不同或为字符串\"401\"不会满足此比较；普通支路调用handler.next。
响应data不是可索引对象等异常须另行区分，不能套用正常返回分支。

4. 匹配401时的等待链已经闭合。
AppDio构造安装该拦截器；fetch错误链创建ErrorInterceptorHandler，_BaseHandler建立
未完成_AsyncCompleter；调用自定义onError后，0x42eebc/0x42eec4直接返回其future。
普通next0x67f76c调用completeError；匹配401分支跳过它。
在offAll等操作正常返回的条件下，这个future在所列链中保持pending，而非立即ok=false。
GET/POST未传CancelToken；listed wrapper/handler路径没有等待阶段的补偿完成或总超时。
此结论针对已列出本地链，不是实际运行观测或所有外部取消机制的普遍否定。

5. HTTP和原生WS的认证失败不是同一路径。
清空的JWT是Dart字段；该HTTP拦截器未调用wsLogout/native JWT写入，不能认定原生token同清。
后续HTTP请求按当时Dart JWT构造Bearer头；Main被offAll移除时自身dispose清接收端资源，
完整body没有显式wsLogout。原生认证、心跳和重登字段由authentication/reconnect工件分析。

6. Main event10调用wsLogin后，0x52a398不读取int结果，只打印ws login success！。
这条日志只能说明本地Future正常完成，不能证明服务器认证成功。
Main初始initWs.catchError0x52af54也只日志并返回null，没有在此启动重试。
Main stream.listen只传onData；没有在该调用注册onError/onDone重连处理。

7. Dart JWT的恢复入口是登录响应0x48f830中的0x48fa8c赋值。
53个业务注释汇编文件的精确StoreStaticField(0xba4)库存只有登录响应和上述401清空两处。
这是精确字段标注扫描，不排除其他别名、初始化快照或原生字段；不证明所有运行时写入已穷尽。

这里的Dart代码和状态名称均为静态重建；原始源码未恢复，未运行目标、未访问业务服务器。
'''

PSEUDO = '''// Analyst reconstruction, not recovered original Dart source.
Future<HttpResponse> post(path, {data}) async {
  try { return handleResponse(await dio.post(path, data: data)); }
  on Exception catch (e) { return handleException(e); }
  // Non-Exception throws are rethrown by compiled catch dispatch.
}
HttpResponse handleException(Exception e) =>
  HttpResponse()..ok=false..exception=parseException(e); // data remains null.
HttpResponse handleResponse(response) {
  if (response.statusCode==401) return unauthorizedResponse();
  if (response.statusCode!=null && response.statusCode>=200 && response.statusCode<300)
    return HttpResponse()..ok=true..data=response.data;
  return failedHttpResponse(response.statusCode,response.statusMessage);
}
void responseInterceptorError(error, handler) {
  if ((error.response?.statusCode ?? 0)==401 && error.response?.data['code']==401) {
    Utils.jwt=''; Get.offAll(LoginPage()); return; // handler not completed.
  }
  handler.next(error);
}
Future errorTask() {
  final handler = ErrorInterceptorHandler(); // new incomplete completer.
  callback(error,handler);
  return handler.completer.future;
}
void onTransportConnectedEvent10() {
  wsLogin(Utils.jwt).then((ignoredInt) { Log.d('ws login success！'); });
}
void initialConnect(host) {
  initWs(host).catchError((e) { Log.d(e); return null; });
}
// No native login success is inferred from these Dart completion handlers.
'''


def build():
    evidence = OUT / 'evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    read = elf_reader()
    methods, checks, snapshots = [], [], []
    for relative in PATHS:
        path = ASM / relative
        data = path.read_bytes()
        lines = data.decode().splitlines()
        for i, line in enumerate(lines):
            match = HEADER.search(line)
            if not match or int(match[1],16) not in SELECTED:
                continue
            address,size = int(match[1],16),int(match[2],16)
            end = next(j for j in range(i+1,len(lines)) if lines[j]=='  }')
            snippet = evidence / (SELECTED[address]+'.asm.txt')
            snippet.write_text('\n'.join(lines[i-1:end+1])+'\n')
            methods.append({'id':SELECTED[address], 'address':hex(address), 'size':hex(size),
                'source':str(path), 'source_sha256':sha(data),
                'start_line':i, 'end_line':end+1,
                'snippet':str(snippet), 'snippet_sha256':sha(snippet.read_bytes())})
            for match in re.finditer(r'//\s+(0x[0-9a-f]+): bl\s+#(0x[0-9a-f]+)',snippet.read_text()):
                va,target = (int(v,16) for v in match.groups())
                raw,offset=read(va)
                checks.append({'binary':str(LIB),'elf_va':hex(va),'file_offset':hex(offset),
                    'bytes_le':raw.hex(),'word_hex':f'{int.from_bytes(raw,"little"):08x}',
                    'check':'BL','target_elf':hex(target)})
            snapshots.append(snapshot(evidence,SELECTED[address],address,address+size,read))
    assert {int(m['address'],16) for m in methods}==set(SELECTED)
    snapshots.append(snapshot(evidence,'http_response_allocate_stub',0x42c41c,0x42c428,read))
    snapshots.append(snapshot(evidence,'null_field_allocator_fast_path',0x6f8ccc,0x6f8d18,read))
    support=[]
    for path,start,end in [
        (APP/'analysis/aot_dump/pp.txt',13066,13071),
        (APP/'analysis/aot_dump/pp.txt',13261,13279),
        (APP/'analysis/aot_dump/asm/distinguish/common/http/http_response.dart',1,11),
        (APP/'tools/blutter/dartsdk/v3.5.2/runtime/vm/constants_arm64.h',130,164),
    ]:
        raw=path.read_bytes()
        support.append({'file':str(path),'sha256':sha(raw),'start_line':start,'end_line':end,
                        'excerpt':'\n'.join(raw.decode().splitlines()[start-1:end])})
    inventory, writes = [], []
    for path in sorted((ASM/'distinguish').rglob('*.dart')):
        raw=path.read_bytes()
        inventory.append({'file':str(path),'sha256':sha(raw)})
        for i,line in enumerate(raw.decode().splitlines()):
            if 'StoreStaticField(0xba4' in line:
                writes.append({'file':str(path),'sha256':sha(raw),'line':i+1,'excerpt':line})
    assert len(inventory)==53 and len(writes)==2
    data={'scope':'static HTTP failure + Main connection observer','source_binary':{'file':str(LIB),'sha256':LIB_SHA},
        'generator':{'file':str(Path(__file__).resolve()),'sha256':sha(Path(__file__).read_bytes())},
        'methods':methods,'raw_instruction_checks':checks,'raw_llvm_snapshots':snapshots,
        'source_evidence':support,'claims':CLAIMS,
        'dart_jwt_exact_field_scan':{'inventory':inventory,'writes':writes,
            'scope':'Exact StoreStaticField(0xba4) annotations in53 business asm files; not alias/native analysis'},
        'target_code_executed':False,'business_server_contacted':False}
    (OUT/'dart_http_failure.json').write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    (OUT/'HTTP失败与Dart连接观察者说明.txt').write_text(TEXT)
    (OUT/'reconstructed_http_failure.dart.txt').write_text(PSEUDO)
    return data


def snapshot(directory,name,start,end,read):
    raw,_=read(start,end-start)
    path=directory/(name+'.llvm.txt')
    path.write_text(subprocess.check_output([LLVM,'-D',f'--start-address={hex(start)}',f'--stop-address={hex(end)}',str(LIB)],text=True))
    return {'file':str(path),'sha256':sha(path.read_bytes()),'binary':str(LIB),
            'elf_start':hex(start),'elf_end_exclusive':hex(end),'raw_bytes_sha256':sha(raw)}


def verify(data):
    read=elf_reader()
    for m in data['methods']:
        raw=Path(m['source']).read_bytes()
        assert sha(raw)==m['source_sha256']
        snippet=Path(m['snippet']).read_bytes()
        assert sha(snippet)==m['snippet_sha256']
        assert '\n'.join(raw.decode().splitlines()[m['start_line']-1:m['end_line']])+'\n'==snippet.decode()
    for c in data['raw_instruction_checks']:
        address,target=int(c['elf_va'],16),int(c['target_elf'],16)
        raw,offset=read(address)
        assert raw.hex()==c['bytes_le'] and offset==int(c['file_offset'],16)
        word=int.from_bytes(raw,'little');imm=word&0x3ffffff
        if imm&0x2000000:imm-=0x4000000
        assert word&0xfc000000==0x94000000 and address+4*imm==target
    words=0
    for s in data['raw_llvm_snapshots']:
        raw=Path(s['file']).read_bytes()
        assert sha(raw)==s['sha256']
        start,end=int(s['elf_start'],16),int(s['elf_end_exclusive'],16)
        assert sha(read(start,end-start)[0])==s['raw_bytes_sha256']
        found=set()
        for m in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+',raw.decode(),re.M):
            address,word=(int(v,16) for v in m.groups())
            assert start<=address<end and int.from_bytes(read(address)[0],'little')==word
            found.add(address)
        assert len(found)==(end-start)//4
        words+=len(found)
    for e in data['source_evidence']:
        raw=Path(e['file']).read_bytes()
        assert sha(raw)==e['sha256'] and '\n'.join(raw.decode().splitlines()[e['start_line']-1:e['end_line']])==e['excerpt']
    result={'status':'PASS','full_method_excerpts':len(data['methods']),
            'direct_bl_targets':len(data['raw_instruction_checks']),'llvm_instruction_words':words,
            'source_support_ranges':len(data['source_evidence']),
            'target_code_executed':False,'business_server_contacted':False}
    (OUT/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    data=json.loads((OUT/'dart_http_failure.json').read_text()) if '--verify' in sys.argv else build()
    verify(data)
