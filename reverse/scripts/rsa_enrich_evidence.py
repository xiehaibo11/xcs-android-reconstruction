#!/usr/bin/env python3
"""Add verified ABI, enum and invocation evidence to the local RSA extraction."""

from _paths import app_root, workspace_root
import json
import re
import struct
from pathlib import Path
from rsa_extract_go import ELF64

ROOT = app_root()
OUT = ROOT / 'analysis/deep_rsa'
FUNCS = json.loads((OUT / 'go_functions.json').read_text())
OPS = json.loads((OUT / 'operations.json').read_text())
elf = ELF64((ROOT / 'unpacked/lib/arm64-v8a/librsa_bridge.so').read_bytes())


def save(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


# Literal addresses are operands of model.init's enum map assignments. Numeric
# values 0..N are confirmed in MOV/ORR operands to mapassign_fast32.
enum_sources = {
    'Hash': [(0, 0x1fd91f, 3), (1, 0x1fda95, 4), (2, 0x1fddd8, 6),
             (3, 0x1fddde, 6), (4, 0x1fdde4, 6), (5, 0x1fddea, 6)],
    'Cipher': [(0, 0x1fd922, 3), (1, 0x1fdc04, 5), (2, 0x1fddf0, 6),
               (3, 0x1fddf6, 6), (4, 0x1fddfc, 6)],
    'SaltLength': [(0, 0x1fda99, 4), (1, 0x1fee7a, 11)]
}
enums = {}
for enum, entries in enum_sources.items():
    enums[enum] = [dict(value=value, name=elf.read_va(address, size).decode(),
                        literal_address=hex(address), literal_bytes=size)
                   for value, address, size in entries]
save('enum_values.json', dict(initializer='github.com/jerson/rsa-mobile/bridge/model.init',
                            initializer_address='0x10c880',
                            evidence='ARM64 initialization assignments and string bytes', enums=enums))

abi = dict(
    image='arm64-v8a/librsa_bridge.so', image_base=0,
    exported_c_entry='RSABridgeCall', exported_c_address='0x1fc874',
    cgo_export_thunk='_cgoexp_1f8ff7f41c8c_RSABridgeCall', cgo_export_address='0x1fc7a0',
    go_entry='main.RSABridgeCall', go_entry_address='0x1fc530',
    dispatcher='github.com/jerson/rsa-mobile/bridge.Call', dispatcher_address='0x1f56c0',
    argument_semantics=[dict(index=0, c_type='const char *', meaning='NUL-terminated operation name', evidence='runtime.gostring at 0x1fc574'),
                        dict(index=1, c_type='const unsigned char *', meaning='FlatBuffers request buffer', evidence='main.RSABridgeCall.func1 at 0x1fc588 copies input via runtime.gobytes'),
                        dict(index=2, c_type='int32_t', meaning='request buffer size', evidence='STR w2 at 0x1fc548 and sign extension at 0x1fc584')],
    result=dict(allocation_bytes=24, fields=[
        dict(offset=0, reconstructed_name='data', type='unsigned char *', meaning='C-allocated serialized FlatBuffers response', evidence='STR x0,[x1] at 0x1fc5fc after main._Cfunc_CBytes'),
        dict(offset=8, reconstructed_name='size', type='int32_t', meaning='response buffer length', evidence='STR w2,[x1,#8] at 0x1fc604'),
        dict(offset=16, reconstructed_name='error', type='char *', meaning='C string for dispatcher failure; null on dispatcher success', evidence='zero store at 0x1fc5cc / STR x0,[x1,#0x10] at 0x1fc64c')],
        failure_field_validity='On native error branch, only error is explicitly written. data/size must not be assumed initialized.',
        ownership='C allocation confirmed; caller-side freeing and ownership policy have not been recovered.'),
    error_layers=[
        'Unknown operation returns native C error string formatted as "not implemented: %s".',
        'RSA operation errors are serialized into FlatBuffers response error slot 1; native error pointer can still be null.'],
    trust='ABI shapes and stores are confirmed from ARM64 instructions; reconstructed C struct/function parameter names are descriptive, not original source names.'
)
save('native_bridge_contract.json', abi)

# Missing UTF-8 literals alone do not establish unreachability, so scan the raw
# AOT images under three encodings and preserve the limitation explicitly.
needles = ['RSABridgeCall', 'librsa_bridge.so', 'package:fast_rsa/'] + [x['operation'] for x in OPS]
scans = []
for arch in ['arm64-v8a', 'x86_64', 'armeabi-v7a']:
    path = ROOT / 'unpacked/lib' / arch / 'libapp.so'
    blob = path.read_bytes()
    hits = []
    for needle in needles:
        for encoding in ['utf-8', 'utf-16le', 'utf-16be']:
            pattern = needle.encode(encoding)
            count = blob.count(pattern)
            if count:
                hits.append(dict(string=needle, encoding=encoding, count=count,
                                 first_file_offset=hex(blob.find(pattern))))
    scans.append(dict(image=str(path), encodings=['utf-8', 'utf-16le', 'utf-16be'],
                      searched_literals=len(needles), hits=hits))
plugin = ROOT / 'jadx/sources/w4/a.java'
channel = ROOT / 'jadx/sources/j5/k.java'
registration = ROOT / 'jadx/sources/io/flutter/plugins/GeneratedPluginRegistrant.java'
plugin_lines = plugin.read_text().splitlines()
channel_lines = channel.read_text().splitlines()
registration_lines = registration.read_text().splitlines()
def locate(lines, value):
    return [i + 1 for i, line in enumerate(lines) if value in line]
save('actual_invocation_evidence.json', dict(
    registration=dict(source=str(registration), lines=locate(registration_lines, 'new w4.a()') + locate(registration_lines, 'fast_rsa')),
    android_handler=dict(source=str(plugin), handler_lines=locate(plugin_lines, 'public void a(j jVar') + locate(plugin_lines, 'dVar.c();'),
                         channel_lines=locate(plugin_lines, '"fast_rsa"'),
                         behavior='All method calls directly invoke Result.c(), without native library calls.'),
    result_implementation=dict(source=str(channel), lines=locate(channel_lines, 'public void c()') + locate(channel_lines, 'this.f6256a.a(null);'),
                               behavior='Result.c() sends a null BinaryMessenger reply, consistent with Flutter notImplemented behavior.'),
    aot_literal_scans=scans,
    conclusion='The generic RSA library is bundled and its Android plugin is registered. No application-side native invocation is established by these checks.',
    limits='A Java MethodChannel stub does not exclude Dart FFI. Literal absence does not prove absence of dynamically constructed or encoded calls. No runtime app trace was performed.'
))

byaddr = {f['address']: f for f in FUNCS}
annotated = []
for line in (OUT / 'business_disassembly.asm').read_text().splitlines():
    m = re.match(r'\s*([0-9a-f]+):', line)
    if m:
        address = int(m[1], 16)
        if address in byaddr:
            f = byaddr[address]
            annotated.append('\n/* ' + f['name'] + ' @ ' + hex(address) + '; '
                             + str(f['source_file']) + ':' + str(f['start_line']) + ' */')
        call = re.search(r'\tbl\t0x([0-9a-f]+)', line)
        if call and int(call[1], 16) in byaddr:
            line += ' // Go pclntab: ' + byaddr[int(call[1], 16)]['name']
    annotated.append(line)
(OUT / 'annotated_business_disassembly.asm').write_text('\n'.join(annotated) + '\n', encoding='utf-8')

response_fbs = '''// Reconstructed response table field names are descriptive.
// Slot indices/storage widths verified against Builder.Prepend*Slot calls.
namespace reconstructed_rsa;

table StringResponse { value: string; error: string; }
table BytesResponse { value: [ubyte]; error: string; }
table BoolResponse { value: bool; error: string; }
table KeyPair { privateKey: string; publicKey: string; }
table PKCS12KeyPair { privateKey: string; publicKey: string; certificate: string; }
table PrivateKeyInfo { bitLen: long; size: long; error: string; }
table PublicKeyInfo { bitLen: long; size: long; e: long; }
table KeyPairResponse { value: KeyPair; error: string; }
table PKCS12KeyPairResponse { value: PKCS12KeyPair; error: string; }
table PrivateKeyInfoResponse { value: PrivateKeyInfo; error: string; }
table PublicKeyInfoResponse { value: PublicKeyInfo; error: string; }
'''
(OUT / 'response_models_reconstructed.fbs').write_text(response_fbs, encoding='utf-8')

header = '''/* Reconstructed ARM64 C ABI from instruction stores; descriptive names. */
#include <stdint.h>
typedef struct {
    uint8_t *data;       /* offset 0; valid when error == NULL */
    int32_t size;        /* offset 8 */
    uint32_t padding;    /* offset 12; not used by bridge */
    char *error;         /* offset 16 */
} NativeBridgeResponse;
NativeBridgeResponse *RSABridgeCall(const char *method, const uint8_t *request, int32_t request_size);
/* Native error and serialized operation error are separate levels.
   C allocation is established; caller-side release policy remains unverified. */
'''
(OUT / 'native_bridge_reconstructed.h').write_text(header, encoding='utf-8')

with (OUT / 'operation_request_response.tsv').open('w', encoding='utf-8') as w:
    w.write('operation\thandler_elf_address\trequest_model\tfields_in_wire_order\tresponse_builder\tliteral_verified\n')
    for op in sorted(OPS, key=lambda x: x['operation']):
        w.write('\t'.join([op['operation'], op['handler_address'], ','.join(op['request_models']),
                           '; '.join(name + ': ' + ','.join(field['name'] for field in fields)
                                     for name, fields in op['fields'].items()),
                           ','.join(op['response_builders']),
                           str(op['dispatch_literal_check']['matches_handler'])]) + '\n')

report = '''RSA 原生库深入提取说明

本次仅读取本地 arm64-v8a/librsa_bridge.so 与已反编译的 Java/Dart AOT 文件。
没有执行 APK 或原生库，没有连接业务服务器，没有读取或输出私钥内容。
既有 APP/ghidra/xcs_native 项目未修改。

已确认结果

1. 编译信息为 Go 1.21.0，GOOS=android，GOARCH=arm64，-buildmode=c-shared。
   build flags 含 -w -s，但 Go pclntab 仍存在。恢复了全部 4,221 个 Go 函数名、
   ELF 地址、边界、原构建机文件路径和起始源码行号。
   原构建路径是元数据，不表示源文件内容已恢复。

2. RSA 相关命名空间及 main 包合计 191 个函数。核心来自
   github.com/jerson/rsa-mobile；FlatBuffers 依赖版本 v2.0.6+incompatible。
   go_functions.tsv 可检索完整名称与地址，annotated_business_disassembly.asm
   在真实 ARM64 指令上标注了原函数名、源码起始行和直接调用的 Go 名称。

3. bridge.Call 确认支持 34 个字符串操作。所有 34 个操作都经过独立比较常量核对：
   较短名称由 MOV/MOVK 的小端比较常量还原；较长名称由传给 runtime.memequal
   的完整字面量确认。dispatch_literal_checks.json 全部 matches_handler=true。
   包括 OAEP/PKCS1v15 加解密、PKCS1v15/PSS 签名验签、密钥格式转换、生成、
   公私钥元信息、Hash 与 Base64。支持能力属于通用插件库。

4. 恢复 28 个 FlatBuffers 请求表、76 个字段以及字段线序。
   字段序号由 getter 传给 flatbuffers.Table.Offset 的 vtable offset 校验。
   请求 buffer 是 FlatBuffers 二进制表，不是 JSON request。
   request_models_reconstructed.fbs 是重建的 schema，不是原始 .fbs 源文件。
   字符串及 byte vector 的共用 ByteVector getter，结合操作 wrapper 的
   runtime.slicebytetostring 转换以及字段名区分；标量为 32 位。

5. enum_values.json 保存已确认的枚举编号：
   Hash：0 MD5，1 SHA1，2 SHA224，3 SHA256，4 SHA384，5 SHA512。
   Cipher：0 DES，1 D3DES，2 AES128，3 AES192，4 AES256。
   SaltLength：0 AUTO，1 EQUALS_HASH。
   名称来自 model.init 的枚举字面量，编号来自初始化的 map assignment 参数。

6. 处理 ELF R_AARCH64_RELATIVE 重定位后，从 Go RTTI 恢复了响应值结构：
   KeyPair：PrivateKey(string)，PublicKey(string)。
   PKCS12KeyPair：PrivateKey(string)，PublicKey(string)，Certificate(string)。
   PrivateKeyInfo：BitLen(int64)，Size(int64)，Error(string)。
   PublicKeyInfo：BitLen(int64)，Size(int64)，E(int64)。
   go_response_structs.json 包含原始结构地址、字段偏移和类型宽度。
   response_models_reconstructed.fbs 包含 11 个响应/值表；response slot 0
   为返回值，slot 1 为错误字符串。响应字段的 value/error 名称是描述性重建。

7. 原生调用链：
   RSABridgeCall 0x1fc874（C 导出）
     -> _cgoexp_1f8ff7f41c8c_RSABridgeCall 0x1fc7a0
     -> main.RSABridgeCall 0x1fc530
     -> github.com/jerson/rsa-mobile/bridge.Call 0x1f56c0
     -> bridge.instance.<具体操作>
     -> rsa.(*FastRSA).<具体算法> / FlatBuffers response builder。
   ELF 地址均未加 ASLR base；旧 Ghidra 项目地址比本次 ELF 地址大 0x100000。

8. ARM64 C ABI 为 method 字符串指针、request 指针、int32 request_size，
   返回 malloc(24) 的结构指针。结构偏移 0 为 response data 指针，8 为 int32
   长度，16 为 native error 字符串指针。错误分支只明确写入 error，不能假定
   data/size 在错误分支中初始化。native_bridge_contract.json 与
   native_bridge_reconstructed.h 保存了指令位置和描述性类型。
   原生 error 与序列化响应中的操作 error 是两个层次：未知方法会返回
   "not implemented: %s"；RSA 运算失败通常被编码在 response slot 1 中。
   C 分配可确认；调用方释放策略尚未恢复。

实际 APP 调用的证据边界

Java GeneratedPluginRegistrant 注册 w4.a，它的 fast_rsa MethodChannel handler
直接调用 dVar.c()。j5.k 对该 Result.c() 的实现是向 BinaryMessenger 返回 null，
与 Flutter notImplemented 的行为一致；此 Java handler 未调用 RSA 原生库。

对 arm64、armv7、x86_64 的 libapp.so 检查 UTF-8、UTF-16LE、UTF-16BE 字面量：
未发现 RSABridgeCall、librsa_bridge.so、package:fast_rsa/ 或 RSA 专用操作名。
只有通用的 hash/base64/generate 子串命中，它们不能确认此插件的调用。
actual_invocation_evidence.json 保存精确路径、行号、全部搜索词与命中。

以上说明库已经打包且插件注册，但尚未建立应用业务实际调用这 34 个操作的证据。
MethodChannel stub 不排除 Dart FFI；字面量缺失也不能证明不存在动态构造或编码
的调用。因此不能把插件支持的所有操作写成 APP 的实际业务功能。

可信程度与限制

名称、地址、源码路径由 Go pclntab 校验；请求字段序号、分发字面量、C ABI store
由真实 ARM64 指令校验；Go 响应值字段由重定位后的 RTTI 校验。这些不依赖此前
Ghidra 对 runtime.sigset 的类型分析失败。本次没有恢复完整可重新编译的 Go
源码；重建的 schema/header 中说明性字段名、源码格式、命名空间不是原文件。

复现命令（工作目录 <LOCAL_WORKSPACE>）：
python3 APP/scripts/rsa_extract_go.py
python3 APP/scripts/rsa_enrich_evidence.py
'''
(OUT / '深入RSA分析说明.txt').write_text(report, encoding='utf-8')

assert len(FUNCS) == 4221 and len(OPS) == 34
assert all(x['dispatch_literal_check']['matches_handler'] for x in OPS)
requests = json.loads((OUT / 'request_models.json').read_text())
assert len(requests) == 28
assert all([x['index'] for x in fields] == list(range(len(fields))) for fields in requests.values())
assert all(0x59010 <= x['address'] < x['end'] <= 0x1fd840 for x in FUNCS)
summary = dict(go_functions=len(FUNCS), rsa_namespace_functions=191, operations=len(OPS),
               dispatch_literals_verified=34, request_models=len(requests),
               request_fields=sum(len(f) for f in requests.values()),
               response_tables=11, go_response_structs=4,
               functions_with_source_files=sum(x['source_file'] is not None for x in FUNCS),
               source_file_strings='Original build paths and start lines, not recovered source contents',
               original_binary_executed=False, server_accessed=False,
               validation='Function boundaries, all operation literals and consecutive model field indices checked',
               ghidra='No change to prior project; metadata and annotated native assembly provide evidence independent of the prior Go analyzer failure.')
save('summary.json', summary)
print(json.dumps(summary, ensure_ascii=False))
