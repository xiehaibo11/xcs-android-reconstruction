#!/usr/bin/env python3
"""Reproduce bounded preview-exit and shared-callback static evidence.

Reads original AOT dumps, matching SDK/tool source and ELF bytes only. No APK,
Dart snapshot, business library, endpoint or downloaded code is executed.
"""

from _paths import app_root, workspace_root
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

APP = app_root()
OUT = APP / 'analysis/connection_preview_closure/end_preview'
ASM = APP / 'analysis/aot_dump/asm'
LIB = APP / 'unpacked/lib/arm64-v8a/libapp.so'
LLVM = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
HEADER = re.compile(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)')
SELECTED = [
    0x457460, 0x457b58, 0x457dc4, 0x4580b4, 0x45911c, 0x459704,
    0x45b36c, 0x45fcb4, 0x460ab4, 0x460b60, 0x461014, 0x463a10, 0x463e08,
    0x51d844, 0x4ac018, 0x4ac0b8, 0x4ac134, 0x527460,
    0x42bb14, 0x4cf458, 0x5a9168, 0x5a92f8, 0x5a93b0, 0x5d8f1c,
    0x56a2ac, 0x50cb28, 0x546744, 0x55e25c, 0x50cb98, 0x6e5ed8,
    0x66ae4c, 0x55e2c8, 0x55e4b8, 0x638f64, 0x546b10, 0x55e340,
    0x4aac98, 0x4aad80, 0x4aae00, 0x4aaed8, 0x4aaffc, 0x4abf98,
]
RAW_RANGES = [
    ('shared_null_entry', 0x6f2a58, 0x6f2a60),
    ('allocate_closure_fastpath', 0x6f9118, 0x6f9164),
    ('main_saveimg_then_protocol', 0x527558, 0x527588),
    ('save_endpreview_then_protocol', 0x460c4c, 0x460c7c),
    ('save_params_id_reset', 0x460ad0, 0x460ad4),
    ('end_preview_id_reset', 0x46102c, 0x461030),
    ('discarded_substring_then_static_wrapper', 0x4aad30, 0x4aadd4),
    ('empty_iscontentws_serializer', 0x4aaed8, 0x4aaf78),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dump_json(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def load_elf():
    with LIB.open('rb') as stream:
        elf = ELFFile(stream)
        sections = [{'name': s.name, 'elf_va': s['sh_addr'],
                     'file_offset': s['sh_offset'], 'size': s['sh_size']}
                    for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']
    data = LIB.read_bytes()

    def read(address, length=4):
        section = next(s for s in sections if s['elf_va'] <= address and
                       address + length <= s['elf_va'] + s['size'])
        offset = section['file_offset'] + address - section['elf_va']
        return data[offset:offset + length], offset, section['name']
    return read, sections


def source_range(source, start, end, filename):
    data = source.read_bytes()
    snippet = OUT / 'evidence' / filename
    snippet.write_text('\n'.join(data.decode().splitlines()[start - 1:end]) + '\n')
    return {'source': str(source), 'source_sha256': sha(data),
            'start_line': start, 'end_line': end, 'snippet': str(snippet),
            'snippet_sha256': sha(snippet.read_bytes())}


def claims():
    return [
        {'id': 'shared_entry', 'methods': ['0x527460', '0x460b60'],
         'raw_ranges': ['shared_null_entry', 'allocate_closure_fastpath'],
         'conclusion': '0x6f2a58 的完整可执行入口只有 mov x0,x22; ret。匹配 Dart SDK 的 NULL_REG=R22，故返回 Dart null；不读回调实参，不写状态，不调用请求。不能按 Shader 标签推定源码归属。'},
        {'id': 'tool_alias', 'support_sources': ['null_register', 'entry_point_map', 'pool_function_label'],
         'conclusion': 'Blutter 以 entrypoint 为 key 只保留首个方法，Function 对象展示名通过该 entrypoint map 查找。多个 PP 项指向同一 0x6f2a58，展示的 Shader 标签不是每个业务 Function 对象原名的可靠证据。'},
        {'id': 'two_future_values', 'methods': ['0x527460', '0x460b60'],
         'raw_ranges': ['main_saveimg_then_protocol', 'save_endpreview_then_protocol'],
         'conclusion': '两处都把 Function 对象放 x1、NULL context 放 x2，AllocateClosure 后调用 Future.then<Null?>，仅一个 onValue 回调。0x52755c 是 msg_type=101 分支 saveImg Future 的 then；0x460c50 是保存且关闭分支 endPreview Future 的 then。没有 onError，也没有等待 then 结果。'},
        {'id': 'save_close_gate', 'methods': ['0x45fcb4', '0x460b60'],
         'conclusion': '保存响应先检查 HttpResponse.ok，再将 data[success] 强制为 bool 并检查为 true，再检查捕获的 close 标志为 true。满足才调用 endPreview(selectedDevice.id)，挂空 then 后立即 Navigator.pop(true)。ok/success/close 为 false 则直接返回；success 类型错误会走 bool 类型检查错误，不伪造为服务器成功。'},
        {'id': 'service_id_reset', 'methods': ['0x457dc4', '0x4580b4', '0x461014'],
         'conclusion': 'PreviewService+0xb 是 startPreview 先写入的设备 ID，默认 0；endPreview 在 0x46102c 先将其清为 Smi 0，再 POST /api/preview/end_preview/{调用实参}。未等响应、未根据 success/ok 才清理、未失败回滚。'},
        {'id': 'save_params_also_clears_id', 'methods': ['0x45fcb4', '0x460ab4', '0x460b60', '0x4ac0b8'],
         'raw_ranges': ['save_params_id_reset', 'end_preview_id_reset'],
         'conclusion': 'savePreviewParams 在 0x460ad0 也先清 PreviewService+0xb 为 0，再 POST set_params_v2，与 close 标志无关。普通保存或保存失败后，ID 已清；若此后没有 startPreview 重写 ID，则 route completion 会跳过 endPreview。save(close) 响应成功分支仍用捕获的 selectedDevice.id 显式 endPreview。不能称父回调为任何退出都能补发 end 的保证。'},
        {'id': 'route_completion', 'methods': ['0x4ac018', '0x4ac0b8', '0x4ac134'],
         'conclusion': 'Main.showFramePreview 为非 null 的 Get.to 返回 Future 挂完成回调 0x4ac0b8。回调忽略路由返回值，比较 PreviewService+0xb 与 0；不等于 0 时读取该 ID 并 endPreview，Future 被丢弃。save-close 已同步清0时，父回调通常不重复发 end 请求。'},
        {'id': 'default_back', 'methods': ['0x457460', '0x42bb14', '0x4cf458', '0x5a9168', '0x5a92f8', '0x5a93b0'],
         'conclusion': '预览 AppBar 未提供自有 leading/onPressed；框架 automaticallyImplyLeading 为 true。满足可返回路由条件时框架选择 BackButton（全屏对话路由为 CloseButton），默认动作调用 Navigator.maybePop。真正完成已挂钩的预览路由后，才由 Main route completion 执行上述 endPreview 条件分支；返回动作本身不直接发 end 请求。'},
        {'id': 'two_ids_and_rx_value', 'methods': ['0x459704', '0x45911c', '0x527460', '0x51d844', '0x461014', '0x4ac0b8', '0x460b60'],
         'conclusion': 'MainService+0xf 是不同的 unboxed int，默认 -1，startPreview 的 Future onValue 不检查响应成功即写 device.id??0，Main 102 分支用于带 ID 图像匹配；MainService+0xb 是全局 RxString。上述退出方法只清 PreviewService+0xb，不清 MainService 匹配 ID，也不清 RxString 值。预览 initState 下一次进入时将 RxString.value 置空。'},
        {'id': 'preview_dispose_scope', 'methods': ['0x457460', '0x45b36c', '0x5d8f1c'],
         'conclusion': '完整 frame_preview_page.dart 导出方法清单中无预览 State 自有 dispose，也没有 PopScope/WillPopScope/onWillPop。此有限静态结论不表示子 Widget 观察者没有框架清理，也不证明所有动态分派后果。'},
        {'id': 'obx_cleanup', 'methods': ['0x45b36c', '0x463a10', '0x463e08', '0x56a2ac', '0x50cb28', '0x546744', '0x55e25c', '0x50cb98', '0x6e5ed8', '0x66ae4c', '0x55e2c8', '0x55e4b8', '0x638f64', '0x546b10', '0x55e340', '0x5d8f1c'],
         'conclusion': 'hand_view 建立两个 Obx，均读 MainService 的 RxString.value；实际 State 为 ObxState。Widget 正常卸载经 StatefulElement.unmount 调 dispose，ObxState.cancel 自己的 subs，并 close 自己的 RxNotifier；该 notifier 取消其跟踪的外部 Rx stream listener、清 map、关闭自己的 stream。这里没有关闭 MainService 全局 Rx，也没有清全局值。cancel/removeSubscription 有异步路径且调用方未 await，不宣称立即完成解绑。'},
        {'id': 'iscontentws_no_user_arguments', 'methods': ['0x4aac98', '0x4aad80', '0x4aae00', '0x4aaed8'],
         'raw_ranges': ['discarded_substring_then_static_wrapper', 'empty_iscontentws_serializer'],
         'conclusion': 'onStartGames 的 URL substring 运算确实执行，但结果 r0 没有作为业务参数传给 static isContentWs。wrapper 不装载用户参数，并以 RustLib.instance 覆盖 r0；API 层只使用 receiver，serializer 创建空 SseSerializer/WriteBuffer 后 pdeCallFfi funcId=5，不写 String。应重建为 isContentWs()，不能称为 isContentWs(host/URI)。substring 自身仍可能抛范围/类型相关异常。'},
        {'id': 'iscontentws_limited_semantics', 'methods': ['0x4aaffc', '0x4abf98'],
         'conclusion': 'Dart bool 回调 true 直接 sendStartGame；false 调 wsLogin(JWT)，其 Future 完成后再发送（完成值被忽略）。本工件验证Dart签名；native worker已在相邻is_content_ws工件闭合为正常读取SDK+0x2a5连接标志，不能把true当host/URI匹配或认证成功，也不能把wsLogin Future完成当认证成功。'},
    ]


NOTES = '''预览退出与共享回调静态补证

已确认 0x6f2a58 的完整执行体只有 8 字节：e00316aa c0035fd6，即 mov x0,x22; ret。匹配 SDK 将 R22 定义为 NULL_REG，所以这是返回 Dart null 的无操作入口，不读取响应或实参、不写状态、不请求网络。多个 Function 对象可以共享此代码；Blutter 展示的 Shader 名称来自以 entrypoint 索引的代表对象，不能据此认定业务回调的源码身份。

0x52755c 在 Main 的 msg_type=101 分支中，跟随 saveImg 调用，分配 NULL context 的闭包并挂 Future.then<Null?>。0x460c50 跟随 endPreview，使用同样协议。两者只提供 onValue 回调，没有 onError，不 await 回调结果。前者不是 102 预览图消息的回调。

保存且关闭：0x460b60 按 ok、data['success'] as bool、close 的顺序门控。全部为 true 才 endPreview(selectedDevice.id)，挂空 then 后立即 Navigator.pop(true)，不等待服务器结束预览的响应。任一 false 返回；success 不是 bool 时类型检查可能抛错。不能描述为 endPreview 成功后才 pop。

两个设备 ID 必须分开：PreviewService+0xb 默认0，startPreview 在请求前写所选 ID，endPreview 在 POST 前同步清0。MainService+0xf 默认-1，startPreview 的 onValue 直接写 device.id??0 而未检查成功；它供 Main 的 102 图像分支匹配设备。MainService+0xb 是另一对象的 RxString。已核对的退出方法没有清 MainService 匹配 ID 或 RxString 值；预览 initState 再次进入时将 RxString.value 清为空字符串。

savePreviewParams 也会在 0x460ad0 先将 PreviewService+0xb 清0，再 POST set_params_v2；close 标志不参与这次清理。因此普通保存、HTTP包装失败、success=false 或响应类型错误时 ID 同样已清。此后若没有 startPreview 重写 ID，返回路由的父回调会因 ID==0 跳过 endPreview；不能写成任何退出均有 end 请求兜底。保存且关闭的成功分支用捕获的 selectedDevice.id 显式 endPreview，不依赖这个已清0的服务 ID。

Main.showFramePreview 为 Get.to 的非 null Future 挂 0x4ac0b8：路由完成后忽略返回值，若 PreviewService ID !=0 则 endPreview(ID)，丢弃其 Future。保存关闭已经清0的正常路径不会再次发送。默认 AppBar 没有业务返回回调；框架在可返回路由上用 BackButton，经 Navigator.maybePop，实际路由完成后才透过父回调执行该条件清理。maybePop 不成功或路由 Future 未提供时，不能承诺已发送 endPreview。

完整预览业务文件没有自有 dispose、PopScope、WillPopScope、onWillPop 导出方法。这不等于 Rx observer 保留：hand_view 两个 Obx 实际使用 ObxState，框架卸载 State 时调用 dispose；ObxState 取消自身 subs 并 close 自己的 RxNotifier，该 notifier 取消跟踪的外部 Rx stream listener、清观察 map、关闭自身 stream。它不 close MainService 的全局 RxString，也不清全局 Rx 值。取消链含未 await 的 Future 和 removeSubscription 异步路径，故不写成同步完成。Main 原生事件订阅属于另一个生命周期，由根代理独立补证。

额外签名纠正：isContentWs()没有业务参数。onStartGames先执行host substring运算，但结果未传递；wrapper加载RustLib.instance覆盖返回寄存器，funcId=5 serializer只创建空SseSerializer/WriteBuffer，没有写String。true直接sendStartGame，false等wsLogin本地Future完成后发送。native判定已在相邻is_content_ws目录闭合为正常读取SDK+0x2a5连接标志，不是认证成功或地址匹配判据。旧isContentWs(host)重建文字应据此更正；本工件不依赖旧目录。

复现：python3 APP/scripts/end_preview_closure_extract.py；独立核验：python3 APP/scripts/end_preview_closure_extract.py --verify。end_preview_closure.json 保存完整方法行区间与 SHA256、SDK/tool 源片段、全量导出扫描范围、原 ELF 地址/小端字节/直接 BL 目标和 LLVM 快照。verification.json 的 PASS 检查来源完整片段、原 ELF 与指令记录一致；不会替代对业务语义的人工审查。全过程仅静态读取，没有执行 APK/业务库或连接业务服务器。
'''

PSEUDOCODE = '''// 静态重建伪代码；字段采用反汇编 offset，避免混淆两个 service 的 ID。
Null sharedCodeEntry_6f2a58(dynamic ignored) => null;

Future<HttpResponse> endPreview(dynamic deviceId) {
  PreviewService.instance.field_b = 0; // 同步，HTTP响应之前。
  return httpClient.post('/api/preview/end_preview/' + deviceId.toString());
}

Future<HttpResponse> savePreviewParams(dynamic deviceId, dynamic params) {
  PreviewService.instance.field_b = 0; // 0x460ad0，也在响应前；不依赖close。
  return httpClient.post('/api/preview/set_params_v2/' + deviceId.toString(), data: params);
}

void saveResponseCallback(HttpResponse response, bool close,
                          Devices selectedDevice, BuildContext context) {
  if (!response.ok) return;
  if (!(response.data['success'] as bool)) return;
  if (!close) return;
  endPreview(selectedDevice.id).then<Null?>(sharedCodeEntry_6f2a58);
  Navigator.of(context).pop<bool>(true); // 没有await endPreview。
}

void showFramePreview() {
  Get.to(() => FramePreviewPage())?.then<Null?>((ignoredRouteResult) {
    if (PreviewService.instance.field_b != 0) {
      endPreview(PreviewService.instance.field_b); // Future/响应未处理。
    }
    return null;
  });
}
// 默认AppBar BackButton -> Navigator.maybePop。
// 若成功结束上述路由，其Future完成，才调用父route completion。

void previewInitState() {
  MainService.instance.field_b /* RxString */.value = '';
}
void startPreviewValueCallback(HttpResponse response, Devices selectedDevice) {
  MainService.instance.field_f /* int */ = selectedDevice.id ?? 0;
  Log.d(response.data); // 没有ok/success门控。
}
// endPreview和route completion不重置MainService.field_f，不清全局RxString。

void onRecognitionMessage101() {
  saveImg(/* 已由原Main方法构造的消息参数 */)
      .then<Null?>(sharedCodeEntry_6f2a58); // 非102预览图回调。
}

void ObxState_dispose() {
  subs.cancel();       // 自身subscription，返回Future被忽略。
  observer.close();    // 自身notifier的dependency subscriptions.cancel、map.clear、stream.close。
  // 未调用MainService.instance.field_b.close，也未清Main全局RxString.value。
}

void onStartGames() {
  final server = Utils.field_0xb94; // 0x4aaccc所加载的static字符串字段。
  final stripped = server.substring(7);
  stripped.substring(0, stripped.indexOf(':8081'));
  // 上面说明执行了截取；以原0x4aac98序列为准，最终结果未作为参数传给wrapper。
  isContentWs().then((bool value) {
    if (value) {
      sendStartGame();
    } else {
      wsLogin(Utils.jwt).then((ignoredLoginResult) => sendStartGame());
    }
  });
}
Future<bool> isContentWs() => RustLib.instance.api.crateApiSimpleIsContentWs();
// serializer: new WriteBuffer -> new SseSerializer -> pdeCallFfi(funcId:5,...)
// 无host/URI/String序列化；bool语义和认证成功判定未由本段闭合。
'''


def build():
    (OUT / 'evidence').mkdir(parents=True, exist_ok=True)
    read, sections = load_elf()
    methods, checks, refs, absent_header, scanned = [], [], [], True, []
    for path in sorted(ASM.rglob('*.dart')):
        data = path.read_bytes()
        scanned.append({'source': str(path), 'sha256': sha(data)})
        lines = data.decode().splitlines()
        for i, line in enumerate(lines):
            if '0x6f2a58' in line:
                refs.append({'source': str(path), 'source_sha256': sha(data),
                             'line': i + 1, 'text': line})
            header = HEADER.search(line)
            if not header:
                continue
            if int(header[1], 16) == 0x6f2a58:
                absent_header = False
            if int(header[1], 16) not in SELECTED:
                continue
            end = next(j for j in range(i + 1, len(lines)) if lines[j] == '  }')
            record = source_range(path, i, end + 1, header[1][2:] + '.asm.txt')
            record.update({'address': header[1], 'size': header[2],
                           'method_declaration': lines[i - 1].strip()})
            methods.append(record)
            text = Path(record['snippet']).read_text()
            for instruction in re.finditer(r'//\s+(0x[0-9a-f]+): bl\s+#(0x[0-9a-f]+)', text):
                address, target = (int(x, 16) for x in instruction.groups())
                raw, offset, section = read(address)
                word = int.from_bytes(raw, 'little')
                imm = word & 0x3ffffff
                if imm & 0x2000000:
                    imm -= 0x4000000
                assert word & 0xfc000000 == 0x94000000 and address + imm * 4 == target
                checks.append({'binary': str(LIB), 'elf_va': hex(address),
                               'file_offset': hex(offset), 'section': section,
                               'bytes_le': raw.hex(), 'word_hex': f'{word:08x}',
                               'check': 'BL', 'target_elf': hex(target)})
    assert {int(m['address'], 16) for m in methods} == set(SELECTED)
    assert absent_header
    raw_ranges = []
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for name, start, stop in RAW_RANGES:
        raw, offset, section = read(start, stop - start)
        instructions = []
        for ins in decoder.disasm(raw, start):
            target = hex(int(ins.op_str[1:], 0)) if ins.mnemonic in ('bl', 'b') and ins.op_str.startswith('#') else None
            instructions.append({'binary': str(LIB), 'elf_va': hex(ins.address),
                                 'file_offset': hex(offset + ins.address - start),
                                 'bytes_le': ins.bytes.hex(), 'mnemonic': ins.mnemonic,
                                 'operands': ins.op_str, 'target_elf': target})
        assert len(instructions) * 4 == len(raw)
        llvm = OUT / 'evidence' / (name + '.llvm.txt')
        llvm.write_text(subprocess.check_output([
            LLVM, '-D', f'--start-address={hex(start)}', f'--stop-address={hex(stop)}', str(LIB)
        ], text=True))
        raw_ranges.append({'id': name, 'binary': str(LIB), 'elf_start': hex(start),
                           'elf_end_exclusive': hex(stop), 'file_offset': hex(offset),
                           'section': section, 'bytes_le': raw.hex(),
                           'raw_bytes_sha256': sha(raw), 'instructions': instructions,
                           'llvm_file': str(llvm), 'llvm_sha256': sha(llvm.read_bytes())})
    support = []
    for identity, path, start, end in [
        ('null_register', APP / 'tools/blutter/dartsdk/v3.5.2/runtime/vm/constants_arm64.h', 130, 164),
        ('entry_point_map', APP / 'tools/blutter/blutter/src/DartApp.cpp', 371, 379),
        ('pool_function_label', APP / 'tools/blutter/blutter/src/DartDumper.cpp', 502, 526),
    ]:
        record = source_range(path, start, end, identity + '.source.txt')
        record['id'] = identity
        support.append(record)
    pool = APP / 'analysis/aot_dump/pp.txt'
    pool_bytes = pool.read_bytes()
    pool_aliases = [{'source': str(pool), 'source_sha256': sha(pool_bytes),
                     'line': i + 1, 'text': line}
                    for i, line in enumerate(pool_bytes.decode().splitlines())
                    if 'Function:' in line and '(0x6f2a58)' in line]
    preview = ASM / 'distinguish/pages/frame_preview/frame_preview_page.dart'
    preview_bytes = preview.read_bytes()
    lines = preview_bytes.decode().splitlines()
    inventory = [{'address': m[1], 'size': m[2], 'declaration': lines[i - 1].strip(),
                  'header_line': i + 1}
                 for i, line in enumerate(lines) if (m := HEADER.search(line))]
    negatives = {name: name in preview_bytes.decode()
                 for name in ('_ dispose(', 'PopScope', 'WillPopScope', 'onWillPop')}
    assert not any(negatives.values())
    out = {'scope': 'static endPreview shared callback, route/ID/Rx cleanup, and isContentWs signature',
           'source_binary': {'file': str(LIB), 'sha256': sha(LIB.read_bytes()),
                             'section_mapping': sections},
           'generator': {'file': str(Path(__file__).resolve()), 'sha256': sha(Path(__file__).read_bytes())},
           'methods': methods, 'raw_instruction_checks': checks, 'raw_ranges': raw_ranges,
           'support_sources': support, 'shared_entry_scan': {
               'scope': str(ASM), 'method_header_found': not absent_header,
               'file_count': len(scanned), 'inventory_sha256': sha(json.dumps(scanned).encode()),
               'asm_reference_count': len(refs), 'references': refs,
               'pool_alias_count': len(pool_aliases), 'pool_aliases': pool_aliases},
           'preview_export_inventory': {'source': str(preview), 'source_sha256': sha(preview_bytes),
                                        'methods': inventory, 'negative_patterns_found': negatives},
           'cleanup_fields': [
               {'owner': 'PreviewService', 'field': '+0xb', 'meaning': 'requested preview device ID',
                'construction_default': 0, 'exit_write': 'Smi 0 before save/end HTTP', 'methods': ['0x457dc4', '0x460ab4', '0x461014']},
               {'owner': 'MainService', 'field': '+0xf', 'meaning': '102 image device matching ID (unboxed int)',
                'construction_default': -1, 'exit_write': 'none in reviewed exit methods', 'methods': ['0x459704', '0x45911c', '0x527460']},
               {'owner': 'MainService', 'field': '+0xb', 'meaning': 'global RxString preview image value',
                'exit_write': 'none in reviewed exit methods', 'reentry_write': "initState .value=''",
                'methods': ['0x459704', '0x51d844']},
               {'owner': 'ObxState', 'field': '+0x13 / +0x17', 'meaning': 'own notifier / own subscription',
                'exit_write': 'dispose invokes subscription.cancel + notifier.close',
                'methods': ['0x56a2ac', '0x546744', '0x55e25c']},
           ],
           'claims': claims(), 'limits': [
               'Static callbacks/entrypoints and bounded framework bodies only; no runtime observation.',
               'No server response or native end-preview success assertion is available.',
               'This artifact verifies the Dart signature; native bool semantics are verified separately in ../is_content_ws/is_content_ws.json.',
               'The complete preview exported method list is an AOT dump scope, not an original-source recovery.',
           ], 'target_code_executed': False, 'business_server_contacted': False}
    dump_json('end_preview_closure.json', out)
    (OUT / '预览退出与共享回调说明.txt').write_text(NOTES)
    (OUT / '重建预览清理.dart.txt').write_text(PSEUDOCODE)


def verify():
    data = json.loads((OUT / 'end_preview_closure.json').read_text())
    read, _ = load_elf()
    assert sha(LIB.read_bytes()) == data['source_binary']['sha256']
    assert sha(Path(data['generator']['file']).read_bytes()) == data['generator']['sha256']
    for record in data['methods'] + data['support_sources']:
        source = Path(record['source']).read_bytes()
        assert sha(source) == record['source_sha256']
        snippet = Path(record['snippet']).read_bytes()
        assert sha(snippet) == record['snippet_sha256']
        assert snippet.decode() == '\n'.join(source.decode().splitlines()[record['start_line'] - 1:record['end_line']]) + '\n'
    bl_count = 0
    for record in data['raw_instruction_checks']:
        address = int(record['elf_va'], 16)
        actual, offset, _ = read(address)
        assert actual.hex() == record['bytes_le'] and hex(offset) == record['file_offset']
        word = int.from_bytes(actual, 'little')
        imm = word & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        assert word & 0xfc000000 == 0x94000000 and word == int(record['word_hex'], 16)
        assert address + imm * 4 == int(record['target_elf'], 16)
        bl_count += 1
    words, range_instructions = 0, 0
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for record in data['raw_ranges']:
        start, stop = int(record['elf_start'], 16), int(record['elf_end_exclusive'], 16)
        raw, _, _ = read(start, stop - start)
        assert raw.hex() == record['bytes_le'] and sha(raw) == record['raw_bytes_sha256']
        decoded = list(decoder.disasm(raw, start))
        assert len(decoded) == len(record['instructions'])
        for actual, expected in zip(decoded, record['instructions']):
            assert hex(actual.address) == expected['elf_va'] and actual.bytes.hex() == expected['bytes_le']
            assert actual.mnemonic == expected['mnemonic'] and actual.op_str == expected['operands']
            if expected['target_elf'] is not None:
                assert hex(int(actual.op_str[1:], 0)) == expected['target_elf']
            range_instructions += 1
        content = Path(record['llvm_file']).read_bytes()
        assert sha(content) == record['llvm_sha256']
        local_words = 0
        for instruction in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', content.decode(), re.M):
            address, expected = (int(v, 16) for v in instruction.groups())
            assert start <= address < stop and int.from_bytes(read(address)[0], 'little') == expected
            local_words += 1
        assert local_words == (stop - start) // 4
        words += local_words
    assert data['raw_ranges'][0]['bytes_le'] == 'e00316aac0035fd6'
    assert [i['mnemonic'] for i in data['raw_ranges'][0]['instructions']] == ['mov', 'ret']
    assert data['raw_ranges'][0]['instructions'][0]['operands'] == 'x0, x22'
    scan = data['shared_entry_scan']
    scanned = [{'source': str(path), 'sha256': sha(path.read_bytes())}
               for path in sorted(ASM.rglob('*.dart'))]
    assert len(scanned) == scan['file_count'] and sha(json.dumps(scanned).encode()) == scan['inventory_sha256']
    assert not any(re.search(r'// \*\* addr: 0x6f2a58,', Path(record['source']).read_text()) for record in scanned)
    for record in scan['references'] + scan['pool_aliases']:
        source = Path(record['source']).read_bytes()
        assert sha(source) == record['source_sha256']
        assert source.decode().splitlines()[record['line'] - 1] == record['text']
    assert not scan['method_header_found'] and len(scan['references']) == scan['asm_reference_count']
    assert len(scan['pool_aliases']) == scan['pool_alias_count']
    inventory = data['preview_export_inventory']
    source = Path(inventory['source']).read_bytes()
    assert sha(source) == inventory['source_sha256']
    assert not any(inventory['negative_patterns_found'].values())
    assert not any(name in source.decode() for name in inventory['negative_patterns_found'])
    known = {m['address'] for m in data['methods']}
    for claim in data['claims']:
        assert set(claim.get('methods', [])).issubset(known)
    for file, expected in [('预览退出与共享回调说明.txt', NOTES), ('重建预览清理.dart.txt', PSEUDOCODE)]:
        assert (OUT / file).read_text() == expected
    result = {'status': 'PASS', 'complete_methods': len(data['methods']),
              'support_source_ranges': len(data['support_sources']), 'claims': len(data['claims']),
              'raw_direct_bl_checks': bl_count, 'raw_range_instructions': range_instructions,
              'llvm_words_checked': words, 'shared_entry_bytes': 8,
              'asm_shared_entry_references': scan['asm_reference_count'],
              'pp_shared_entry_aliases': scan['pool_alias_count'],
              'preview_exported_methods': len(inventory['methods']),
              'generator_sha256': data['generator']['sha256'],
              'target_code_executed': False, 'business_server_contacted': False}
    dump_json('verification.json', result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify', action='store_true', help='verify saved output without regenerating it')
    arguments = parser.parse_args()
    if not arguments.verify:
        build()
    verify()
