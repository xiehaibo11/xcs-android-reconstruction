#!/usr/bin/env python3
"""Reproduce bounded static preview failure / late image evidence.

Only reads original Blutter AOT text, matching SDK source and arm64 ELF bytes.
Does not execute APK, Dart snapshot or business native code; no network access.
"""

from _paths import app_root, workspace_root
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

APP = app_root()
ASM = APP / 'analysis/aot_dump/asm'
BUSINESS = ASM / 'distinguish'
LIB = APP / 'unpacked/lib/arm64-v8a/libapp.so'
OUT = APP / 'analysis/reconnect_preview_failure/preview'
LLVM = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
HEADER = re.compile(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)')
BL = re.compile(r'//\s+(0x[0-9a-f]+): bl\s+#(0x[0-9a-f]+)')
SELECTED = [
    0x457b04, 0x457b58, 0x459b30, 0x459e60, 0x457dc4, 0x45911c,
    0x459704, 0x4597b0, 0x4580b4, 0x45fcb4, 0x460ab4, 0x460b60,
    0x461014, 0x463a10, 0x463e08, 0x458144, 0x51d844, 0x564d4c,
    0x4ac018, 0x4ac0b8, 0x51f028, 0x527460, 0x5281d8, 0x529164,
    0x529c50, 0x529c80, 0x529d68, 0x529e50, 0x52a198, 0x528074,
    0x528820, 0x526d30, 0x526d90, 0x556974, 0x302dfc, 0x5d8f1c,
    0x51d884, 0x6e5ed8, 0x55e25c, 0x42c230, 0x457e8c, 0x42cc54,
    0x42c3d4, 0x67f850, 0x42ede4, 0x459f08, 0x4b6ecc, 0x52a398,
    0x520fe8, 0x5210c8, 0x523f84, 0x52a724,
]
RAW_RANGES = [
    ('ws102_complete_branch', 0x52758c, 0x5276f8),
    ('ws102_range_error_stubs', 0x528020, 0x528028),
    ('start_value_callback_complete', 0x45911c, 0x4591a8),
    ('preview_init_complete', 0x51d844, 0x51d884),
    ('save_clear_id', 0x460ad0, 0x460ad4),
    ('save_request_numeric_conversions', 0x45fe7c, 0x460074),
    ('end_clear_id', 0x46102c, 0x461030),
    ('save_close_callback_complete', 0x460b60, 0x460ce4),
    ('route_completion_complete', 0x4ac0b8, 0x4ac134),
    ('shared_null_callback', 0x6f2a58, 0x6f2a60),
    ('saveimg_http_schedule_and_return', 0x52878c, 0x5287e0),
    ('saveimg_response_string_decode_write', 0x5291a4, 0x5292d4),
    ('saveimg_live_channel_number_append', 0x529578, 0x529600),
    ('setstate_complete', 0x302dfc, 0x302e60),
    ('stateful_unmount_complete', 0x5d8f1c, 0x5d8fac),
    ('main_dispose_complete', 0x556974, 0x556a20),
    ('event10_branch', 0x527efc, 0x527f64),
    ('http_response_allocate_stub', 0x42c41c, 0x42c428),
    ('common_allocate_complete', 0x6f8ccc, 0x6f8d18),
]
PARAMETERS = [
    ('left', '0x1b', '0x53', 'double.toInt()', '0x4604a4'),
    ('top', '0x23', '0x4f', 'double.toInt()', '0x4604ec'),
    ('right', '0x2b', '0x57', 'double.toInt()', '0x460534'),
    ('bottom', '0x33', '0x5b', 'double.toInt()', '0x46057c'),
    ('brightness', '0x3b', '0x3f', 'double', '0x4605a0'),
    ('motor', '0x43', '0x43', 'double.toInt()', '0x4605c4'),
    ('cap_brightness', '0x4b', '0x7b', 'int', '0x4605fc'),
    ('cap_exposure', '0x53', '0x7f', 'int', '0x460634'),
    ('cap_hue', '0x5b', '0x83', 'int', '0x46066c'),
    ('cap_saturation', '0x63', '0x87', 'int', '0x4606a4'),
    ('cap_contrast', '0x6b', '0x8b', 'int', '0x4606dc'),
    ('cap_gain', '0x73', '0x8f', 'int', '0x460714'),
    ('img_rotation', '0x7b', '0x93', 'int', '0x46074c'),
    ('img_min_hreshold', '0x83', '0x97', 'int', '0x460784'),
    ('cap_fps', '0x8b', '0x9b', 'int', '0x4607bc'),
    ('bate', '0x93', '0xaf', 'int', '0x4607f4'),
    ('img_add_num', '0x9b', '0xb3', 'int', '0x46082c'),
    ('gk_min', '0xa3', '0xb7', 'int', '0x460864'),
    ('gk_max', '0xab', '0xbb', 'int', '0x46089c'),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(name, data):
    (OUT / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def elf_reader():
    with LIB.open('rb') as stream:
        elf = ELFFile(stream)
        sections = [{'name': s.name, 'elf_va': s['sh_addr'],
                     'file_offset': s['sh_offset'], 'size': s['sh_size']}
                    for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']
    binary = LIB.read_bytes()

    def read(address, size=4):
        section = next(s for s in sections if s['elf_va'] <= address and
                       address + size <= s['elf_va'] + s['size'])
        offset = section['file_offset'] + address - section['elf_va']
        return binary[offset:offset + size], offset, section['name']
    return read, sections


def snippet(path, start, end, filename):
    original = path.read_bytes()
    target = OUT / 'evidence' / filename
    target.write_text('\n'.join(original.decode().splitlines()[start - 1:end]) + '\n')
    return {'source': str(path), 'source_sha256': sha(original),
            'start_line': start, 'end_line': end,
            'snippet': str(target), 'snippet_sha256': sha(target.read_bytes())}


def claim(identity, conclusion, methods, points=()):
    return {'id': identity, 'certainty': 'confirmed_static_client_flow',
            'conclusion': conclusion, 'methods': [hex(v) for v in methods],
            'instruction_points': [hex(v) for v in points]}


def claims():
    return [
        claim('two_singleton_ids', 'PreviewService+0xb 默认0，是路由结束用的请求设备ID；MainService+0xf 默认-1，是102前缀过滤用的 unboxed int；MainService+0xb 是全局 RxString。它们不是同一个字段。', [0x4580b4, 0x459704, 0x4597b0], [0x4580f0, 0x459768]),
        claim('reentry_clear_only_image', '预览 initState 只对全局 RxString.value 赋空字符串，不清 MainService 匹配ID，不在此入口发送 startPreview。', [0x51d844], [0x51d868]),
        claim('start_local_then_async_id', '选方向先 setState 改方向并加载第一台方向匹配设备参数、画框；startPreview 请求前写 PreviewService ID。onValue 无 ok/success 检查，直接写 MainService ID=device.id??0，再日志。GET普通失败正常完成也进入它；reject/pending 不进入 onValue。', [0x457b04, 0x457b58, 0x459e60, 0x459b30, 0x457dc4, 0x45911c, 0x457e8c], [0x457dec, 0x459180]),
        claim('switch_no_stop_no_generation', '已审查选方向/start/onValue 没有先 end 旧设备，没有清 Rx 图像值，没有请求代际/当前选中设备/页面mounted复核；onValue捕获设备对象。异步完成顺序与所选方向可以不同，属于条件性推导，不是已观察事故。', [0x457b58, 0x45911c]),
        claim('ws102_prefixed_filter', '102先对 data 调 toString，含|时 split：int.parse(parts[0])，取parts[1]，仅与 MainService+0xf 比较；不等直接返回，相等则 decode_data(parts[1]) 后 Rx.value=。多余分段不参与本分支。', [0x527460, 0x528074], [0x527654, 0x527678, 0x52769c, 0x5276a0, 0x5276b8, 0x5276c4]),
        claim('ws102_legacy_unfiltered', 'data.toString不含|时，整个字符串 decode_data 后直接赋全局Rx；无设备ID比较，无预览页/PreviewService ID/当前方向检查。两条102路径本身不做HTTP取图。', [0x527460], [0x5275fc, 0x5276e4, 0x5276f0]),
        claim('ws102_invalid_before_write', 'int.parse及parts[0]/[1] bounds、decode_data替换错误发生在Rx setter前，本次分支不会覆盖原值。正常String且indexOf(|)>=0时split应有至少两段，不能仅见bounds stub就宣称常见输入会越界。没有局部try/catch或错误占位图。', [0x527460, 0x528074], [0x52763c, 0x527654, 0x527678, 0x528020, 0x528024]),
        claim('render_decode_after_rx_write', '102写入的是替换后的字符串；Obx非空分支再 base64Decode→decodeJpg→State.field_bb→updateDrawImg→encodePng→Image.memory。非法base64/JPEG/框参数错误发生在赋值之后，不恢复全局Rx原值；空字符串分支给空占位Widget。', [0x463e08, 0x458144, 0x51d884], [0x463eac, 0x463eb4, 0x463ebc]),
        claim('loading_is_opacity_not_timeout', '另一观察回调依据Rx是否空控制加载提示 AnimatedOpacity，Duration=200ms；不是识别重试/预览超时/自动重新start定时器。', [0x463a10]),
        claim('optimistic_save', 'save先构造19参数Map并更新所选Devices对象的19配置槽，再调用服务POST。缓存brightness槽写固定75.0，请求brightness取UI double；请求框4参数及motor均double.toInt()，本地框参数仍保留UI double，motor缓存int。返回失败/响应阶段类型错误没有本方法内回滚。', [0x45fcb4, 0x460b60], [0x46045c, 0x4604a4, 0x460598, 0x4605a0, 0x46089c, 0x4608e0]),
        claim('save_error_phase_boundary', '不能把所有save错误均归为ID已清0：查方向设备/组参数Map/框参数及motor.toInt在调用savePreviewParams之前；若这里抛错，尚未到服务清ID。只有达到0x4608e0服务调用，或之后的响应map索引/success bool类型错误，才能按已完成的设备写入和ID清零分析。无匹配设备也不发请求，不在此方法清ID。', [0x45fcb4, 0x460ab4, 0x460b60], [0x45fd74, 0x45fe8c, 0x460038, 0x46045c, 0x4608e0, 0x460ad0]),
        claim('save_resets_id_even_failure', 'savePreviewParams第一项业务写入即 PreviewService+0xb=0，再构URL/POST，与close无关，不等响应。随后普通返回的route completion可因0跳过end，即使保存失败。', [0x460ab4, 0x4ac0b8], [0x460ad0]),
        claim('save_response_gate', '保存onValue需 response.ok && (data[success] as bool)==true && close 才执行end与pop；ok=false、success=false、close=false直接返回。success缺失/类型不对或data不支持索引可抛错，不转成失败提示或回滚。', [0x460b60], [0x460ba0, 0x460c04, 0x460c0c, 0x460c28]),
        claim('end_unawaited_and_pop', '成功save-close调用endPreview(capturedDevice.id)，只挂返回null的onValue，没有onError；立即Navigator.pop(true)，不等待结束HTTP。end方法在POST之前清PreviewService ID。', [0x460b60, 0x461014], [0x460c4c, 0x460c78, 0x460cb8, 0x46102c]),
        claim('route_end_future_not_returned', '父route completion忽略路由结果，ID!=0才endPreview(ID)，但丢弃Future并return null，故异步end错误/等待不被这个route then接续等待。同步服务调用抛错仍可让route回调Future失败；该then结果也被调用者丢弃。', [0x4ac018, 0x4ac0b8, 0x461014], [0x4ac118]),
        claim('http_three_failure_classes', 'HTTP get/post Await AppDio 后handleResponse，200<=status<300置ok=true且不查body.success；Exception走HttpResponse(ok=false,exception,data=null)普通包装路径，非Exception rethrow，异常解析本身抛错也不保证包装成功。双条件HTTP401且Dart data[code]==整数常量401（动态相等运算，不是严格int类型校验，字符串401不满足）进入interceptor：清JWT并offAll(LoginPage)后不next/resolve/reject；导航等正常返回时已审查completer链pending。不能把结束失败一概称reject。', [0x457e8c, 0x42c230, 0x42cc54, 0x42c3d4, 0x67f850, 0x42ede4]),
        claim('end_failure_no_restore', 'end普通ok=false或body.success=false不恢复ID也无专用失败回调；非Exception拒绝只向无onError的then传播；401特殊pending使onValue不执行。三者都没有本链自动重新start/重试end/清MainID或Rx。不能据页面关闭断言服务器设备已停止。', [0x460b60, 0x4ac0b8, 0x461014]),
        claim('main_stream_registration', 'Main initState订阅Rust事件流，listen只传onData(0x527460)，所审查调用无onError/onDone/cancelOnError实参；预览State没有创建自己的Rust事件订阅。', [0x51f028], [0x51f3b4, 0x51f3bc]),
        claim('101_image_outer_future', '101→MessageUpImg→saveImg的外层 async Future只await临时目录；普通图像GET.then(0x529164)结果丢弃，随后外层完成。msg101挂的共享空then只观察该外层；不是文件写完的保证。img=x分支直接追加empty.jpg占位结果，不走GET。', [0x527460, 0x529e50, 0x5281d8, 0x529d68], [0x527558, 0x527584, 0x5284dc, 0x5287a8, 0x5287d4, 0x5287dc]),
        claim('101_image_callback_error', '图片HTTP onValue不读HttpResponse.ok，直接data as String、decode_data、base64decode、同步创建/写文件。因此普通GET失败包装data=null会在String强制检查抛错。2xx data非String/base64非法/文件I/O异常也无本回调内恢复或重试。', [0x529164, 0x457e8c, 0x42c3d4, 0x42cc54], [0x5291e8, 0x5291f0, 0x5291fc, 0x5292d0]),
        claim('101_live_channels_and_order', '图片完成后才读取Main的当前channels，按Device.serial_no与消息serial_number匹配；原number==1清移除偏移，再减当前channel偏移，setState闭包在当前结果列表尾追加。没有按num排序或重复抑制，没有捕获旧列表或roundId检查；并行完成顺序/列表替换能影响追加位置，须作为条件性时序。', [0x529164, 0x529c80, 0x529e50, 0x459f08], [0x5295b8, 0x5295d0, 0x5295f4, 0x529d24]),
        claim('101_current_count_followup', '该回调统计当前渠道device.mj_count总和与非空识别结果数；相等时取消计时器、countdown置0、提示等待数据发送中，再onOpenChangePage和onValidDataAndSendData。这里不展开既有result_pipeline，也不把101图像GET当102预览图流。', [0x529164, 0x529c50], [0x5297a8, 0x5297d0, 0x5297e8, 0x529814, 0x529824]),
        claim('main_dispose_not_http_cancel', 'Main.dispose取消事件订阅及两个Timer，调用del_cache_img、Wakelock.disable但不等待；没有取消已经挂出的图片GET/Future回调，没有清全局MainID/Rx。不能由此证明cancel以后仍会派发新的WS事件；ReceivePort收尾由根工件另核。', [0x556974, 0x526d30, 0x526d90], [0x5569cc, 0x556a00]),
        claim('late_setstate_mutates_before_error', 'framework unmount先调用State.dispose再State.element=null。此release setState先调用传入闭包，再读element；null则NullCastError。因此若既有图片回调确在Main unmount后完成，写文件及结果append闭包可能先执行，再在setState抛错；没有mounted guard。不是运行时已发生的断言。', [0x529164, 0x529c80, 0x302dfc, 0x5d8f1c], [0x302e28, 0x302e30, 0x302e5c, 0x5d8f84]),
        claim('late_save_context', 'save-close成功回调先发送capturedDevice.id的end，再读取预览State.element用于Navigator.of；若页面已卸载，仍可能先发end，随后element=null触发NullCastError。没有回调前mounted/当前方向检查，不能保证只pop原页面一次。', [0x460b60, 0x5d8f1c], [0x460c4c, 0x460c88, 0x460c94, 0x460ce0]),
        claim('observer_value_distinction', '预览文件无自有dispose导出不表示子Widget观察订阅永久保留。ObxState.dispose取消自己的sub并close自己的notifier；本操作不清全局MainService的Rx值。完整观察框架关联证据见既有end_preview工件，本轮仅重摘关键dispose。', [0x55e25c]),
        claim('no_automatic_preview_resume_in_reviewed_paths', '全业务直接调用索引只见start一处、save一处、end两处。event10分支wsLogin完成仅日志，设备轮询回调只更新设备状态；未见这三方法或端点常量的额外调用。此为有限AOT业务索引/完整回调范围，不排除未知间接分派或服务器自行恢复。', [0x527460, 0x52a398, 0x520fe8, 0x5210c8, 0x523f84, 0x52a724]),
    ]


def scenarios():
    rows = [
        ('end_then_late_prefixed', 'end已先清PreviewService ID，但MainService匹配ID仍为A；Main listener随后实际收到A|image且decode成功', 'Rx仍可更新；是否服务器在end后发送未知', ['end_failure_no_restore', 'ws102_prefixed_filter']),
        ('closed_page_legacy', '预览路由关闭、Main仍存活并收到不带|的102', '无设备/预览状态门控，写全局Rx；已卸载Obx不等于全局值清空', ['ws102_legacy_unfiltered', 'observer_value_distinction']),
        ('reenter_before_start_response', '新预览init清Rx，Main匹配ID仍A；随后请求start(B)的onValue尚未执行，收到A|image', '符合旧A匹配，空图可再次被旧A数据覆盖；init本身没有自动start', ['reentry_clear_only_image', 'start_local_then_async_id', 'ws102_prefixed_filter']),
        ('switch_pending_or_reject', '切方向B已更新UI及PreviewService ID，但B start仍pending或reject', 'Main匹配ID可仍A，已有图像不因切方向而清；普通ok=false正常完成则也会改B', ['switch_no_stop_no_generation', 'start_local_then_async_id']),
        ('start_response_order', '先start A再start B，两请求都正常完成，A完成晚于B', '后到A回调把Main匹配ID写A，即使UI最后选B；没有代际检查', ['start_local_then_async_id', 'switch_no_stop_no_generation']),
        ('failed_save_then_back', 'save已进入savePreviewParams并先清PreviewService ID=0；ok=false、success=false、响应阶段类型错误或特殊pending；期间没有新start', '返回路由父回调因0跳过end；共享设备字段保持此前写值，无失败回滚', ['optimistic_save', 'save_resets_id_even_failure', 'save_response_gate', 'save_error_phase_boundary']),
        ('end_ordinary_failure', 'save-close门控通过，end普通Exception→ok=false或2xx业务success=false', '页面已经pop；空onValue不查看结果；ID不恢复；服务器是否停止未知', ['end_unawaited_and_pop', 'http_three_failure_classes']),
        ('end_nonexception_or_401', 'end产生非Exception错误或双重401特殊分支', '前者错误向无onError的then传播，后者请求链pending；都不等待路由，不自动重试；401另offAll登录页', ['http_three_failure_classes', 'route_end_future_not_returned']),
        ('save_completes_after_back', '保存close=true挂出后先返回且预览已unmount，随后保存ok/success均true', '回调先end捕获设备，再因element=null在Navigator查找前抛错；可能重复结束请求但未实测', ['late_save_context']),
        ('old_save_close_after_switch', '保存A(close=true)待响应期间又start B；A保存onValue门控通过', 'end实参仍A，但其服务入口清全局PreviewService ID（可已是B），随后pop；没有重新核对当前方向', ['save_response_gate', 'end_unawaited_and_pop', 'switch_no_stop_no_generation']),
        ('parallel_101_completion', '多个101消息在独立GET中，后发请求先完成，回调均匹配当前渠道', '按各回调完成顺序append；无该回调内部num排序/重复抑制。已有列表被清后旧回调也使用新列表', ['101_image_outer_future', '101_live_channels_and_order']),
        ('101_after_main_unmount', '已经挂出的图片GET在Main unmount后正常返回String且解码/写盘成功', '先写盘并可能执行append，随后setState element-null失败；不会因取消WS订阅自动取消这个HTTP Future', ['main_dispose_not_http_cancel', 'late_setstate_mutates_before_error']),
        ('cache_delete_vs_callback', 'Main.dispose调用del_cache_img，同时已有图片回调待完成', '删除与GET Future未建立await/取消顺序；文件是否存在、创建/写入是否抛I/O错误取决于实际顺序，不作确定结论', ['main_dispose_not_http_cancel', '101_image_callback_error']),
    ]
    return [{'id': i, 'certainty': 'conditional_static_interleaving_not_observed',
             'preconditions': pre, 'derived_outcome': outcome, 'claims': refs}
            for i, pre, outcome, refs in rows]


ERRORS = [
    {'phase': 'startPreview', 'condition': 'ordinary Exception or non-2xx response wrapped normally', 'future': 'value: HttpResponse(ok=false,data=null)', 'effect': 'onValue仍写MainID，不查ok；无重试/回滚', 'methods': ['0x457e8c', '0x45911c']},
    {'phase': 'start/save/end/getImg', 'condition': 'non-Exception thrown in HTTP wrapper', 'future': 'error; rethrow', 'effect': 'value回调不执行，已执行的本地写入不自动撤销', 'methods': ['0x457e8c', '0x42c230']},
    {'phase': 'start/save/end/getImg', 'condition': "HTTP status==401 AND Dart data['code']==401 (dynamic equality against integer literal, not strict int type)", 'future': 'pending in reviewed interceptor completer chain if interceptor/navigation return normally', 'effect': '清Dart JWT并offAll(LoginPage)，handler无next/resolve/reject；字符串401不满足，非严格int校验；不是普通ok=false', 'methods': ['0x67f850', '0x42ede4']},
    {'phase': 'save before service entry', 'condition': '查设备/组Map/数值toInt错误；或无方向匹配设备', 'future': 'synchronous throw or return without HTTP', 'effect': '未到savePreviewParams则本次服务ID未清，不能与响应类型错误后的状态混同；设备缓存写入须按实际指令阶段判断', 'methods': ['0x45fcb4', '0x460ab4']},
    {'phase': 'save callback', 'condition': '!ok OR success=false', 'future': 'value callback returns null', 'effect': '不end、不pop、无本回调提示/rollback；设备字段与服务ID已改', 'methods': ['0x460b60']},
    {'phase': 'save callback', 'condition': "data无索引能力或data['success']非bool", 'future': 'then result error (discarded)', 'effect': '不达end/pop；已写状态不回滚', 'methods': ['0x460b60']},
    {'phase': 'end sync service entry', 'condition': 'late _httpClient或参数字符串拼接阶段同步错误', 'future': 'call throws before obtaining returned future', 'effect': '服务ID已清；可使save/route回调then失败；与后续HTTP异步错误不同', 'methods': ['0x461014', '0x460b60', '0x4ac0b8']},
    {'phase': 'end normal value', 'condition': 'ok=false OR 2xx with business success=false', 'future': 'value; shared onValue returns null, or route discards Future', 'effect': '结果不读取，无服务器停止判定、恢复ID或重试', 'methods': ['0x460b60', '0x4ac0b8', '0x461014']},
    {'phase': 'WS102 parse/filter', 'condition': 'illegal integer prefix; parts bounds checks; decode_data replacement error', 'future': 'onData synchronous error; no local catch', 'effect': '本次尚未setter，原Rx值未由此分支覆盖；全局其他并发写入未知', 'methods': ['0x527460', '0x528074']},
    {'phase': 'WS102 Rx render', 'condition': 'invalid base64/JPEG or downstream image/rectangle processing error', 'future': 'observer/build error; no local recovery', 'effect': 'Rx已存新字符串，不回滚；不自动startPreview', 'methods': ['0x463e08', '0x458144']},
    {'phase': 'saveImg outer', 'condition': '临时目录/同步建目录等在GET调度前出错', 'future': 'outer saveImg Future error; msg101 then has no onError', 'effect': '不会达到GET安排；不能说所有saveImg都成功正常完成', 'methods': ['0x5281d8', '0x527460']},
    {'phase': 'saveImg HTTP value', 'condition': '普通GET失败产生ok=false/data=null，或2xx data不是String', 'future': 'String type check throws in then; chained future discarded', 'effect': '尚未解码写盘/append；外层saveImg Future可早已完成', 'methods': ['0x529164', '0x42c3d4']},
    {'phase': 'saveImg decode/file/callback', 'condition': 'base64非法、同步I/O异常、Device.direction null、Main unmounted', 'future': 'then callback throws (no local catch)', 'effect': '根据失败阶段可能已写盘/改result.num/append，不能统一宣称全部操作回滚', 'methods': ['0x529164', '0x302dfc']},
]


NOTES = '''预览失败、晚到102与图片异步恢复静态说明

最关键的客户端状态是两个单例里的不同ID。PreviewService+0xb默认0，在startPreview发请求前写设备ID；savePreviewParams和endPreview均在HTTP前清0。MainService+0xf默认-1，只有start的onValue写入device.id??0，用于102带前缀图像过滤；MainService+0xb是全局RxString图像值。已审查退出/save/end不清后两个字段。再次进入预览的initState仅Rx.value=''，不清匹配ID，也没有在initState直接自动发startPreview。

102不含|的旧格式：data.toString→decode_data整个字符串→全局Rx.value，无设备过滤。含|：split后int.parse(parts[0])，读取parts[1]，与MainService匹配ID比较；不符直接返回，相符替换字符串后写Rx。多余分段不使用。这里没有检查PreviewService ID、预览是否打开、方向或mounted，也没有HTTP取图。因此只要Main listener实际收到消息，退出后的旧ID前缀或无前缀消息仍可更新全局值；静态代码不能证明服务器真的晚发或取消订阅后仍派发。

非法int前缀及decode_data替换错误在Rx setter之前发生，本次不会覆盖原值。parts[0]/[1]都有bounds→RangeError分支，但正常String且indexOf('|')>=0时split会有至少两段，不能把编译器bounds检查当作普通格式一定越界。decode_data是按静态0xbc0配置分割并replaceAll；102本分支只写字符串。真正base64Decode/JPG解码发生在Obx绘图回调，失败时新Rx值已存，未恢复旧值。加载提示的200ms AnimatedOpacity不是超时、重试或自动恢复预览机制。

切换设备先更新方向、加载所选设备参数，再start；它不先end旧设备，也不清现有Rx图像。start的onValue不检查ok/success，不核对当前方向、页面mounted或请求代际：普通HTTP异常包装成ok=false仍正常完成并改Main匹配ID；non-Exception拒绝及特殊401 pending不运行onValue。若多个start异步返回顺序不同，最后执行的回调决定匹配ID，而PreviewService ID在请求发起时已经写过；两个ID可能暂时或最终不同。再进入时清空图像与新start回调之间，旧Main ID仍能匹配旧帧；这是条件性时序结论，不是运行时事故观察。

保存先构造19参数并写共享Devices对象，再POST。brightness请求取UI double，但本地缓存槽强写75.0；请求left/top/right/bottom及motor均double.toInt()，本地框参数保留UI double，motor缓存int。只有确实达到savePreviewParams，服务才同步清ID=0，close=false/true都如此。查设备/组Map/toInt的前置错误或无匹配设备未必到达此处，不能笼统称所有类型错误均已清ID。响应回调按ok、data['success'] as bool、close门控：false只返回，无本回调错误提示和回滚；响应非法success类型会使then失败，此时设备缓存写入及ID清零已发生。故这一保存响应失败后再返回，若没有新start，父路由回调因ID=0跳过end。无法断言实际服务器预览因此继续或停止。

save-close满足门控后：endPreview(capturedDevice.id)→挂空onValue→立即Navigator.pop(true)。end第一步清0，不等待响应，不读ok/body.success。父路由完成回调也只在PreviewService ID!=0时end，Future不return/await，与route完成链没有异步等待接续。同步服务构URL/late字段错误可使save或route的then回调失败；取得Future后的异步错误不会因父回调return null而加入route链。页面已卸载时晚到save-close回调仍先end捕获设备，随后读State.element，null则抛错；没有mounted检查。结果不能概括为end成功后退出。

HTTP必须分三类：Exception走HttpResponse(ok=false,exception,data=null)普通包装路径，异常解析本身若抛错不保证包装成功；非Exception rethrow；HTTP status401且Dart data['code']==整数常量401（AND，动态相等运算，不是严格int类型校验，字符串'401'不满足）→清Dart JWT、offAll(LoginPage)，onError没有handler.next/resolve/reject，导航等正常返回时已审查completer链保持pending。handleResponse只将200<=status<300视为ok，不查业务success。结束请求的普通失败回调不恢复ID，拒绝无业务onError，pending不运行回调；本链没有自动start、补发end或恢复Main ID/Rx。完整HTTP模型见同轮dart_http/dart_http_failure.json；本目录同时保存关键完整原方法及原ELF allocator补证data默认null，后续验证不依赖其他生成脚本hash。

101图像获取是另一条链。saveImg外层只await getTemporaryDirectory；普通图像创建缓存目录后GET(getImgUrl(img)).then(0x529164)，丢弃then Future并完成外层。msg101的共享空then只观察这个外层，不能表示图片已写完；img='x'直接追加empty.jpg占位，不GET。图片onValue不检查ok而直接data as String→decode_data→base64decode→同步写盘；普通GET失败data=null会在String检查抛错，外层此时可能已经完成。临时目录/同步目录操作也可让外层失败，不是所有saveImg错误都只在内部then。

图片回调在HTTP完成后读取Main的当前channels，按消息serial_number与Devices.serial_no匹配，在当时的结果列表尾追加，number==1时先清移除偏移，然后减当前偏移。未见roundId/请求代际、重复抑制、num排序或捕获旧列表。多个GET可独立在途，条件性影响追加顺序；旧回调可落入已替换的新列表。计数达到当前mj_count总和时，该回调继续既有结果校验/发送链。这里只指出对既有result_pipeline的衔接，不另推服务器消息生成规则。

Main.dispose取消Rust事件订阅及两个Timer，del_cache_img和Wakelock.disable不等待；没有取消既有图像HTTP Future。缓存删除调用本身也丢弃getTemporaryDirectory.then及Directory.delete的Future，实际删除与写盘先后未知。框架unmount先dispose、再置State.element=null；本release setState先执行闭包再查element。因此若已有图片回调在Main卸载后完成，写盘与append闭包可能先发生，随后NullCastError；不能简单写成mounted保护阻止全部写入。WS取消/ReceivePort收尾由根同轮工件处理，不能以缺HTTP取消推定取消后的新WS派发。

有限负证据：全distinguish导出源目录扫描三服务entry直接BL，只有start 1、save 1、end 2；同时检查三端点字符串引用。event10只wsLogin.then，完成回调只日志，轮询完整回调没有自动恢复预览/补end。预览文件完整方法目录无自有dispose、PopScope/WillPopScope/onWillPop；这不等于Obx观察订阅未清。已有关联工件确认框架卸载Obx会清其自身观察器，所清不是全局Rx值。本轮不以方法目录负证据排除未知间接分派、其他原生逻辑或服务器自行恢复。

复现：python3 APP/scripts/preview_failure_extract.py
独立验证：python3 APP/scripts/preview_failure_extract.py --verify
preview_failure.json保存流程、错误、条件性时序、边界；evidence_manifest.json保存完整原方法的地址/size/一基行区间/来源与摘录SHA256、直接BL原ELF核验、关键raw字段binary/elf_va/bytes_le/target_elf及LLVM快照。verification.json的PASS证明来源、摘录和原始机器码一致，不把手工业务语义推论等同运行时验证。未执行APK/Dart/业务库，也未联系业务服务器。
'''

PSEUDOCODE = '''// 手工静态重建，结构化示意；字段名是解释性别名，非原源码。
// 数组/字符串操作按所见顺序；无新增错误处理/取消/await。
class PreviewIds {
  dynamic serviceId = 0; // PreviewService+0xb
  int imageMatchingId = -1; // MainService+0xf，独立字段
  RxString image = ''.obs; // MainService+0xb
}
void previewInitState() { ids.image.value = ''; } // 不清匹配ID，不自动start
Future<HttpResponse> startPreview(dynamic id) {
  ids.serviceId = id;
  return http.get('/api/preview/start_preview/' + id.toString());
}
void selectDirection(int direction) {
  setState(() { selectedDirection = direction; });
  final device = firstMatchingDirection(Utils.devices, direction); // 无匹配则返回
  setState(() { loadDeviceParams(device); updateDrawImg(); });
  startPreview(device.id).then((r) {
    ids.imageMatchingId = device.id ?? 0; // 不查ok/success/mounted/当前direction
    Log.d(r.data);
  }); // then Future被丢弃，无onError；切换不先end旧设备
}
void mainWsOnData(WsEvent e) {
  if (e.eventType == 4) {
    final m = Message.fromJson(jsonDecode(e.content) as Map<String,dynamic>);
    if (m.msg_type == 102) {
      final s = m.data.toString();
      if (s.indexOf('|') != -1) {
        final p = s.split('|');
        final id = int.parse(p[0]); // 非tryParse；parts bounds、非法整数错误未catch
        final data = p[1]; // 其余段忽略
        if (id != ids.imageMatchingId) return;
        ids.image.value = Utils.decode_data(data);
      } else {
        ids.image.value = Utils.decode_data(s); // 无设备ID过滤
      }
    } else if (m.msg_type == 101) {
      saveImg(MessageUpImg.fromJson(m.data)).then((_) => null); // 共享8字节null入口
    }
    // 其他业务分支见原完整方法，不在此伪代码重新展开。
  } else if (e.eventType == 10) {
    wsLogin(Utils.jwt).then((ignoredInt) { Log.d('ws login success！'); });
    // 无preview重启，日志不是认证成功判据
  }
}
Widget imageObserver() {
  if (ids.image.value == '') return emptyWidget;
  final bytes = base64Decode(ids.image.value);
  jpg = decodeJpg(bytes); // 失败不恢复已写Rx值
  updateDrawImg();
  return Image.memory(encodePng(jpg));
}
Future<HttpResponse> savePreviewParams(id, Map<String,num> data) {
  ids.serviceId = 0; // close标志不参与，先清ID
  return http.post('/api/preview/set_params_v2/' + id.toString(), data: data);
}
Future<HttpResponse> endPreview(id) {
  ids.serviceId = 0; // 不等服务器回复
  return http.post('/api/preview/end_preview/' + id.toString());
}
void save(bool close) {
  final device = firstMatchingDirection(Utils.devices, selectedDirection);
  final data = uiMapOf19Parameters();
  write19DeviceSlots(device, ui); // 框参数缓存double/请求toInt；brightness缓存75.0/请求UI；motor.toInt
  savePreviewParams(device.id, data).then((r) {
    if (!r.ok) return null;
    if (!(r.data['success'] as bool)) return null;
    if (!close) return null;
    endPreview(device.id).then((_) => null); // 无onError/await
    Navigator.of(state.element!).pop<bool>(true); // end后才读element
    return null;
  }); // no rollback/error toast in this callback
}
void showPreview() {
  final f = Get.to(() => FramePreviewPage());
  f?.then((ignoredRouteResult) {
    if (ids.serviceId != 0) endPreview(ids.serviceId); // Future不return
    return null;
  }); // 返回值也丢弃
}
Future<void?> saveImg(MessageUpImg m) async {
  var number = m.mahjong_number ?? 0;
  final img = m.img ?? '';
  if (Utils.static_bc4 == true) number += number.isEven ? -1 : 1;
  if (img == 'x') {
    appendPlaceholderToCurrentMatchingSerialChannel(m.serial_number, number);
    return;
  }
  final temp = await getTemporaryDirectory(); // 本外层唯一await
  final directory = prepareDateCacheDirectorySync(temp);
  final filename = randomPngName();
  http.get(getImgUrl(img)).then((r) {
    // 无 r.ok 判断；普通失败data=null，此处as String抛错
    final bytes = base64Decode(Utils.decode_data(r.data as String));
    final file = createFileIfAbsentSync(directory, filename);
    file.writeAsBytesSync(bytes);
    final result = buildChannelResult(file.path, number, m.ai_val, m.ai_precision);
    for (final channel in main.currentChannels) {
      if (channel.device.serial_no != m.serial_number) continue;
      assertNonNull(channel.device.direction); // release所见非空检查
      if (result.number == 1) channel.removedOffset = 0;
      result.number -= channel.removedOffset;
      setState(() { channel.currentResults.add(result); });
    }
    if (currentNonEmptyResultCount() == sumCurrentDeviceMjCount()) {
      receiveTimer?.cancel(); countdown = 0;
      setState(() { statusText = '等待数据发送中...'; });
      onOpenChangePage(); onValidDataAndSendData();
    }
    return null;
  }); // GET/then未await；无roundId/mounted/CancelToken/排序/去重
  return; // 外层完成≠图片处理完成
}
// wrapper摘要：Exception→ok=false,data=null正常value；非Exception→rethrow。
// HTTP401 && Dart data['code']==401（整数常量相等比较，非严格int校验）：
// JWT=''并offAll(LoginPage)，导航正常返回时handler不完成→已审查链pending。
void mainDispose() {
  wsSubscription?.cancel(); pollTimer?.cancel(); receiveTimer?.cancel();
  Utils.del_cache_img(); Wakelock.disable(); // 不await，不取消既有HTTP
}
// release framework：StatefulElement.unmount: state.dispose(); state.element=null。
// release State.setState: fn(); state.element!.markNeedsBuild();
// 所以 late HTTP callback 条件满足时可能先写盘/append，后element-null错误。
'''


def call_index():
    targets = {0x457dc4: 'startPreview', 0x460ab4: 'savePreviewParams', 0x461014: 'endPreview'}
    strings = ('/api/preview/start_preview/', '/api/preview/set_params_v2/', '/api/preview/end_preview/')
    inventory, calls, literals = [], [], []
    for path in sorted(BUSINESS.rglob('*.dart')):
        raw = path.read_bytes()
        lines = raw.decode().splitlines()
        inventory.append({'source': str(path), 'source_sha256': sha(raw)})
        owner = None
        for i, line in enumerate(lines):
            if (h := HEADER.search(line)):
                owner = h[1]
            if (b := BL.search(line)) and int(b[2], 16) in targets:
                calls.append({'source': str(path), 'source_sha256': sha(raw),
                              'line': i + 1, 'text': line, 'owner_method': owner,
                              'elf_va': b[1], 'target_elf': b[2], 'method': targets[int(b[2], 16)]})
            if any(s in line for s in strings):
                literals.append({'source': str(path), 'source_sha256': sha(raw),
                                 'line': i + 1, 'text': line, 'owner_method': owner})
    assert [sum(c['method'] == n for c in calls) for n in targets.values()] == [1, 1, 2]
    return {'scope': str(BUSINESS), 'file_count': len(inventory), 'source_inventory': inventory,
            'source_inventory_sha256': sha(json.dumps(inventory).encode()),
            'direct_calls': calls, 'endpoint_literal_references': literals,
            'limits': 'Direct BL target and endpoint literal scan only; cannot exclude unknown indirect dispatch/inlining or native/server actions.'}


def build():
    (OUT / 'evidence').mkdir(parents=True, exist_ok=True)
    read, sections = elf_reader()
    methods, checks = [], []
    for path in sorted(ASM.rglob('*.dart')):
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            h = HEADER.search(line)
            if not h or int(h[1], 16) not in SELECTED:
                continue
            end = next(j for j in range(i + 1, len(lines)) if lines[j] == '  }')
            item = snippet(path, i, end + 1, h[1][2:] + '.asm.txt')
            item.update({'address': h[1], 'size': h[2], 'method_declaration': lines[i - 1].strip()})
            methods.append(item)
            for m in BL.finditer(Path(item['snippet']).read_text()):
                address, target = [int(v, 16) for v in m.groups()]
                raw, offset, section = read(address)
                word = int.from_bytes(raw, 'little')
                imm = word & 0x3ffffff
                if imm & 0x2000000:
                    imm -= 0x4000000
                assert word & 0xfc000000 == 0x94000000 and address + imm * 4 == target
                checks.append({'binary': str(LIB), 'elf_va': hex(address), 'file_offset': hex(offset),
                               'section': section, 'bytes_le': raw.hex(), 'word_hex': f'{word:08x}',
                               'check': 'BL', 'target_elf': hex(target)})
    assert {int(m['address'], 16) for m in methods} == set(SELECTED)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    ranges = []
    for name, start, stop in RAW_RANGES:
        raw, offset, section = read(start, stop - start)
        instructions = []
        for ins in decoder.disasm(raw, start):
            target = hex(int(ins.op_str[1:], 0)) if ins.mnemonic in ('b', 'bl') and ins.op_str.startswith('#') else None
            instructions.append({'binary': str(LIB), 'elf_va': hex(ins.address),
                                 'file_offset': hex(offset + ins.address - start), 'bytes_le': ins.bytes.hex(),
                                 'mnemonic': ins.mnemonic, 'operands': ins.op_str, 'target_elf': target})
        assert len(instructions) * 4 == len(raw)
        llvm = OUT / 'evidence' / (name + '.llvm.txt')
        llvm.write_text(subprocess.check_output([LLVM, '-D', f'--start-address={hex(start)}',
                                                f'--stop-address={hex(stop)}', str(LIB)], text=True))
        ranges.append({'id': name, 'binary': str(LIB), 'elf_start': hex(start), 'elf_end_exclusive': hex(stop),
                       'file_offset': hex(offset), 'section': section, 'bytes_le': raw.hex(),
                       'raw_sha256': sha(raw), 'instructions': instructions, 'llvm_file': str(llvm),
                       'llvm_sha256': sha(llvm.read_bytes())})
    support = snippet(APP / 'tools/blutter/dartsdk/v3.5.2/runtime/vm/constants_arm64.h', 130, 164, 'null_register.source.txt')
    preview = BUSINESS / 'pages/frame_preview/frame_preview_page.dart'
    data = preview.read_bytes()
    lines = data.decode().splitlines()
    inventory = [{'address': m[1], 'size': m[2], 'declaration': lines[i - 1].strip(), 'header_line': i + 1}
                 for i, line in enumerate(lines) if (m := HEADER.search(line))]
    negatives = {name: name in data.decode() for name in ('_ dispose(', 'PopScope', 'WillPopScope', 'onWillPop')}
    assert not any(negatives.values())
    index = call_index()
    manifest = {'generator': {'file': str(Path(__file__).resolve()), 'sha256': sha(Path(__file__).read_bytes())},
                'source_binary': {'file': str(LIB), 'sha256': sha(LIB.read_bytes()), 'section_mapping': sections},
                'methods': methods, 'raw_direct_bl_checks': checks, 'raw_ranges': ranges,
                'support_sources': [support], 'business_call_index': index,
                'preview_export_inventory': {'source': str(preview), 'source_sha256': sha(data),
                                             'methods': inventory, 'negative_patterns_found': negatives}}
    write_json('evidence_manifest.json', manifest)
    schema = [{'request_key': key, 'ui_field': '+' + ui, 'device_slot': '+' + dev,
               'request_conversion': typ, 'local_store_elf_va': store,
               'local_value': ('constant 75.0' if key == 'brightness' else
                               'current UI double (not request integer conversion)' if key in ('left', 'top', 'right', 'bottom') else
                               'current UI (same request conversion)'),
               'device_json_note': 'Devices JSON uses beta; preview API literal is bate' if key == 'bate' else None}
              for key, ui, dev, typ, store in PARAMETERS]
    evidence = {m['address']: m for m in methods}
    save_text = Path(evidence['0x45fcb4']['snippet']).read_text()
    keys = re.findall(r'// 0x[0-9a-f]+: r\d+ = "([^"]+)"', save_text)
    assert keys == [r[0] for r in PARAMETERS]
    cl = claims()
    for c in cl:
        c['evidence'] = [{k: evidence[a][k] for k in ('source', 'start_line', 'end_line', 'source_sha256', 'snippet', 'snippet_sha256')}
                         | {'address': a} for a in c['methods']]
    output = {'scope': 'static preview failure, late WS102, asynchronous 101 image and bounded recovery paths',
              'evidence_manifest': str(OUT / 'evidence_manifest.json'),
              'counts': {'claims': len(cl), 'conditional_scenarios': len(scenarios()), 'error_paths': len(ERRORS),
                         'preview_parameters': len(schema), 'full_methods': len(methods), 'direct_preview_calls': len(index['direct_calls'])},
              'claims': cl, 'conditional_interleavings': scenarios(), 'error_paths': ERRORS,
              'preview_parameter_state_writes': schema,
              'http_cross_reference': {'path': str(APP / 'analysis/reconnect_preview_failure/dart_http/dart_http_failure.json'),
                                       'purpose': 'root agent full wrapper/completer/error model; not a required generator/hash input'},
              'related_artifacts': [str(APP / 'analysis/connection_preview_closure/end_preview/end_preview_closure.json'),
                                    str(APP / 'analysis/result_pipeline/pipeline.json')],
              'finite_negative_boundaries': [
                  'Reviewed 102 branch has no page-open, direction, PreviewService ID or mounted test; not a whole-program negative.',
                  'Reviewed start/save/end callbacks have no generation/cancel/mounted checks or retry/rollback branches.',
                  'Direct BL and literal index is the complete distinguish AOT dump file set recorded in manifest; unknown indirect dispatch not excluded.',
                  'No own preview dispose in exported method inventory does not mean child Obx subscriptions never dispose.',
                  'Main subscription.cancel does not automatically cancel already-created HTTP futures; no claim about delivery after subscription cancellation.',
                  'Conditional late/interleaved outcomes are logical consequences under stated preconditions; no runtime/server observation.',
                  'Unhandled Zone/Flutter error presentation, actual HTTP order, native device cessation, server message origin and cache deletion order remain unknown.',
              ], 'target_code_executed': False, 'business_server_contacted': False}
    write_json('preview_failure.json', output)
    (OUT / '中文说明.txt').write_text(NOTES)
    (OUT / '重建伪代码.txt').write_text(PSEUDOCODE)


def verify():
    manifest = json.loads((OUT / 'evidence_manifest.json').read_text())
    output = json.loads((OUT / 'preview_failure.json').read_text())
    read, _ = elf_reader()
    assert sha(LIB.read_bytes()) == manifest['source_binary']['sha256']
    assert sha(Path(manifest['generator']['file']).read_bytes()) == manifest['generator']['sha256']
    for r in manifest['methods'] + manifest['support_sources']:
        raw = Path(r['source']).read_bytes()
        data = Path(r['snippet']).read_bytes()
        assert sha(raw) == r['source_sha256'] and sha(data) == r['snippet_sha256']
        assert data.decode() == '\n'.join(raw.decode().splitlines()[r['start_line'] - 1:r['end_line']]) + '\n'
        if 'address' in r:
            assert HEADER.search(data.decode()).groups() == (r['address'], r['size'])
            assert data.decode().splitlines()[-1] == '  }'
    for r in manifest['raw_direct_bl_checks']:
        address = int(r['elf_va'], 16)
        raw, offset, _ = read(address)
        assert raw.hex() == r['bytes_le'] and hex(offset) == r['file_offset']
        word = int.from_bytes(raw, 'little')
        imm = word & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        assert word & 0xfc000000 == 0x94000000 and address + imm * 4 == int(r['target_elf'], 16)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    words = 0
    for r in manifest['raw_ranges']:
        start, stop = int(r['elf_start'], 16), int(r['elf_end_exclusive'], 16)
        raw, _, _ = read(start, stop - start)
        assert raw.hex() == r['bytes_le'] and sha(raw) == r['raw_sha256']
        decoded = list(decoder.disasm(raw, start))
        assert len(decoded) == len(r['instructions'])
        for actual, expected in zip(decoded, r['instructions']):
            assert hex(actual.address) == expected['elf_va'] and actual.bytes.hex() == expected['bytes_le']
            assert actual.mnemonic == expected['mnemonic'] and actual.op_str == expected['operands']
            if expected['target_elf']:
                assert hex(int(actual.op_str[1:], 0)) == expected['target_elf']
        llvm = Path(r['llvm_file']).read_bytes()
        assert sha(llvm) == r['llvm_sha256']
        local_words = 0
        for i in re.finditer(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', llvm.decode(), re.M):
            address, word = [int(v, 16) for v in i.groups()]
            assert start <= address < stop and int.from_bytes(read(address)[0], 'little') == word
            local_words += 1
        assert local_words == (stop - start) // 4
        words += local_words
    shared = next(r for r in manifest['raw_ranges'] if r['id'] == 'shared_null_callback')
    assert shared['bytes_le'] == 'e00316aac0035fd6'
    assert call_index() == manifest['business_call_index']
    preview = manifest['preview_export_inventory']
    data = Path(preview['source']).read_bytes()
    assert sha(data) == preview['source_sha256']
    assert not any(preview['negative_patterns_found'].values())
    assert not any(name in data.decode() for name in preview['negative_patterns_found'])
    addresses = {m['address'] for m in manifest['methods']}
    ids = {c['id'] for c in output['claims']}
    for c in output['claims']:
        assert set(c['methods']) <= addresses
        assert len(c['evidence']) == len(c['methods'])
    for s in output['conditional_interleavings']:
        assert set(s['claims']) <= ids
    for e in output['error_paths']:
        assert set(e['methods']) <= addresses
    assert (OUT / '中文说明.txt').read_text() == NOTES
    assert (OUT / '重建伪代码.txt').read_text() == PSEUDOCODE
    result = {'status': 'PASS', 'full_method_excerpts': len(manifest['methods']),
              'claims': len(output['claims']), 'conditional_scenarios': len(output['conditional_interleavings']),
              'error_paths': len(output['error_paths']), 'preview_parameters': len(PARAMETERS),
              'raw_direct_bl_checks': len(manifest['raw_direct_bl_checks']), 'raw_ranges': len(manifest['raw_ranges']),
              'llvm_instruction_words': words, 'source_support_ranges': len(manifest['support_sources']),
              'business_files_scanned': manifest['business_call_index']['file_count'],
              'direct_preview_calls': len(manifest['business_call_index']['direct_calls']),
              'preview_exported_methods': len(preview['methods']),
              'generator_sha256': manifest['generator']['sha256'],
              'target_code_executed': False, 'business_server_contacted': False}
    write_json('verification.json', result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify', action='store_true', help='verify saved evidence without regenerating')
    args = parser.parse_args()
    if not args.verify:
        build()
    verify()
