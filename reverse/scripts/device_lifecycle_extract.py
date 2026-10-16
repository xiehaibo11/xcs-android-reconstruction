#!/usr/bin/env python3
"""Reproduce reviewed static device/game/preview lifecycle artifacts.

Reads Blutter's text output only. Semantic annotations and Dart-like pseudocode
are manual data-flow reconstructions, not recovered original source. No APK,
Dart snapshot, native library, endpoint or downloaded code is executed.
"""

from _paths import app_root, workspace_root
from pathlib import Path
import argparse
import hashlib
import json
import re

APP = app_root()
ASM = APP / 'analysis/aot_dump/asm/distinguish'
OUT = APP / 'analysis/device_lifecycle'
METHODS, SOURCES, POINTS = {}, {}, {}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def index_methods():
    for path in sorted(ASM.rglob('*.dart')):
        raw = path.read_bytes()
        lines = raw.decode().splitlines(keepends=True)
        source_sha = sha(raw)
        SOURCES[path] = lines
        for i, line in enumerate(lines):
            point = re.match(r'    // (0x[0-9a-f]+): (.*)', line)
            if point:
                POINTS.setdefault(point[1], []).append(dict(address=point[1],
                    source=str(path), line=i+1, text=line.strip(),
                    source_sha256=source_sha))
            header = re.search(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)', line)
            if not header:
                continue
            end = i + 1
            while end < len(lines) and lines[end].rstrip() != '  }':
                end += 1
            assert end < len(lines), (path, i)
            address = header[1]
            assert address not in METHODS, address
            METHODS[address] = dict(address=address, size=header[2], source=str(path),
                source_relative=str(path.relative_to(APP)), start_line=i,
                end_line=end+1, declaration=lines[i-1].strip(),
                source_sha256=source_sha, body=''.join(lines[i-1:end+1]))


def ev(*addresses):
    return [hex(a) if isinstance(a, int) else a for a in addresses]


def point(address):
    address = hex(address) if isinstance(address, int) else address
    matches = POINTS.get(address, [])
    assert len(matches) == 1, (address, matches)
    return matches[0]


def claim(key, conclusion, methods, points=()):
    return dict(id=key, conclusion=conclusion, certainty='confirmed_static_client_flow',
        method_evidence=ev(*methods), instruction_evidence=[point(a) for a in points])


SELECTED = [
    # Main state, UI and lifecycle.
    0x565264,0x51f028,0x52a76c,0x52af04,0x520fe8,0x52a724,0x5210c8,
    0x523f84,0x556974,0x527460,0x52a6fc,0x52a6d4,0x4a7858,
    0x4aac60,0x4aac98,0x4aaffc,0x4abf98,0x4abe28,0x4abeec,
    0x4aaa10,0x4aaa48,0x4aab28,0x4aac38,0x4aa740,0x4aa778,0x4aa940,
    0x4ac190,0x4ac018,0x4ac0b8,0x4ac134,0x4b7010,0x4b776c,0x4b77f8,
    # Services; previous HTTP contract is reused for schema details.
    0x52106c,0x5245d8,0x4abe90,0x4aaacc,0x4aa8e4,0x4af6e0,
    0x52b0b4,0x4b103c,0x4b02b0,0x4afc3c,
    0x457dc4,0x460ab4,0x461014,
    # Settings and its response/state chain.
    0x4ac23c,0x4af610,0x4af648,0x4af7f8,0x52afa4,0x52b020,0x52b110,
    0x52b498,0x52bf28,0x52b9d8,0x52c324,0x52c350,
    0x4b0d78,0x4b0db0,0x4b10a4,0x4aff50,0x4aff98,0x4b0318,
    0x4afb30,0x4afd30,0x4af558,0x4af5cc,0x4b42d0,0x4b447c,
    # Preview selection, drawing, UI actions and response chain.
    0x564d4c,0x51d844,0x4575e8,0x457904,0x457b04,0x457b58,0x459e60,
    0x459b30,0x45911c,0x458144,0x463e08,0x45b36c,0x462adc,0x45fc68,
    0x45fcb4,0x460b60,0x463668,0x4636b4,0x4639cc,
    # Physical field names corroborated by model serialization.
    0x459f08,0x4901f0,
]


def claims():
    return [
        claim('main_device_identity', 'Main.initState 遍历 Utils.devices，先把每台设备 lighting_switch 设为 0，再构造 Channel；Channel 引用同一个 Devices 对象，结果列表初始为空、移除偏移为 0，不是设备深拷贝。', [0x51f028,0x4901f0,0x459f08], [0x51f220,0x51f284]),
        claim('main_initial_async_order', 'initState 发起 getMjConfigReq.then，完成设备通道建模后立即查询设备状态，再创建 5 秒 Timer.periodic 并订阅 Rust 事件流；这些 Future 未 await。', [0x51f028,0x52a76c], [0x51f334,0x51f36c,0x51f374,0x51f3b4]),
        claim('main_config_ws', 'MjConfig 回调直接将 data.success 转为 bool，不先读 response.ok；成功时按 URL substring(7) 和 :8081 截取 host 发起 initWs，并以 catchError 记录日志；初始化 Future 不 await。牌字典随后写入 Main.field_1f。', [0x52a76c,0x52af04]),
        claim('poll_schedule', '首次查询立即发生，随后每 5000000 微秒触发 deviceStatusAll；查询方法返回 void，在 Future 上挂 then。审查方法未设置 in-flight 锁，也未 await 上次请求。', [0x51f028,0x520fe8,0x52a724], [0x521050]),
        claim('poll_success_match', '设备轮询先要求 HttpResponse.ok，再将 body.success 强制转 bool 并要求 true；对每个现有 Channel 遍历响应 data，直接比较 serial_no。不创建/删除通道，不匹配则保留旧值，同一 serial_no 多行会继续更新。', [0x5210c8]),
        claim('poll_offline_sound', '只有旧 online==1 且当前响应 online==0 的匹配记录触发 offline_error.wav；音频 play 的 Future 未 await，随后执行字段更新和刷新。', [0x5210c8], [0x521438,0x521450]),
        claim('poll_field_updates', '匹配记录更新 9 个 nullable 字段：ip:String?、online:int?、delay:double?、connected_at:String?、ver:String?、client_wifi:String?、client_ip:String?、run_time:String?、up_time:String?。HTTP 轮询不写 direction、mj_count、lighting_switch 或 status。', [0x523f84,0x459f08,0x4901f0], [0x52403c,0x5240e0,0x524188,0x524230,0x5242d8,0x524380,0x524428,0x5244d0,0x524578]),
        claim('ws_device_field_names', '117 按 serial_no 设置 lighting_switch=1；114 设置 lighting_switch=0，全部关闭后更新状态文字并取消接收倒计时；115 设置 online=0 且 lighting_switch=0；116 设置 online=1。field_1f 是 lighting_switch，不能命名为 Devices.status。', [0x527460,0x459f08,0x4901f0,0x52a6fc,0x52a6d4], [0x527850,0x5279b0,0x5279b4,0x527ad0,0x527c00]),
        claim('device_display', '左侧通道按 direction=1/2/3/4 显示东/南/西/北，其他显示未知；显示 mj_count、在线状态及受 lighting_switch 影响的灯光标识。该显示行没有控制升降的 HTTP 调用。', [0x4b7010,0x4b776c,0x4b77f8], [0x4b7494]),
        claim('dispose', 'Main.dispose 处置 popover、取消事件订阅和 5 秒轮询 Timer、取消接收倒计时，删除缓存图片、禁用 Wakelock。所审查 dispose 不取消已发出的 HTTP Future、不 await 清理，也未调用 audioPlayer.dispose。', [0x556974]),
        claim('start_precondition', '开始按钮先执行 server_url 的 substring(7)/:8081 截取，但结果没有作为 isContentWs 入参；实际调用无业务参数的 isContentWs()。补充原生 worker 0x1b8348/getter 0x1e2c04 证明正常返回只读 SDK+0x2a5 连接标志，不读认证标志或比较地址。返回 true 则直接请求 start_games，false 则等 wsLogin(JWT) 的本地 Future 完成后再请求；不判断其返回值，也不等待 types50 认证响应。页面入口返回 void。跨层新证据见 connection_preview_closure。', [0x4a7858,0x4aac60,0x4aac98,0x4aaffc,0x4abf98,0x4abe28]),
        claim('start_response', 'start_games 回调不读取 response.ok，直接要求 body.success 是 bool 且 true，才 showSuccess(指令下发成功)；false 静默。HTTP 成功回调不直接清结果、改主状态文字或启动倒计时。', [0x4abeec]),
        claim('end_response', '结束按钮发 end_games.then；回调不读取 response.ok，body.success as bool 为 true 时提示指令下发成功、倒计时值清 0、取消 Timer、状态文字设未开始游戏。Timer 引用未置 null，不清通道识别结果或移除偏移。', [0x4aaa48,0x4aab28,0x4aac38], [0x4aabe0,0x4aabf4]),
        claim('reset_before_response', '重置先发 zhuo_reset_games.then，紧接着在响应返回前清空每个 live Channel 的 result 列表并刷新；回调需 ok && (success as bool) 才提示重新开始成功。失败不恢复清空结果，不重置移除偏移、倒计时或状态文字。', [0x4aa778,0x4aa940], [0x4aa854]),
        claim('restart_response', '设置页重启操作记录重启所有设备并调用无设备参数 restart_device。!ok 或 success==false 分别提示错误并记红日志；ok && success!=false 时先 pop 页面，再调用 Utils.showErr(重启所有设备成功)并记黑日志。并未在客户端把所有设备置离线。', [0x4af648,0x4af7f8], [0x4afa80,0x4afaac,0x4afac0]),
        claim('settings_shared_channels', 'Main 打开设置页时传入同一个 channels 列表；设置页先从 Utils.onlineConfig 填表，再 get_config.then。成功条件为 ok && success!=false，data 解析为 OnlineConfig，写回页面和 Utils.onlineConfig，再填表。', [0x4ac190,0x52afa4,0x52b020,0x52b110,0x52c324,0x52c350], [0x4ac1e8,0x52b404,0x52b468]),
        claim('settings_defaults', '方向数量表单默认每方 26；timeout 默认 60、delay 默认 5；data_send/count_type/upload_img_clarity 默认各 1。这些是客户端填表 fallback，不证明服务器默认或实际上传行为。', [0x52c350]),
        claim('number_save', '保存方位数量将四个控制器当前文本 int.parse 后构造 east/south/west/north 并 POST set_number。方法无范围/总数校验。成功时按 live Channel.device.direction=1..4，从回调时的控制器文本重新解析写 mj_count；不修改 direction，也不使用请求 Map 的数值快照。', [0x4b0db0,0x4b10a4], [0x4b1408,0x4b1494,0x4b1520,0x4b15ac]),
        claim('lighting_config_scope', 'get_config 的 OnlineConfig 会解析 lighting_config 的 switch/east/south/west/north 为 nullable bool；所审查 _initFormData 只使用 config_number/data_config，未找到该设置页将 lighting_config 提交给接口的链。不能把方位数量接口解释为升降开关。', [0x52b498,0x52bf28,0x52b9d8,0x52c350,0x4ac23c]),
        claim('data_save_local_before_http', '保存数据设置请求 data_send、timeout、delay、count_type、upload_img_clarity；在发 HTTP 前已把 timeout 写入 Utils.loginUser，失败无回滚；成功回调仅 toast，不写其他 loginUser 字段。', [0x4aff98,0x4b0318], [0x4b023c,0x4b0268]),
        claim('wifi_save_limited', '仅补充已核对保存支线：设置页 set_wifi 使用当前 SSID/密码文本；选网页先检查 SSID/密码非空再发同一接口。回调 dismiss 后 !ok/明确 success==false 报错，否则提示保存成功；没有自动重启或本地 WifiConfig 更新。扫描/标定未扩展。', [0x4afb30,0x4afd30,0x4b42d0,0x4b447c]),
        claim('preview_selection', '预览页 initState 仅将 Rx 预览图字符串清空，没有自动 start。选择方向先更新当前方向，再找 Utils.devices 中第一个匹配 direction 的设备；加载该设备参数并绘框后 startPreview(device.id)。无匹配则不请求，切换方向未先 end 前一设备。', [0x51d844,0x4575e8,0x457904,0x457b04,0x457b58,0x459e60,0x459b30]),
        claim('preview_ids_before_response', 'startPreview 在 HTTP 前写 PreviewService.currentDeviceId；其响应回调无 ok/success 判断，将 MainService.previewDeviceId 设为匹配 device.id??0 并日志记录 data。两个 deviceId 的写入时机不同。', [0x457dc4,0x45911c], [0x457dec,0x459180]),
        claim('preview_parameter_load', '框参数 left/top/right/bottom 和 13 个整数字段从匹配设备取值，其中框参数及整数使用非空断言；brightness fallback=75.0、motor fallback=3000.0。所审查方法没有捕获空值/类型错误。', [0x459b30,0x564d4c]),
        claim('preview_image_ws', '预览图由 Main 的 WS102 分支到达：content 若含 |，拆为 deviceId|编码图串，int.parse(deviceId) 等于 MainService.previewDeviceId 才 decode_data 并写 Rx；不含 | 的旧格式不按设备过滤，直接解码写 Rx。此链未调用图片 HTTP URL。', [0x527460], [0x52758c]),
        claim('preview_image_render', 'Rx 图非空时 base64Decode→decodeJpg→updateDrawImg→encodePng→Image.memory；红框 x1=left,y1=top,x2=left+right,y2=top+bottom。因此本地绘制把名为 right/bottom 的量用作宽/高，不是绝对右下坐标。', [0x463e08,0x458144]),
        claim('preview_save_buttons', '更新预览图像调用 _onSavePreview(false)，保存配置调用 _onSavePreview(true)。二者都先找第一个当前方向设备、构造 19 个参数并更新共享 Devices，然后 POST savePreviewParams；没有另一个取图 HTTP 请求。', [0x45b36c,0x462adc,0x45fc68,0x45fcb4]),
        claim('preview_save_clears_route_id', 'savePreviewParams 服务入口在 HTTP 前也把 PreviewService.currentDeviceId 清0，与 close 无关，且失败无恢复。因此更新预览图像或保存失败后再普通返回，父路由回调可能因id=0跳过endPreview；除非中间再次startPreview重写id。save(close=true)成功分支仍用捕获的设备id显式发送end。', [0x460ab4,0x460b60,0x4ac0b8], [0x460ad0]),
        claim('preview_cache_brightness', 'save 请求 brightness 使用当前 UI Double；但同方法写 Devices.field_3f 的缓存值固定为 75.0。其余框参数/电机/13整数也在 HTTP 前写入共享设备对象，失败无回滚。', [0x45fcb4], [0x45ffcc,0x460598,0x4605a0,0x4608e0]),
        claim('preview_save_close', 'save 回调需 ok && (success as bool)==true；close=false 时成功不退出；close=true 时先调用 endPreview，挂 then，立即 Navigator.pop(true)，不等待结束响应。!ok 或 success=false 静默；补充原ELF证明共享入口 0x6f2a58 仅 mov x0,x22;ret，返回 null，不读取响应或执行额外清理。来源见 connection_preview_closure/end_preview。', [0x460b60,0x461014], [0x460c4c,0x460cb8]),
        claim('preview_route_end', 'endPreview 调用之初已把 PreviewService.currentDeviceId 清0，再发POST。Main 对预览路由结束的回调若该id非0就endPreview(id)，忽略Future/响应；不读返回bool。savePreviewParams本身也先清0，故不只正常save(true)，更新图像或保存失败后普通返回也可能跳过end。不清MainService.previewDeviceId或Rx图。', [0x461014,0x4ac0b8,0x460ab4], [0x46102c,0x460ad0]),
        claim('preview_imgtype', '图像类型回调先 setState UI类型=参数??0，再遍历所有当前方向设备，逐个 POST set_preview_img_type/{id}/{参数??1}；不 await、不 then，无响应判断或错误提示。nullable 参数的 UI fallback 0 与请求 fallback 1 不同。', [0x463668,0x4636b4,0x4639cc]),
        claim('async_bounds', '所审查请求入口大多返回 void 并挂 then；轮询不串行，预览结束立即 pop，重置/参数缓存先改后请求；这些方法未见请求取消、roundId 或 mounted 防护。此结论只覆盖所列完整方法，不能推定服务端最终硬件状态或事故。', SELECTED),
    ]


POLL_FIELDS = [
    ('ip','0x6b','String?','0x52403c'), ('online','0x67','int?','0x5240e0'),
    ('delay','0x77','double?','0x524188'), ('connected_at','0x6f','String?','0x524230'),
    ('ver','0x73','String?','0x5242d8'), ('client_wifi','0x9f','String?','0x524380'),
    ('client_ip','0xa3','String?','0x524428'), ('run_time','0xa7','String?','0x5244d0'),
    ('up_time','0xab','String?','0x524578'),
]


PREVIEW_PARAMS = [
    # Request key, state field, model field, request type, local update.
    ('left','0x1b','0x53','int','original UI double'),
    ('top','0x23','0x4f','int','original UI double'),
    ('right','0x2b','0x57','int','original UI double; drawing width'),
    ('bottom','0x33','0x5b','int','original UI double; drawing height'),
    ('brightness','0x3b','0x3f','double','constant 75.0, not current UI'),
    ('motor','0x43','0x43','int','UI double.toInt()'),
    ('cap_brightness','0x4b','0x7b','int','UI int'),
    ('cap_exposure','0x53','0x7f','int','UI int'),
    ('cap_hue','0x5b','0x83','int','UI int'),
    ('cap_saturation','0x63','0x87','int','UI int'),
    ('cap_contrast','0x6b','0x8b','int','UI int'),
    ('cap_gain','0x73','0x8f','int','UI int'),
    ('img_rotation','0x7b','0x93','int','UI int'),
    ('img_min_hreshold','0x83','0x97','int','UI int; original spelling'),
    ('cap_fps','0x8b','0x9b','int','UI int'),
    ('bate','0x93','0xaf','int','UI int; model serialized key beta'),
    ('img_add_num','0x9b','0xb3','int','UI int'),
    ('gk_min','0xa3','0xb7','int','UI int'),
    ('gk_max','0xab','0xbb','int','UI int'),
]


def action(key, trigger, methods, endpoint=None, request_origin=None,
           local_before=None, business_success=None, success=None, failure=None,
           future='void entry; Future.then; not awaited'):
    return dict(id=key, trigger=trigger, method_evidence=ev(*methods),
        endpoint=endpoint, request_origin=request_origin,
        local_before_response=local_before or [], business_success=business_success,
        success_state=success or [], failure_state=failure or [], async_behavior=future)


def actions():
    return [
        action('main_init', 'Main.initState', [0x51f028], 'getMjConfigReq', 'no query/body',
            ['initialize Channel with shared Devices, lighting_switch=0', 'query device status once', 'start 5s polling', 'subscribe Rust events'],
            'data.success as bool, no response.ok check in MjConfig callback',
            ['initWs(host) with log-only catchError', 'replace Main MjConfig dictionary']),
        action('device_poll', 'immediate call + Timer.periodic 5 seconds', [0x520fe8,0x52a724,0x5210c8,0x523f84], 'deviceStatusAll', 'no query/body',
            business_success='response.ok AND (body.success as bool)==true',
            success=['serial_no matched existing Devices: replace nine nullable fields', 'offline transition plays offline_error.wav', 'refresh page'],
            failure=['false condition: no update or toast; malformed cast can throw']),
        action('main_dispose', 'Main.dispose', [0x556974],
            success=['cancel event subscription, device polling Timer and receive countdown Timer', 'delete cached images', 'Wakelock.disable'],
            future='cleanup calls not awaited; no in-flight HTTP cancellation in method'),
        action('start_games', 'Main 开始 button', [0x4aac98,0x4aaffc,0x4abf98,0x4abe28,0x4abeec], 'startGamesReq', 'no query/body; Ws login uses current JWT',
            business_success='body.success as bool == true; response.ok not checked',
            success=['showSuccess 指令下发成功 only'], failure=['success=false silent; invalid body bool can throw'],
            future='isContentWs() has no business parameters; normal bool is SDK+0x2a5 transport flag. True sends directly; false waits wsLogin.then without checking its result, then GET.then. Neither path waits for the types50 authentication response.'),
        action('end_games', 'Main 结束 button', [0x4aaa48,0x4aab28,0x4aac38], 'endGamesReq', 'no query/body',
            business_success='body.success as bool == true; response.ok not checked',
            success=['showSuccess 指令下发成功', 'receive countdown=0', 'countdown Timer.cancel without setting field null', 'status text=未开始游戏'],
            failure=['success=false silent; results retained']),
        action('reset_games', 'Main 重置 button', [0x4aa778,0x4aa940], 'resetGames', 'no query/body',
            ['clear all live Channel.result lists immediately after attaching then; refresh'],
            'response.ok AND (body.success as bool)==true', ['showSuccess 重新开始成功'],
            ['no rollback; removed offset/countdown/status retained']),
        action('restart_device', 'settings 重启设备 button', [0x4af648,0x4af7f8], 'restartDevice', 'no query/body; all-devices client UI operation',
            ['log 重启所有设备'], 'response.ok AND body.success != false (dynamic equality)',
            ['Navigator.pop', 'Utils.showErr 重启所有设备成功', 'black log; no local online reset'],
            ['!ok: error?.message??empty, showErr + red log', 'success==false: body.msg as String, showErr + red log']),
        action('settings_open_load', 'Main 设置 button → OnlineSettingPage.initState', [0x4ac190,0x52afa4,0x52b020,0x52b110,0x52c324,0x52c350], 'getConfigReq', 'no query/body; same Main channels list passed',
            ['fill form from Utils.onlineConfig with client fallbacks'],
            'response.ok AND body.success != false (dynamic equality)',
            ['parse OnlineConfig', 'write page config and Utils.onlineConfig', 'refill controllers'],
            ['dismiss; error message + red log']),
        action('save_direction_counts', 'settings 保存方位数量', [0x4b0db0,0x4b10a4], 'setNumberConfigReq',
            'east/south/west/north=int.parse(current direction controller text)',
            ['show loading; no range or sum check in entry'],
            'response.ok AND body.success != false (dynamic equality)',
            ['for shared live channels, direction1..4 maps to corresponding current controller text reparse → Devices.mj_count', 'toast 配置方位数量成功'],
            ['dismiss; error message + red log; malformed input can throw before HTTP']),
        action('save_data_config', 'settings save or reviewed radio callbacks', [0x4aff98,0x4b0318], 'setDataConfigReq',
            'data_send/count_type/upload_img_clarity from state; timeout/delay int.parse(controller)',
            ['show loading', 'write Utils.loginUser.timeout before POST'],
            'response.ok AND body.success != false (dynamic equality)', ['toast 保存成功'],
            ['dismiss + showErr; timeout write not rolled back']),
        action('save_wifi_settings', 'settings 保存 Wi-Fi', [0x4afb30,0x4afd30], 'setWifiReq', 'ssid,pwd=current controller text',
            ['show loading'], 'response.ok AND body.success != false (dynamic equality)', ['toast 保存成功'],
            ['dismiss + showErr; !ok also red log; no local WifiConfig/restart update']),
        action('save_wifi_picker', 'Wi-Fi selection page 保存', [0x4b42d0,0x4b447c], 'setWifiReq', 'ssid,pwd=current controller text',
            ['SSID empty → 请选择WIFI！; password empty → 请输入WIFI密码！; return before request', 'otherwise show loading'],
            'response.ok AND body.success != false (dynamic equality)', ['toast 保存成功'], ['dismiss + showErr']),
        action('preview_select_start', '画框 page, select 东/南/西/北', [0x51d844,0x457b58,0x459b30,0x457dc4,0x45911c], 'startPreview',
            'first Utils.devices match selected direction; path device.id (nullable)',
            ['init clears Rx image', 'set selected direction; load device params; draw frame', 'PreviewService.currentDeviceId=id before HTTP'],
            'no response.ok or body.success check', ['MainService.previewDeviceId=id??0; log body'],
            ['unmatched direction: no request; invalid nullable config can throw; old id/image not rolled back']),
        action('preview_receive_render', 'WS102 → Rx image observer', [0x527460,0x463e08,0x458144],
            request_origin='content deviceId|encoded image or legacy encoded image',
            success=['filtered/decode_data → Rx string', 'base64 → JPG → translucent red rectangle → PNG → Image.memory'],
            failure=['mismatched prefixed deviceId ignored; malformed parse/decode can throw'],
            future='WS and Rx observer; no preview-image HTTP request in chain'),
        action('preview_update', '更新预览图像', [0x462adc,0x45fcb4,0x460ab4,0x460b60], 'savePreviewParams',
            'first selected-direction device; 19-key request from current UI',
            ['write shared Devices params before POST; cached brightness fixed75.0', 'savePreviewParams clears PreviewService.currentDeviceId=0 before POST'],
            'response.ok AND (body.success as bool)==true; close=false', ['remain on page'],
            ['!ok or success=false silent; no rollback']),
        action('preview_save_close', '保存配置', [0x45fc68,0x45fcb4,0x460ab4,0x460b60,0x461014], 'savePreviewParams',
            'same 19-key request; close=true; endPreview uses selected device.id',
            ['write shared Devices params before POST', 'savePreviewParams clears PreviewService.currentDeviceId=0 before POST'],
            'response.ok AND (body.success as bool)==true', ['endPreview clears currentDeviceId then POST', 'Navigator.pop(true) immediately'],
            ['!ok or success=false silent; no rollback'], future='save.then → end.then → immediate pop; does not await end response'),
        action('preview_img_type', 'preview image-type selector', [0x463668,0x4636b4,0x4639cc], 'setPreviewImg(inlined)',
            'all devices matching selected direction; path device.id/(arg??1)',
            ['set UI image type=arg??0'], 'no response handler',
            ['local UI updated before request'], ['no specific error/toast or rollback'],
            future='discard each POST Future; no then/await'),
        action('preview_route_exit', 'frame-preview route completion; end request is conditional', [0x4ac0b8,0x461014,0x460ab4], 'endPreview',
            'if PreviewService.currentDeviceId!=0 use that id; route returned bool ignored',
            ['endPreview clears currentDeviceId before POST'], 'no response handler in route closure',
            ['id==0 skips end; prior savePreviewParams already clears it even on failure', 'no clearing MainService.previewDeviceId/Rx image'],
            future='discard endPreview Future; no await'),
    ]


def request_models():
    return dict(
        evidence_rules=['state/model offsets are class-specific', 'compressed Smi values decoded to Dart integers',
                        'request types and literal keys re-use prior directly constructed Map contract'],
        polling=dict(match='channel.device.serial_no == responseRow[serial_no]',
            fields=[dict(key=k, device_field=f, dart_type=t, store_evidence=point(a)) for k,f,t,a in POLL_FIELDS],
            body_keys=['success','data'], response_data_shape='Iterable of map-like records; no insertion/deletion'),
        devices_identity=dict(id='0x7 int?',lighting_switch='0x1f int?',status='0x47 int?',
            direction='0x4b int?;1东2南3西4北',mj_count='0x5f int?',serial_no='0x63 String?',online='0x67 int?',
            evidence=ev(0x459f08,0x4901f0)),
        main_state=dict(channels='0x1b',mj_configs='0x1f',device_poll_timer='0x23',
            page_mode='0x27 default1',audioPlayer='0x33',status_text='0x37 default未开始游戏',
            receive_countdown_timer='0x3b',receive_countdown='0x3f default0',
            display_type='0x47 default2',overlay='0x4f defaultfalse',evidence=ev(0x565264)),
        preview=dict(evidence=ev(0x459b30,0x45fcb4,0x458144), parameter_count=19,
            parameters=[dict(request_key=k,ui_state_field=s,device_field=d,dart_request_type=t,
                request_origin='current UI field; toInt for first4 and motor',local_update=u)
                for k,s,d,t,u in PREVIEW_PARAMS],
            special_keys=['img_min_hreshold retains source spelling','request bate corresponds to model beta'],
            rectangle='x1=int(left),y1=int(top),x2=int(left+right),y2=int(top+bottom)',
            current_ids=['PreviewService.currentDeviceId: start HTTP-before write, end HTTP-before zero',
                         'MainService.previewDeviceId: start callback write id??0, WS102 filter; not cleared in reviewed end path']))


PSEUDOCODE = r'''// 静态数据流重建；不是原项目源码，不能直接编译。
// Offset 和精确证据参见 lifecycle.json / evidence_manifest.json。
// HTTP logical Map 经已复核 Dio 封装编码；服务端范围与硬件效果未知。

void mainInitState() {
  enableLandscapeAndWakelock(); deleteCachedImages(); audioPlayer=AudioPlayer();
  getMjConfigReq().then((r) {
    if (r.data['success'] as bool) { // 此闭包不检查 r.ok
      final host=serverUrl.substring(7).substring(0,serverUrl.substring(7).indexOf(':8081'));
      initWs(host).catchError((e) { logDebug(e); }); // 不 await
      setState(() { mjConfigs=parseMjConfigs(r.data['list']); });
    }
  });
  for (final d in Utils.devices) {
    d.lighting_switch=0;
    channels.add(Channel(device:d, result:[], removedOffset:0)); // 同一 Devices
  }
  pollDevices();
  devicePollTimer=Timer.periodic(Duration(seconds:5), (_) { pollDevices(); });
  eventSubscription=createEventStream().listen(onRustEvent);
}

void pollDevices() {
  deviceStatusAll().then((r) {
    if (!r.ok) return;
    if (!(r.data['success'] as bool)) return;
    for (final c in channels) {
      for (final row in r.data['data'] as Iterable) {
        if (c.device.serial_no == row['serial_no']) {
          if (c.device.online==1 && row['online']==0) {
            audioPlayer.play(AssetSource('offline_error.wav')); // 不 await
          }
          setState(() {
            c.device.ip=row['ip'] as String?;
            c.device.online=row['online'] as int?;
            c.device.delay=row['delay'] as double?;
            c.device.connected_at=row['connected_at'] as String?;
            c.device.ver=row['ver'] as String?;
            c.device.client_wifi=row['client_wifi'] as String?;
            c.device.client_ip=row['client_ip'] as String?;
            c.device.run_time=row['run_time'] as String?;
            c.device.up_time=row['up_time'] as String?;
          }); // 无 break，后续同 serial_no 行继续处理
        }
      }
    }
  }); // 无 in-flight 串行门
}

void onStartGames() {
  final suffix=serverUrl.substring(7);
  suffix.substring(0,suffix.indexOf(':8081')); // 执行但丢弃返回值；异常仍会阻止后续调用
  isContentWs().then((isContentResult) { // 截取结果未传入；正常返回只读SDK连接标志，不是认证标志
    if (isContentResult) sendStartGamesReq();
    else wsLogin(Utils.JWT).then((ignoredResult) { sendStartGamesReq(); });
  });
}
void sendStartGamesReq() {
  startGamesReq().then((r) {
    if (r.data['success'] as bool) showSuccess('指令下发成功'); // 无 r.ok
  }); // 此处不清结果/改接收状态；后续 WS113/101/114 见 result_pipeline
}
void onEndGames() {
  endGamesReq().then((r) {
    if (r.data['success'] as bool) { // 无 r.ok
      showSuccess('指令下发成功'); receiveCountdown=0;
      receiveCountdownTimer?.cancel(); // 没有置 null
      setState(() { statusText='未开始游戏'; });
    }
  }); // 识别 result 保留
}
void onResetGames() {
  resetGames().then((r) {
    if (r.ok && (r.data['success'] as bool)) showSuccess('重新开始成功');
  });
  for (final c in channels) { c.result=[]; refreshMain(); } // 响应前即清空
}
void onRestartDevice() {
  logBlack('重启所有设备');
  restartDevice().then((r) {
    if (!r.ok) { showErr(r.error?.message??''); logRed(r.error?.message??''); }
    else if (r.data['success']==false) { showErr(r.data['msg'] as String); logRed(r.data['msg'] as String); }
    else { Navigator.pop(context); showErr('重启所有设备成功'); logBlack('重启所有设备成功'); }
  }); // 成功分支源码确实调用 showErr；没有本地批量置离线
}

void loadOnlineSettings() {
  fillForm(Utils.onlineConfig); // 4方默认26;timeout60;delay5;三个选项默认1
  getConfigReq().then((r) {
    dismissLoading();
    if (!r.ok) { showErr(r.error?.message??''); logRed(r.error?.message??''); }
    else if (r.data['success']==false) { showErr(r.data['msg'] as String); logRed(r.data['msg'] as String); }
    else { config=OnlineConfig.fromJson(r.data['data'] as Map<String,dynamic>);
      setState(() { Utils.onlineConfig=config; }); fillForm(config); }
  });
}
void onSaveDirectionCounts() {
  showLoading('保存方位数量');
  final data=<String,int>{'east':int.parse(east.text),'south':int.parse(south.text),
                         'west':int.parse(west.text),'north':int.parse(north.text)};
  setNumberConfigReq(data).then((r) {
    dismissLoading();
    if (!r.ok) { showErr(r.error?.message??''); logRed(r.error?.message??''); }
    else if (r.data['success']==false) { showErr(r.data['msg'] as String); logRed(r.data['msg'] as String); }
    else { for (final c in widget.channels) {
      switch(c.device.direction) {
        case 1:c.device.mj_count=int.parse(east.text);break;
        case 2:c.device.mj_count=int.parse(south.text);break;
        case 3:c.device.mj_count=int.parse(west.text);break;
        case 4:c.device.mj_count=int.parse(north.text);break;
      } // 回调时实时文本，不是 data 快照
    } toast('配置方位数量成功'); }
  });
}
void onSaveDataConfig() {
  showLoading('保存中...');
  final data=<String,int>{'data_send':dataSend,'timeout':int.parse(timeout.text),
      'delay':int.parse(delay.text),'count_type':countType,'upload_img_clarity':uploadImgClarity};
  Utils.loginUser.timeout=int.parse(timeout.text); // 请求前本地写入；失败不回滚
  setDataConfigReq(data).then(showSaveResponse);
}
void onSaveWifi({bool pickerPage=false}) {
  if (pickerPage && ssid.text.isEmpty) { showErr('请选择WIFI！');return; }
  if (pickerPage && password.text.isEmpty) { showErr('请输入WIFI密码！');return; }
  showLoading(); setWifiReq(<String,String>{'ssid':ssid.text,'pwd':password.text}).then(showSaveResponse);
}
void showSaveResponse(r) { // 三处闭包结构相同，但日志行为以 actions 表为准
  dismissLoading();
  if (!r.ok) showErr(r.error?.message??'');
  else if (r.data['success']==false) showErr(r.data['msg'] as String);
  else toast('保存成功');
}

void previewInitState() { MainService.previewImg.value=''; }
void onStartPreview(int direction) {
  setState(() { selectedDirection=direction; });
  for (final d in Utils.devices) {
    if (d.direction!=selectedDirection) continue;
    setState(() { loadPreviewParams(d); }); // 必需字段非空断言；亮度75/电机3000 fallback
    updateDrawImg();
    PreviewService.currentDeviceId=d.id; // service 发 HTTP 前
    startPreviewGet(d.id).then((r) {
      MainService.previewDeviceId=d.id??0; logData(r.data); // 不检查 ok/success
    });
    return; // 第一个设备，不先 end 前一设备
  }
}
void onWs102(String content) {
  if (content.contains('|')) {
    final parts=content.split('|');
    if (int.parse(parts[0])==MainService.previewDeviceId) {
      MainService.previewImg.value=decode_data(parts[1]);
    }
  } else { MainService.previewImg.value=decode_data(content); }
}
Widget rxPreviewImage() {
  if (MainService.previewImg.value=='') return emptySizedBox();
  image=decodeJpg(base64Decode(MainService.previewImg.value));
  updateDrawImg(); return Image.memory(encodePng(image));
}
void updateDrawImg() {
  fillRect(image, x1:left.toInt(),y1:top.toInt(),x2:(left+right).toInt(),
      y2:(top+bottom).toInt(),color:rgba(255,0,0,128)); // right=宽,bottom=高
}
void onSavePreview(bool close) {
  for (final d in Utils.devices) {
    if (d.direction!=selectedDirection) continue;
    final data=<String,dynamic>{
      'left':left.toInt(),'top':top.toInt(),'right':right.toInt(),'bottom':bottom.toInt(),
      'brightness':brightness,'motor':motor.toInt(),
      'cap_brightness':capBrightness,'cap_exposure':capExposure,'cap_hue':capHue,
      'cap_saturation':capSaturation,'cap_contrast':capContrast,'cap_gain':capGain,
      'img_rotation':imgRotation,'img_min_hreshold':imgMinHreshold,'cap_fps':capFps,
      'bate':beta,'img_add_num':imgAddNum,'gk_min':gkMin,'gk_max':gkMax};
    d.left=left; d.top=top; d.right=right;d.bottom=bottom;
    d.internalBrightness=75.0; // 实际 field_3f 固定75，不能改写为 brightness
    d.motor=motor.toInt(); writeOther13DeviceInts(d); // HTTP 前；失败不回滚
    savePreviewParams(d.id,data).then((r) {
      if (!r.ok) return;
      if (!(r.data['success'] as bool)) return;
      if (close) {
        endPreview(d.id).then((_) => null); // 共享entry0x6f2a58原ELF仅返回null
        Navigator.pop<bool>(context,true); // 不等待结束响应
      }
    });
    logData(data);return;
  }
}
void onSetPreviewImg(int? type) {
  setState(() { uiImgType=type??0; });
  for (final d in Utils.devices) {
    if (d.direction==selectedDirection) {
      post('/api/preview/set_preview_img_type/${d.id}/${type??1}'); // 丢弃Future
    }
  }
}
Future savePreviewParams(int? deviceId, Map<String,dynamic> data) {
  PreviewService.currentDeviceId=0; // 所有保存请求，成功/失败、close=false/true均在HTTP前清0
  return post('/api/preview/set_params_v2/$deviceId',data:data);
}
Future endPreview(int? deviceId) {
  PreviewService.currentDeviceId=0;
  return post('/api/preview/end_preview/$deviceId'); // 无 body
}
void onPreviewRouteFinished(dynamic ignoredReturnValue) {
  if (PreviewService.currentDeviceId!=0) endPreview(PreviewService.currentDeviceId);
}
void mainDispose() {
  popoverController.dispose();eventSubscription?.cancel();
  devicePollTimer?.cancel();receiveCountdownTimer?.cancel();
  deleteCachedImages();Wakelock.disable(); // 没有取消已发HTTP或 audioPlayer.dispose
}
'''


EXPLANATION = '''设备、牌局、预览生命周期静态还原

本轮仅阅读 Blutter 输出并还原客户端数据流，没有启动 APK、执行业务库或请求服务器。
使用既有 22 接口总表与 20 接口详细合约；本目录没有重新解释服务器业务实现。
lifecycle.json 给出操作和响应分支；request_models.json 给出字段映射；evidence_manifest.json
记录每个完整方法的来源路径、精确一基行区间、来源 SHA256 和摘录 SHA256。
reconstructed.dart 是不可编译的可读伪代码，不是原始源码。

1. 主页面与设备轮询
Main.initState 把登录设备列表建为 Channel。Channel 使用同一个 Devices 对象；其结果列表
初始为空、移除偏移为0。初始化把 lighting_switch 清0，随后立即查设备状态并每5秒重查。
设备 poll 返回 void，挂 Future.then，没有等待上一轮请求完成。仅 ok 且 success 强制 bool
为 true 才处理响应，按 serial_no 匹配现有设备，不增删通道。更新 ip、online、delay、
connected_at、ver、client_wifi、client_ip、run_time、up_time 共9字段。
旧 online=1 → 响应 online=0 才播放 offline_error.wav，音频 Future 不 await。
没匹配到的设备保留旧字段；重复 serial_no 行继续处理，最后匹配记录可再次覆盖字段。
Main.dispose 会取消轮询、事件订阅、接收倒计时，并清图片缓存、禁用 Wakelock；当前方法
不取消已发 HTTP。所述字段类型可能为空，delay 使用 double? 转型而非 num→double转换。

2. 升降标记与方位数量
WS117 写 Devices.lighting_switch=1；WS114 写0，全部关闭时结束接收倒计时并设等待下轮
文字；115写 online=0、lighting_switch=0；116写 online=1。字段0x1f由模型证明为
lighting_switch，Devices.status是0x47，两者不可混称。左侧显示该标记为“灯光”，
不是已证实的单设备控制按钮。
设置页收到同一 channels 列表；get_config 成功后解析 OnlineConfig 并写 Utils.onlineConfig。
方向数量表单 fallback 每方26；timeout=60、delay=5、data_send/count_type/upload_img_clarity
各1。保存数量把4个控制器 int.parse 成 east/south/west/north 请求，方法内没数量范围或
总数检查。成功回调按每台设备既有 direction=1/2/3/4，把相应控制器“回调时”的文本重
parse写 mj_count；没有修改设备 direction，也没有用发出请求时的 Map 快照。
lighting_config 虽解析 switch/east/south/west/north bool?，所审查设置页未构成提交开关的
完整链，不能用 set_number 推断单设备升降控制。
数据设置在 HTTP 前已写 loginUser.timeout；失败没有回滚。这不证明 loginUser.data_send
或 delay 控制上传；识别上传仍应查看 result_pipeline 的实际读取证据。
Wi-Fi 仅保留两处保存支线：选择页有非空检查，普通设置页保存方法没有；二者成功只
提示保存成功，没有客户端自动重启或 WifiConfig 更新。未扩展扫描和标定。

3. 开始、结束、重置和重启
“开始”先执行 server_url 的 substring(7)/:8081 截取，但结果未传入isContentWs()。
补充原生worker/getter证明该无业务参数API正常返回SDK+0x2a5连接flag，不读认证flag。
返回true直接发start_games；false等wsLogin本地Future完成后发，不检查返回值，也不等认证响应。
回调仅判断
data.success as bool，没有先检查 response.ok；true 提示指令下发成功，false静默，
不直接改变结果/倒计时/主状态文字。真正接收进度由WS113/101/114推进，详见result_pipeline。
“结束”也是无 response.ok 前置判断；success as bool 为true时提示、倒计时清0并取消
Timer、主状态设未开始游戏。Timer引用不置null，识别结果和移除偏移不清。
“重置”发出HTTP并挂then后，就立即清空所有live Channel.result列表。响应必须ok且
success as bool才提示重新开始成功；失败不恢复结果，不重置移除偏移/倒计时/主状态。
“重启设备”页面语义是所有设备，GET无设备id。!ok 或明确success==false报错并红日志；
ok且success!=false则pop页面，随后实际调用Utils.showErr显示重启所有设备成功并黑日志。
没有在本地批量把online置0。此类success!=false是动态比较，不能改写成success严格bool true。

4. 预览、框选和参数保存
预览页进入时只清空Rx图像，方向选中后找第一个匹配设备。加载参数、绘框，再start。
startPreview在HTTP前写PreviewService.currentDeviceId；响应回调不看ok/success，就把
MainService.previewDeviceId设为device.id??0。切换方向未在这些方法中先end旧设备。
预览图由WS102收到，不是一个另外的取图HTTP接口。带deviceId|前缀的格式需id匹配，
旧无前缀格式直接接收。decode_data后写Rx，observer执行base64→JPG→绘红框→PNG→显示。
绘框公式x2=left+right、y2=top+bottom，所以本地right/bottom作宽高；服务器解释未知。
“更新预览图像”调用save(false)；“保存配置”调用save(true)。两者请求同样19参数。
请求拼写保持img_min_hreshold和bate；模型序列化是beta。前4框参数、电机请求转int，
brightness请求是当前UI double。发HTTP前先改共享Devices缓存，失败无回滚。特别是
缓存brightness固定写75.0，即使请求brightness是其他值；其余参数按当前UI字段更新。
save回调要求ok且success as bool true。false或!ok没有专门报错提示。close=false不退出；
close=true先endPreview，挂then后立即pop(true)，不等end响应。endPreview调用即把
currentDeviceId清0。Main预览路由结束回调若id非0才发end，忽略路由返回值和end响应。
另外savePreviewParams入口同样先清currentDeviceId=0，和close标志/请求是否成功无关；
因此更新图像或保存失败后普通返回也可能跳过end，除非中间再startPreview重写id。
正常save(true)成功分支仍显式end，然后路由回调不再发第二次end。这些end链不清MainService预览id
或Rx图像；下一次预览页init才清图。共享end回调0x6f2a58原ELF仅有返回null的两条指令，
没有额外清理。跨层补证见analysis/connection_preview_closure，原asm未修改。
图像类型选择先改UI类型(arg??0)，遍历全部当前方向设备，POST id/(arg??1)，丢弃Future，
无then/await/响应提示。nullable参数的UI和请求fallback不同。

5. 错误、异步和边界
开始/结束/字典/轮询/save的bool转换和部分模型非空断言可抛异常；这些方法没有局部catch。
重置/参数缓存先改后请求；5秒轮询不串行；预览结束不等待服务器。所列完整方法未见
in-flight、请求取消、roundId、mounted保护；只报告这一有限静态观察，不推定实际事故。
HTTP封装可产生失败HttpResponse，但上层是否检查ok以各回调为准；服务端是否接受
success缺失、设备真实行为、状态返回值、允许范围与精确服务端顺序都未经验证。

重建与校验：
python3 APP/scripts/device_lifecycle_extract.py
python3 APP/scripts/device_lifecycle_extract.py --verify
脚本只读原始asm及既有HTTP合约，生成本目录。--verify逐一检查来源SHA、原始行片段、
方法摘录SHA、结论/操作所指方法、精确指令行，以及引用合约SHA；不运行任何业务代码。
'''


ENDPOINT_NAMES = {'getMjConfigReq','deviceStatusAll','startGamesReq','endGamesReq','resetGames',
    'restartDevice','getConfigReq','setNumberConfigReq','setDataConfigReq','setWifiReq',
    'startPreview','savePreviewParams','endPreview','setPreviewImg'}


def run():
    index_methods()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'evidence').mkdir(exist_ok=True)
    manifest=[]
    for address in ev(*SELECTED):
        source=METHODS[address]
        body=source['body'].encode()
        path=OUT / 'evidence' / (address[2:]+'.asm.txt')
        path.write_bytes(body)
        manifest.append({k:v for k,v in source.items() if k!='body'} |
            dict(snippet=str(path),snippet_sha256=sha(body)))
    contract_path=APP / 'analysis/http_contract/endpoint_contracts.json'
    contracts=json.loads(contract_path.read_text())
    filtered=[e for e in contracts['endpoints'] if e['method'] in ENDPOINT_NAMES]
    found={e['method'] for e in filtered}
    # The inlined image-type method uses its original endpoint entry's method name.
    if 'setPreviewImg' not in found:
        images=[e for e in contracts['endpoints'] if '/set_preview_img_type/' in e['path_template']]
        assert len(images)==1, images
        filtered += images
    assert len(filtered)==14, [(e['method'],e['path_template']) for e in filtered]
    cs, acts=claims(),actions()
    provenance=dict(artifact_kind='manual client data-flow reconstruction with original full method evidence',
        generator=dict(path=str(Path(__file__).resolve()),sha256=sha(Path(__file__).read_bytes())),
        source_dump=str(ASM.parent), static_only=True,
        contract_reference=dict(path=str(contract_path),sha256=sha(contract_path.read_bytes()),
            selected_endpoint_templates=[dict(method=e['method'],address=e['address'],http_method=e['http_method'],
                path_template=e['path_template']) for e in filtered]),
        evidence_manifest=str(OUT/'evidence_manifest.json'),
        constraints=['no APK or business-native execution','no business network requests',
                     'no edits to source dump, original APK, root report or result_pipeline'],
        limitations=['server response examples not available; hardware effects not executed',
            'isContentWs native predicate and shared callback raw body are supplemented in connection_preview_closure',
            'Wi-Fi scanning and calibration not extended',
            'annotations and pseudocode are not original source',
            'no claimed raw ELF disassembly verification for this new bundle'])
    write_json('evidence_manifest.json',dict(snippet_count=len(manifest),methods=manifest))
    write_json('lifecycle.json',dict(provenance=provenance,
        counts=dict(endpoint_templates=len(filtered),actions=len(acts),claims=len(cs),
            full_method_snippets=len(manifest),poll_updated_fields=9,preview_parameters=19),
        claims=cs,actions=acts))
    write_json('request_models.json',request_models())
    (OUT/'reconstructed.dart').write_text(PSEUDOCODE)
    (OUT/'设备牌局预览生命周期说明.txt').write_text(EXPLANATION)
    verify()


def verify():
    manifest=json.loads((OUT/'evidence_manifest.json').read_text())['methods']
    errors=[]
    for m in manifest:
        raw=Path(m['source']).read_bytes()
        lines=raw.decode().splitlines(keepends=True)
        extracted=''.join(lines[m['start_line']-1:m['end_line']]).encode()
        snippet=Path(m['snippet']).read_bytes()
        if sha(raw)!=m['source_sha256']: errors.append([m['address'],'source_sha256'])
        if extracted!=snippet: errors.append([m['address'],'source_slice'])
        if sha(snippet)!=m['snippet_sha256']: errors.append([m['address'],'snippet_sha256'])
    doc=json.loads((OUT/'lifecycle.json').read_text())
    addresses={m['address'] for m in manifest}
    for item in doc['claims']+doc['actions']:
        for a in item['method_evidence']:
            if a not in addresses: errors.append([item['id'],'missing_method',a])
        for p in item.get('instruction_evidence',[]):
            raw=Path(p['source']).read_bytes()
            if sha(raw)!=p['source_sha256'] or raw.decode().splitlines()[p['line']-1].strip()!=p['text']:
                errors.append([item['id'],'instruction_line',p['address']])
    models=json.loads((OUT/'request_models.json').read_text())
    for field in models['polling']['fields']:
        p=field['store_evidence']
        raw=Path(p['source']).read_bytes()
        if sha(raw)!=p['source_sha256'] or raw.decode().splitlines()[p['line']-1].strip()!=p['text']:
            errors.append(['polling_model','instruction_line',p['address']])
    ref=doc['provenance']['contract_reference']
    if sha(Path(ref['path']).read_bytes())!=ref['sha256']: errors.append(['contract','source_sha256'])
    generator=doc['provenance']['generator']
    if sha(Path(generator['path']).read_bytes())!=generator['sha256']: errors.append(['generator','source_sha256'])
    record=dict(status='PASS' if not errors else 'FAIL',errors=errors,
        checks=['source file SHA256','inclusive original line slice equals complete snippet',
                'snippet SHA256','method reference coverage','claim and model instruction line/source SHA256',
                'prior HTTP contract SHA256','generator SHA256'],
        counts=doc['counts'],business_execution=False,network_requests=False)
    write_json('verification.json',record)
    print(json.dumps(record,ensure_ascii=False,indent=2))
    assert not errors, errors


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify',action='store_true',help='verify existing artifact evidence only')
    args=parser.parse_args()
    if args.verify: verify()
    else: run()
