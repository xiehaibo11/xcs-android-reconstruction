#!/usr/bin/env python3
"""Reproduce the reviewed static Dart result pipeline and evidence bundle.

This script reads Blutter comment assembly only. Annotations are manual data-flow
reconstruction, not recovered source. It does not import, load or execute APK code.
"""

from _paths import app_root, workspace_root
from pathlib import Path
import argparse
import hashlib
import json
import re

APP = app_root()
ASM = APP / 'analysis/aot_dump/asm'
OUT = APP / 'analysis/result_pipeline'
METHODS = {}
SOURCES = {}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def index_methods():
    for p in sorted((ASM / 'distinguish').rglob('*.dart')):
        raw = p.read_bytes()
        lines = raw.decode().splitlines(keepends=True)
        SOURCES[p] = lines
        for i, line in enumerate(lines):
            m = re.search(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)', line)
            if not m:
                continue
            end = i + 1
            while end < len(lines) and lines[end].rstrip() != '  }':
                end += 1
            assert end < len(lines), (p, i)
            addr = m[1]
            assert addr not in METHODS, addr
            METHODS[addr] = dict(address=addr, size=m[2], source=str(p),
                source_relative=str(p.relative_to(APP)), start_line=i,
                end_line=end + 1, declaration=lines[i-1].strip(),
                body=''.join(lines[i-1:end+1]), source_sha256=sha(raw))


def ev(*addresses):
    return [a if isinstance(a, str) else hex(a) for a in addresses]


def point(address):
    address = address if isinstance(address, str) else hex(address)
    matches = []
    for p, lines in SOURCES.items():
        for i, line in enumerate(lines):
            if re.match(r'    // ' + address + r':', line):
                matches.append(dict(address=address, source=str(p), line=i+1,
                    text=line.strip(), source_sha256=sha(p.read_bytes())))
    assert len(matches) == 1, (address, matches)
    return matches[0]


def claim(key, text, evidence, points=(), certainty='confirmed_static'):
    return dict(id=key, conclusion=text, certainty=certainty,
        method_evidence=ev(*evidence), instruction_evidence=[point(a) for a in points])


SELECTED = [
    0x4a2054,0x4a2164,0x4a26cc,0x4a2d48,0x4a2ea8,0x4a32b0,
    0x4a33cc,0x4a344c,0x4a35c0,0x4a36f8,0x4a375c,0x4a3888,
    0x4a485c,0x4a50b4,0x4a566c,0x4a56d4,0x4a572c,0x4a6458,
    0x4a65ec,0x4a6744,0x4a67dc,0x4a6afc,0x4a712c,0x4a75b4,
    0x4a7750,0x4a77b0,0x4aa6b8,0x4aa71c,0x4aa778,0x4aa940,
    0x51f028,0x527460,0x5281d8,0x529164,0x5298c8,0x529aac,
    0x529c50,0x529c80,0x529d68,0x52a3d0,0x52a474,0x52a52c,
    0x52a6d4,0x52a6fc,0x52a724,0x52a76c,0x52af04,0x556974,
    0x565264,0x4b6ecc,0x576020,0x52d108,0x4bc064,0x4bc338,
    0x4bc60c,0x4bc8e0,0x4bcbb4,0x4b9594,0x4b90e4,
    0x4b6b2c,0x4b6be8,0x4b6cf0,0x4b68d4,0x4b69fc,0x4b6aa8,
    0x4c0658,0x4c081c,0x4c08c8,0x4c095c,0x4bdef4,0x4bdfd8,
    0x4be59c,0x4bda40,0x4bf970,0x459f08,0x4901f0,0x491ce4,
    0x4920e8,0x52a198,0x529e50,0x4a25ac,0x42cc54,0x528820,
]


def extract_palette():
    """Follow literal-array stores; decode compressed Smi integers (value >> 1)."""
    method = METHODS['0x52d108']
    semantic = []
    for line in method['body'].splitlines():
        m = re.match(r'    // (0x[0-9a-f]+): (.*)', line)
        if m:
            semantic.append((m[1], m[2]))
    entries = []
    for i, (addr, instruction) in enumerate(semantic):
        if instruction != 'r16 = "number"':
            continue
        segment = []
        for a, s in semantic[i:]:
            segment.append((a,s))
            if s == 'r0 = Map._fromLiteral()':
                break
        assert segment[-1][1] == 'r0 = Map._fromLiteral()'
        values = []
        for a, s in segment:
            m = re.fullmatch(r'r16 = (".*"|-?\d+)', s)
            if m:
                val = json.loads(m[1])
                values.append((a, val))
        assert [v[1] for v in values[::2]] == ['number','name','id','url'], values
        number, name, ident, url = [v[1] for v in values[1::2]]
        assert number % 2 == 0 and ident % 2 == 0
        entries.append(dict(number=number//2, id=ident//2, name=name, url=url,
            evidence_begin=point(addr), evidence_end=point(segment[-1][0]),
            smi_encoding='literal register integers are compressed Smi, decoded by >>1'))
    assert len(entries) == 42, len(entries)
    assert all(e['id'] == e['number'] for e in entries)
    assert [e['number'] for e in entries] == list(range(1,10))+list(range(11,20))+list(range(21,30))+list(range(31,38))+list(range(41,49))
    return dict(source='ContentRightSide.initState local literal palette',
        method_evidence=ev(0x52d108), count=len(entries), entries=entries)


def static_reads():
    hits = []
    for p, lines in SOURCES.items():
        for i, line in enumerate(lines):
            if 'StaticField(0xba8)' in line:
                context = ''.join(lines[i:i+34])
                hits.append(dict(source=str(p), line=i+1, context=context,
                    source_sha256=sha(p.read_bytes())))
    return dict(scope='all asm/distinguish/**/*.dart', slot='0xba8 Utils.loginUser',
        user_field_mapping=dict(data_send='0x1f',timeout='0x23',delay='0x27'),
        mapping_evidence=ev(0x491ce4,0x4920e8), reads=hits,
        conclusion='Main 的两处读取用户名 field_b；113 读取 timeout field_23；online_setting_page 更新 timeout。所审查结果流程未读取 data_send 或 delay，不能据字段名推定它们控制上传/修改界面/5秒等待。')


def pipeline_claims():
    return [
        claim('dispatch_101','FRB WsEvent.type=4 的 JSON Message.msg_type=101 调用 saveImg 后挂 then；监听回调不 await。', [0x527460,0x5281d8], [0x5274fc,0x527558,0x527584]),
        claim('start_113','113 在 countdown>0 时忽略；否则清空每通道结果，countdown=loginUser.timeout??60，启动固定1秒周期 Timer。', [0x527460,0x52a3d0,0x52a474], [0x527d08,0x527db8,0x527e34,0x527e44,0x527ea8,0x527ed4]),
        claim('countdown_expiry','Timer 每次减1并刷新数据接收中...(N秒)，<=0只取消 Timer；没有在此回调校验、上传、播放错误音或重新识别。', [0x52a3d0,0x52a474], [0x52a408,0x52a43c,0x52a458]),
        claim('finish_114','114 按 serial_no==msg_content.toString() 清 lighting_switch=0；所有通道 lighting_switch!=1 时完成接收，清 Timer/countdown，并安排固定5秒 Future.delayed。Devices.status 是另一个 field_47。', [0x527460,0x459f08,0x4901f0,0x52a6d4], [0x527c00,0x527c28,0x527c30,0x45a068,0x45a074,0x45a230,0x45a23c,0x527cbc,0x527cc0,0x527ccc,0x527cfc]),
        claim('delayed_sound','5秒后按当前 channels 计算 sum(results.length) 与 sum(mj_count??0)，仅 actual<expected 时 play(number_error.wav)，不 await 音频，不提交、不发起重新识别。', [0x52a52c], [0x52a658,0x52a68c,0x52a6a0]),
        claim('lift_117','117 用 msg_content.toString().split("|") 第0项匹配 serial_no，将 lighting_switch 设为1并更新升降牌打开文案。', [0x527460,0x52a6fc,0x459f08], [0x5276f8]),
        claim('pair_swap','mahjong_number 空值为0；静态 bool slot 0xbc4 为 true 时交换相邻编号：偶数n→n-1，奇数n→n+1。这里的未命名 flag 不等于 User.data_send。', [0x5281d8], [0x5282ac,0x5282b8,0x5282bc]),
        claim('placeholder','img=="x" 直接建空结果、empty.jpg 展示/上传图并 append 到首次匹配通道；不下载、不应用删除偏移、不运行后续正常图汇总判定。', [0x5281d8,0x529d68], [0x52848c,0x5284c0,0x5284c8]),
        claim('image_async','正常图 saveImg 只 await getTemporaryDirectory；HttpClient.get(getImgUrl(img)).then 注册后立即 ReturnAsyncNotFuture，未 await 图片 HTTP 完成。', [0x5281d8,0x528820], [0x5287a8,0x5287d4,0x5287dc]),
        claim('image_response','图片 then 回调没有 HttpResponse.ok 条件；data cast String→decode_data→Base64.decode→同步写入缓存，失败响应也可能在此抛类型/解码/IO异常。', [0x529164]),
        claim('ai_mapping','ai_val!=-1 时按远端 MjConfig.number.toString()==ai_val.toString() 查找；找到才写 result、resultImg、精度(??0.0)，未找到保持空结果。null ai_val 不等于-1但查找"null"不会匹配合法整数字典。', [0x529164,0x5298c8,0x529aac,0x4a35c0]),
        claim('image_append','正常图处理首次匹配 serial_no 的通道；匹配分支要求 direction 非null。编号为1时重置 channel 删除偏移，随后编号减偏移，setState append。未见按编号排序或去重。', [0x529164,0x529c80,0x51f028]),
        claim('auto_submit','正常图回调 count(result!="") 恰好等于 sum(mj_count??0) 时，取消 Timer/countdown归0→等待数据发送中...→onOpenChangePage(mode=2)→立即 onValidDataAndSendData；没有非零总数保护。', [0x529164,0x529c50,0x4aa6b8,0x4aa71c,0x4a2164], [0x5297a8,0x5297d0,0x529814,0x529824]),
        claim('validate_channel','onValidData 逐结果 int.parse 计频率/总条数；每通道 results.length 必须等于原始 nullable Devices.mj_count，null与0不同。方向1/2/3/4仅用于东/南/西/北错误文案，未检查方向唯一性或范围。', [0x4a26cc,0x459f08]),
        claim('validate_four','已出现的整数牌值<40 且出现次数>0 时，次数必须恰好4；没有最低牌值判断，没有遍历缺失牌，没有使用 MjConfig.count。>=40不受此频率规则。', [0x4a26cc,0x4a2d48,0x4a35c0], [0x4a2d80,0x4a2d98,0x4a2da0]),
        claim('validate_total','expected=sum(mj_count??0)，actual=全部结果条数；expected!=actual 且 expected!=0 时添加总数错误。没有空 channels 防护，空 channels 可返回true。', [0x4a26cc], [0x4a2b90,0x4a2b98]),
        claim('validate_errors','各错误只进入局部 List<String>；onValidData 按列表是否为空返回bool，未调用显示错误、音频或重识别。int.parse异常会抛出，不折算false。', [0x4a26cc,0x4a2d48], [0x4a2cbc,0x4a2cc0,0x4a2cd0]),
        claim('send_gate','onValidDataAndSendData 是同步 void：先 onValidData，false立即返回；true后显示保存中...、创建数组，addReq.then，然后立即返回。', [0x4a2164,0x4a25ac]),
        claim('send_payload','按 channel→results 当前列表顺序，每项4字段 mahjong_number(int)、serial_number(num.tryParse(serial_no??"0"))、direction(int?)、result(int.parse)。serial_number parse为null主动Throw FormatException。', [0x4a2164,0x4a25ac]),
        claim('post_failure','then先dismiss；HttpResponse.ok=false显示exception.message??""；ok=true且data["success"]==false显示data["msg"] as String。两种失败保留当前结果/页模式，没有自动重试。', [0x4a2ea8], [0x4a2ed8,0x4a2ef4,0x4a2f60,0x4a2f94,0x4a2fac,0x4a3044]),
        claim('post_success','ok=true且success不等于false时，显示发送成功；遍历当前live channels，mode=1、每通道结果=new empty List，displayType=2时flag=true才置false。没有在这里重置已选指针、删除偏移、接收Timer或状态文字。', [0x4a2ea8,0x4a32b0], [0x4a3050,0x4a3068,0x4a32ec,0x4a3310,0x4a333c,0x4a3354]),
        claim('manual_right','Main.onSelectMj 将选中 config.id.toString() 写 result、config.url 写结果图；这个右侧选择器使用本地42牌 palette，全部 literal id==number。没有立刻调用提交。', [0x4a33cc,0x4a344c,0x52d108,0x4bc064]),
        claim('manual_left','左侧 changeMj 使用 config.number：已有卡替换 result/resultImg，空卡则 append 新 ChannelResult(number.toString(), url, supplied序号, uploadImg=url)。不自动提交、不排序/去重。', [0x4b6b2c,0x4b6be8,0x4b6cf0]),
        claim('palette_counts','Popover 的 MjChangeItem.count 是按当前全部 results 与 config.number 字符串相等汇总出来的实际次数；不是 MjConfig 可配置count。popover数值>0 && !=4使用警示色，包含花牌；不等同上传的<40规则。', [0x4bdfd8,0x4be59c,0x4bda40,0x4a35c0]),
        claim('review_counts','Main.buildChange 用 num.tryParse 匹配同牌值，空解析主动FormatException；非空且code<50时以条数0/1..3/4/>4显示不同状态(0/1/0/2)，code>=50为0。这套展示规则和上传<40规则不同。', [0x4a485c], [0x4a4afc,0x4a4b1c,0x4a4b28,0x4a4b30,0x4a4b38,0x4a4b40,0x4a4b48]),
        claim('manual_send','右侧发送数据按钮的回调直接 onValidDataAndSendData；人工改牌不隐含网络确认，必须按同一完整校验进入请求。', [0x4b9594,0x4b90e4,0x4a2054,0x4a2164]),
        claim('delete_main','Main 删除先弹确认框；确认按通道和 mahjongNumber 调 removeChannelMjLogic，取消仅关闭对话框。核心删除所有相等编号条目，较大编号减1，替换列表，删除偏移再+1；即使没有匹配条目也增加偏移。', [0x4a712c,0x4a75b4,0x4a7750,0x4a77b0,0x4a6744,0x4a67dc,0x4a6afc], [0x4a6964,0x4a6974,0x4a6980,0x4a6ac4]),
        claim('delete_left','左侧组件自己的 removeMj 用 where(result.mahjongNumber!=selected序号) 替换列表；该方法没有改其它编号或 Main 删除偏移。不能和 Main 的确认删除算法合并。', [0x4b68d4,0x4b69fc,0x4b6aa8]),
        claim('ack_hidden','该牌无错误菜单包在 Visibility(false) 下；保留的回调仅将 ChannelResult.waring=false，没有校验/提交。', [0x4c0658,0x4c08c8,0x4c095c], [0x4c074c,0x4c099c]),
        claim('reset','onResetGames 启动 resetGames().then 后立即清空所有通道结果；清空不等待请求成功。response成功才显示重新开始成功，没有证据把它叫单张AI重新识别。', [0x4aa778,0x4aa940], [0x4aa79c,0x4aa7c8,0x4aa854]),
        claim('recognition_ui','智能识别数据列表基于 ChannelResult.shiBie；本轮范围没恢复可调用的再次识别网络链，某行构建回调含 Dart TFA 移除代码 Throw，不能据UI文字推定后台重识别能力。', [0x4bf970,0x4b6ecc]),
        claim('dispose','dispose取消streamsubscription、5秒设备轮询Timer、接收countdownTimer，清图片缓存/禁用wakelock；未见保存或取消5秒Future.delayed及图片HTTP then。', [0x556974]),
        claim('async_scope','上述 Timer/5秒delay/图片 then/upload then 在审查方法中没有 roundId/批次版本校验，也未见提交inflight标志、await链或catchError/finally；这是有限范围静态观察，不是已发生故障证明。', [0x527460,0x5281d8,0x529164,0x4a2164,0x4a2ea8,0x556974], certainty='bounded_static_observation'),
    ]


def models():
    result_fields = [
        ('result','0x7','String','constructor argument; AI value.toString/manual code'),
        ('resultJD','0xb','double','0.0; matched AI precision??0.0'),
        ('resultImg','0x13','String','constructor argument; default empty.jpg in incoming 101'),
        ('result180','0x17','String','""'),('result180JD','0x1b','double','0.0'),
        ('result180Img','0x23','String','""'),('mahjongNumber','0x27','int','constructor argument; adjusted sequence'),
        ('uploadImg','0x2f','String','constructor argument; normal incoming image cache path'),
        ('select','0x33','bool','false'),('waring','0x37','bool','false; exact toString spelling'),
        ('shiBie','0x3b','List<ShiBie>','[]'),
        ('channelIndex (semantic alias)','0x3f','int','-1; Main.buildChange assigns channel index'),
    ]
    return dict(
        upload=dict(method='POST',endpoint='/api/zhuo/add',service_address='0x4a25ac',
            source_address='0x4a2164',body_kind='top-level JSON array',
            field_order=['mahjong_number','serial_number','direction','result'],
            item_fields={
                'mahjong_number':dict(type='int',source='ChannelResult.mahjongNumber'),
                'serial_number':dict(type='num (int or double)',source='num.tryParse(Devices.serial_no??"0")',
                    failure='null parse -> explicit FormatException; does not normalize to int'),
                'direction':dict(type='int?',source='Devices.direction',validation='no direction range/unique validation'),
                'result':dict(type='int',source='int.parse(ChannelResult.result)',failure='FormatException propagates'),
            },not_uploaded=['images','uploadImg','resultJD','ai_precision','shiBie','roundId'],
            order='channel list order, then channel.results append order',
            evidence=ev(0x4a2164,0x4a25ac),
            transport_reference=str(APP/'analysis/http_contract/endpoint_contracts.json')),
        mj_config=dict(fields=[dict(name=n,offset=o,type=t) for n,o,t in [
            ('number','0x7','int'),('name','0xf','String'),('url','0x13','String'),('id','0x17','int')]],
            count_field=False,evidence=ev(0x4a35c0,0x52a76c)),
        channel_result=dict(fields=[dict(name=n,offset=o,type=t,default_or_source=d) for n,o,t,d in result_fields],
            evidence=ev(0x4b6ecc,0x576020,0x4a485c)),
        channel=dict(fields={'0x7':'Devices','0xb':'int semantic removed-card offset','0x13':'List<ChannelResult>'},
            offset_default=0,evidence=ev(0x51f028,0x4a67dc,0x529164)),
        main_state=dict(alias_note='following names are semantic aliases unless symbols expose them',
            fields={'0x1b':'channels','0x1f':'remoteMjConfigs','0x23':'devicePollingTimer',
                '0x27':'unboxed int pageMode, default1, open2, success1',
                '0x2f':'selectedResult nullable','0x33':'audioPlayer (actual late-field symbol)',
                '0x37':'statusText','0x3b':'countdownTimer nullable','0x3f':'unboxed countdown integer',
                '0x47':'unboxed displayType default2','0x4f':'bool selectedOverlay flag'},
            close_page_transition='mode = mode==1 ? 0 : 1',
            evidence=ev(0x565264,0x4aa71c,0x4a375c,0x4a32b0)),
        devices=dict(confirmed_offsets={'0x1f':'lighting_switch','0x47':'status','0x4b':'direction',
            '0x5f':'mj_count','0x63':'serial_no'},evidence=ev(0x459f08,0x4901f0)),
        statistic_counts=dict(expected='sum(Devices.mj_count??0)',auto_ready='count(all result!="")',
            delayed_finish='sum(all results.length)',validation_histogram='count int.parse(result)',
            popover='MjChangeItem.count derived by result==config.number.toString()'),
    )


ERRORS = [
    dict(stage='101 dispatch',condition='JSON/type/model field malformed',behavior='jsonDecode/as Map/factory cast may throw; listener has no local recovery'),
    dict(stage='saveImg preparation',condition='temp directory/cache create/file path failure',behavior='async Future error; outer then has no onError'),
    dict(stage='image then',condition='HttpResponse.data not String or decrypt/base64/write failure',behavior='throw from callback; no ok gate/catchError/finally, no error toast in this function'),
    dict(stage='normal image append',condition='matched device.direction null',behavior='NullCastError before append'),
    dict(stage='onValidData',condition='blank/non-integer result',behavior='int.parse throws before EasyLoading.show; validation does not return false'),
    dict(stage='onValidData',condition='channel/frequency/total rule violation',behavior='local error strings, return false; no POST/no toast/no audio here'),
    dict(stage='payload build',condition='serial_no cannot num.tryParse',behavior='explicit FormatException after loading is shown; function contains no dismissal for this path'),
    dict(stage='POST then',condition='ok=false',behavior='dismiss then showErr(exception?.message??""); results retained'),
    dict(stage='POST then',condition='ok=true && success==false',behavior='dismiss then showErr(msg as String); results retained; non-string msg cast throws'),
    dict(stage='POST Future',condition='future completes with error instead of HttpResponse',behavior='then success callback does not run; no local catchError/finally here'),
    dict(stage='POST success callback',condition='ok=true && success!=false',behavior='dismiss, toast, clear current channels; malformed response access/context/lifecycle may still throw'),
    dict(stage='5-second 114 check',condition='current total results less than expected',behavior='play number_error.wav; no upload/re-recognition call; audio Future unawaited'),
]


def report(claims, palette, reads):
    lines = [
        '识别结果校验、人工修改与上传完整静态数据流',
        '对象：arm64 Flutter Dart AOT，分析仅读取 Blutter 汇编。没有运行 APK/业务库，没有请求服务器。',
        '本文件与 reconstructed_pipeline.dart 是人工重建，不是原 Dart 源码。方法证据、原始行号与 SHA-256 见 evidence_manifest.json。',
        '',
    ]
    for c in claims:
        refs=[]
        for a in c['method_evidence']:
            m=METHODS[a]
            refs.append(f"{a} {m['source_relative']}:{m['start_line']}-{m['end_line']}")
        lines.extend([c['id']+' ['+c['certainty']+']', c['conclusion'], '证据：'+'；'.join(refs), ''])
    lines.extend([
        '数量和牌字典结论：',
        'MjConfig 只有 number/name/url/id；设备 mj_count 是通道期望张数；popover MjChangeItem.count 是现有结果频次。三个含义不能混用。',
        '右侧本地 palette '+str(palette['count'])+' 项：1..9、11..19、21..29、31..37、41..48，已逐项跟踪 literal map store，所有 id==number。远端牌字典的 id/number 是否总相等仍未知。',
        'data_send 与 delay：'+reads['conclusion'],
        '',
        '完整错误路径：',
    ])
    for e in ERRORS:
        lines.append(f"{e['stage']}：{e['condition']} → {e['behavior']}")
    lines.extend([
        '', '异步边界（只报告代码可观察到的范围）：',
        'saveImg 的 Future 完成不表示图片下载完成。不同101的 GET 可同时在途，append 顺序取决于回调完成，113清结果与114的5秒检查不等待这些GET。',
        '5秒 Future.delayed 没有保存在可取消状态字段中，回调读取运行时当下的 channels。上传成功也读取当前 channels 清理，未捕获所发数组对应的批次。',
        '所列方法没有 roundId/epoch、提交 in-flight 标志、显式重试或 catchError/finally；dispose 取消已有Timer/订阅，却未保存取消这些 delayed/HTTP then 的句柄。',
        '这些是静态观察；没有实机确认回调竞态、重复提交、异常日志、服务器去重/确认或跨轮影响。',
        '', '成功判定：',
        '客户端首先检查公共包装 HttpResponse.ok（包装器依据 HTTP 2xx）。随后业务判断是 data["success"]==false 的错误分支，而非 success==true 的严格成功分支；普通JSON map缺失/null/非false值会走发送成功。',
        'payload是四字段JSON数组；serial_number使用num.tryParse而非int.parse，允许解析为double，空 serial_no用字符串0。direction在构造数组处仍允许null。',
        '', '复现：',
        'python3 APP/scripts/result_pipeline_extract.py',
        'python3 APP/scripts/result_pipeline_extract.py --verify-only',
        '脚本为手工标注的确定性导出，执行静态证据截取/哈希校验及本地literal map解析，不执行目标业务。',
    ])
    return '\n'.join(lines)+'\n'


PSEUDO = r'''// 人工静态重建 Dart 伪代码；不可直接作为完整应用运行。
// 原状态字段语义别名与方法地址见 payload_models.json / evidence_manifest.json。
// 图像 decrypt 函数以已有登录配置方案为准；未包含实际服务器/密钥。

void onWsMessage(Message message) { // 0x527460
  switch (message.msg_type) {
    case 101:
      // 没有await；saveImg也没有await自身的GET。
      saveImg(MessageUpImg.fromJson(message.msg_content)).then(sharedCompletion);
      break;
    case 113:
      if (countdown > 0) return;
      for (final channel in channels) setState(() => channel.results = []);
      countdown = Utils.loginUser.timeout ?? 60;
      setState(() => statusText = '数据接收中...(${countdown}秒)');
      countdownTimer = Timer.periodic(Duration(seconds: 1), (_) { // 52a3d0
        countdown--;
        setState(() => statusText = '数据接收中...(${countdown}秒)');
        if (countdown <= 0) countdownTimer?.cancel();
      });
      break;
    case 114:
      var allClosed = true;
      for (final channel in channels) {
        if (channel.device.serial_no == message.msg_content.toString()) {
          channel.device.lighting_switch = 0; // Devices.field_1f, NOT status
          markNeedsBuild();
        }
        if (channel.device.lighting_switch == 1) allClosed = false;
      }
      if (allClosed) {
        setState(() => statusText = '接受完成，等待下轮数据...');
        countdownTimer?.cancel(); countdownTimer = null; countdown = 0;
        // Future未保存/未await；读取5秒后的当前状态。
        Future.delayed(Duration(seconds: 5), () { // 52a52c
          final expected = channels.fold(0, (n,c) => n+(c.device.mj_count??0));
          final actual = channels.fold(0, (n,c) => n+c.results.length);
          if (actual < expected) audioPlayer.play(AssetSource('number_error.wav'));
        });
      }
      break;
    // 117: serial_no匹配split('|')[0]，lighting_switch=1。
    // 其它分支见原协议分析。
  }
}

Future<void> saveImg(MessageUpImg msg) async { // 0x5281d8
  var n = msg.mahjong_number ?? 0;
  if (boolStaticSlot0xbc4) n = n.isEven ? n-1 : n+1;
  final img = msg.img ?? '';
  if (img == 'x') {
    final r = ChannelResult('', 'images/other/empty.jpg', n,
        'images/other/empty.jpg');
    for (final c in channels) {
      if (c.device.serial_no == msg.serial_number) {
        setState(() => c.results.add(r)); break;
      }
    }
    return; // 没有ready汇总或删除偏移调整。
  }
  final dir = await getTemporaryDirectory();
  final file = createCacheFile(dir, randomizedDateTimeFilename());
  HttpClient.instance.get(getImgUrl(img)).then((response) { // 0x529164
    // 无response.ok判断。
    final bytes = base64.decode(decode_data(response.data as String));
    file.writeAsBytesSync(bytes);
    final r = ChannelResult('', 'images/other/empty.jpg', n, file.path);
    if (msg.ai_val != -1) {
      final config = getMjConfig(msg.ai_val.toString()); // number.toString匹配
      if (config != null) {
        r.result = msg.ai_val.toString(); r.resultImg = config.url;
        msg.ai_precision ??= 0.0; r.resultJD = msg.ai_precision!;
      }
    }
    for (final c in channels) {
      if (c.device.serial_no == msg.serial_number) {
        requireNonNull(c.device.direction); // 汇编matched分支确有null错误出口。
        if (r.mahjongNumber == 1) c.removedOffset = 0;
        r.mahjongNumber -= c.removedOffset;
        setState(() => c.results.add(r));
        break; // 首次匹配即转入汇总。
      }
    }
    final expected = channels.fold(0, (n,c) => n+(c.device.mj_count??0));
    final ready = channels.expand((c)=>c.results).where((r)=>r.result!='').length;
    if (ready == expected) { // 没有expected>0判断。
      countdownTimer?.cancel(); countdown = 0;
      setState(() => statusText='等待数据发送中...');
      onOpenChangePage(); // 0x4aa6b8: setState pageMode=2
      onValidDataAndSendData(); // 立即调用，没有delay/data_send控制。
    }
  }); // 不await，不return这个then Future，无catchError。
}

bool onValidData() { // 0x4a26cc
  final errors = <String>[]; final counts = <int,int>{};
  var actual=0, expected=0;
  for (final c in channels) {
    for (final r in c.results) {
      final value=int.parse(r.result); // 空串会抛，不会跳过。
      counts[value]=(counts[value]??0)+1; actual++;
    }
    expected+=c.device.mj_count??0;
    if (c.device.mj_count != c.results.length) {
      errors.add('错误：${directionLabel(c.device.direction??0)}配置为：'
        '${c.device.mj_count}张，现在： ${c.results.length}张。');
    }
  }
  counts.forEach((value,count) { // 4a2d48
    if (value < 40 && count > 0 && count != 4) {
      errors.add('错误：${value}数量应该为4，现在${value}数据为${count}');
    }
  });
  if (expected != actual && expected != 0) {
    errors.add('错误：配置合计${expected}张，目前：${actual}张。');
  }
  // 仅局部错误列表，没有toast/audio调用。
  return errors.isEmpty;
}

void onValidDataAndSendData() { // 0x4a2164
  if (!onValidData()) return;
  EasyLoading.show(status:'保存中...');
  final payload=<Map<String,num?>>[];
  for (final c in channels) {
    for (final r in c.results) {
      final source = c.device.serial_no ?? '0';
      final serial = num.tryParse(source);
      if (serial == null) throw FormatException(source);
      payload.add({
        'mahjong_number':r.mahjongNumber, 'serial_number':serial,
        'direction':c.device.direction, 'result':int.parse(r.result)
      });
    }
  }
  GamesService.instance.addReq(payload).then((response) { // 4a2ea8
    EasyLoading.dismiss();
    if (!response.ok) { context.showErr(response.exception?.message??''); return; }
    if (response.data['success'] == false) {
      context.showErr(response.data['msg'] as String); return;
    }
    showSuccess('发送成功');
    for (final c in channels) { // 当前live channels，不是payload快照。
      setState(() {
        pageMode=1; c.results=[];
        if (displayType==2 && selectedOverlay) selectedOverlay=false;
      });
    }
  }); // void立即返回；无catchError/finally。
}

void onSelectMj(MjConfig config) { // Main 4a33cc + 4a344c
  if (selectedResult != null) setState(() {
    selectedResult!.result=config.id.toString(); // local palette id==number
    selectedResult!.resultImg=config.url;
    if (displayType==2) selectedOverlay=false;
  });
}
void leftChangeMj(ChannelResult? r, MjConfig config, int channelIndex, int seq) {
  setState(() { // 4b6b2c,4b6be8,4b6cf0
    if (r != null) { r.result=config.number.toString(); r.resultImg=config.url; }
    else channels[channelIndex].results.add(
      ChannelResult(config.number.toString(),config.url,seq,config.url));
  });
}
void mainDeleteConfirmed(int channelIndex,int seq) { // 4a67dc
  final c=channels[channelIndex]; final remaining=<ChannelResult>[];
  for (final r in c.results) {
    if (r.mahjongNumber==seq) continue;
    if (r.mahjongNumber>seq) r.mahjongNumber--;
    remaining.add(r);
  }
  setState(()=>c.results=remaining); c.removedOffset++;
}
void leftDelete(int channelIndex,int seq) { // 4b68d4
  setState(()=>channels[channelIndex].results=channels[channelIndex].results
    .where((r)=>r.mahjongNumber!=seq).toList());
}
void onResetGames() { // 4aa778
  GamesService.instance.resetGames().then(resetToastCallback);
  for (final c in channels) { c.results=[]; markNeedsBuild(); }
}
// '该牌无错误' Visibility(false)，回调只置waring=false。
// 没有从以上链恢复自动重新识别或单张AI重试调用。
'''


def verify():
    manifest=json.loads((OUT/'evidence_manifest.json').read_text())
    checks=[]
    for entry in manifest['methods']:
        p=Path(entry['source']); lines=p.read_text().splitlines(keepends=True)
        recovered=''.join(lines[entry['start_line']-1:entry['end_line']]).encode()
        snippet=(OUT/entry['snippet']).read_bytes()
        checks.append(dict(address=entry['address'],
            source_hash_matches=sha(p.read_bytes())==entry['source_sha256'],
            range_matches=snippet==recovered,
            snippet_hash_matches=sha(snippet)==entry['snippet_sha256']))
    passed=all(all(c[k] for k in ['source_hash_matches','range_matches','snippet_hash_matches']) for c in checks)
    result=dict(passed=passed,method_count=len(checks),checks=checks,
        scope='verifies source ranges and SHA256 only; does not prove every semantic annotation automatically')
    write_json('verification.json', result)
    assert passed
    return result


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--verify-only',action='store_true'); args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    if args.verify_only:
        result=verify(); print(json.dumps(dict(passed=result['passed'],methods=result['method_count'])))
        return
    index_methods()
    selected=[hex(a) for a in SELECTED]
    missing=[a for a in selected if a not in METHODS]
    assert not missing, missing
    claims=pipeline_claims(); palette=extract_palette(); reads=static_reads()
    (OUT/'evidence').mkdir(exist_ok=True)
    manifest=[]
    for address in selected:
        method=METHODS[address].copy(); body=method.pop('body')
        rel='evidence/'+address+'.asm.txt'; (OUT/rel).write_text(body)
        method.update(snippet=rel,snippet_sha256=sha(body.encode()))
        manifest.append(method)
    write_json('evidence_manifest.json',dict(format_version=1,
        extraction_script=str(Path(__file__).resolve()),script_sha256=sha(Path(__file__).read_bytes()),
        annotation_origin='manual control-flow/field data-flow review; literal palette parsed mechanically',
        methods=manifest))
    write_json('pipeline.json',dict(format_version=1,claims=claims,error_paths=ERRORS,
        scope='Dart AOT MainPage, ChannelResult, Devices, MjConfig, related manual widgets and Games.addReq',
        evidence_manifest='evidence_manifest.json',runtime_execution=False,business_network_requests=False))
    write_json('payload_models.json',models())
    write_json('local_palette.json',palette)
    write_json('login_user_field_reads.json',reads)
    (OUT/'中文说明.txt').write_text(report(claims,palette,reads))
    (OUT/'reconstructed_pipeline.dart').write_text(PSEUDO)
    result=verify()
    print(json.dumps(dict(passed=result['passed'],methods=len(manifest),claims=len(claims),
        error_paths=len(ERRORS),local_palette=len(palette['entries']),output=str(OUT)),ensure_ascii=False))


if __name__=='__main__':
    main()
