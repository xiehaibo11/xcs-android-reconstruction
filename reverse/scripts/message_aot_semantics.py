#!/usr/bin/env python3
"""Reproducible static evidence catalog; does not run the APK or its libraries."""

from _paths import app_root, workspace_root
import hashlib
import json
import re
import struct
from pathlib import Path

APP = app_root()
ASM = APP / 'analysis/aot_dump/asm/distinguish'
OUT = APP / 'analysis/message_semantics'
LIB = APP / 'unpacked/lib/arm64-v8a/libapp.so'
FILES = {n: ASM / n for n in [
    'pages/main/main_page.dart', 'pages/frame_preview/frame_preview_page.dart',
    'model/message.dart', 'model/devices.dart', 'model/user.dart',
    'model/channel.dart', 'model/channel_result.dart', 'model/mj_config.dart',
    'src/rust/frb_generated.dart', 'src/rust/flutter_event/ws_event.dart',
    'common/utils.dart', 'common/function.dart', 'service/main_service.dart']}
TEXT = {n: p.read_text() for n, p in FILES.items()}
MAIN = 'pages/main/main_page.dart'


def evidence(name, *addresses):
    lines = TEXT[name].splitlines()
    refs = []
    for address in addresses:
        needle = f'// {address}:'
        indices = [i for i, line in enumerate(lines, 1) if needle in line]
        assert indices, (name, address)
        refs.append({'file': str(FILES[name]), 'line': indices[0], 'elf_virtual_address': address,
                     'excerpt': lines[indices[0] - 1].strip()})
    return refs


def raw_compare(data, address, value):
    addr = int(address, 16)
    phoff, = struct.unpack_from('<Q', data, 32)
    size, count = struct.unpack_from('<HH', data, 54)
    for i in range(count):
        typ, flags, off, va, pa, fs, ms, align = struct.unpack_from('<IIQQQQQQ', data, phoff + i * size)
        if typ == 1 and va <= addr < va + fs:
            file_offset = off + addr - va
            word, = struct.unpack_from('<I', data, file_offset)
            assert word == 0x7100001f | ((value * 2) << 10), (address, value, hex(word))
            return {'file_offset': hex(file_offset), 'bytes_hex': data[file_offset:file_offset + 4].hex(),
                    'instruction': f'cmp w0, #{hex(value * 2)}', 'dart_smi_value': value,
                    'verification': 'Raw ELF instruction word equals AArch64 SUBS WZR,W0,#(msg_type*2).'}
    raise ValueError(address)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = LIB.read_bytes()
    branches = [
        (101, '0x5274fc', '0x527504', '0x527588', '接收单张牌图像/识别数据',
         'msg_content 是非空 Map<String,dynamic>；MessageUpImg.fromJson 后调用 saveImg。',
         ['解析 serial_number、mahjong_number、img、ai_val、ai_precision。',
          'img=="x" 时添加空图占位结果；否则按 getImgUrl(img) 获取图片响应，decode_data 后 base64Decode，写入临时缓存。',
          '按 serial_number==Devices.serial_no 归属 Channel；ai_val 匹配 MjConfig.number，设置结果编码、牌图URL与 ai_precision。',
          '当非空识别结果总数等于设备 mj_count 总和时，取消倒计时、显示等待数据发送中...、打开改牌页、调用 onValidDataAndSendData。'],
         ['0x527540', '0x527558', '0x528348', '0x528798', '0x5291f0', '0x5291fc', '0x5292d0', '0x529390', '0x5297a8', '0x529804', '0x529c50', '0x529814', '0x529824']),
        (102, '0x527590', '0x527598', '0x5276f4', '实时预览 JPEG 图像帧',
         '对 msg_content 调用字符串转换；可为纯图像编码字符串，或 deviceId|图像编码字符串。',
         ['有 | 时把第0段 int.parse，只有它等于 MainService 的当前预览设备ID才使用第1段；额外段未读取。',
          '没有 | 时直接使用完整字符串。', 'Utils.decode_data 后写 MainService 的响应式字符串 field_b.value。',
          'FramePreview UI 读取该值，base64Decode→decodeJpg→encodePng→Image.memory。'],
         ['0x5275e0', '0x52760c', '0x527654', '0x52769c', '0x5276b8', '0x5276c4', '0x5276e4']),
        (117, '0x5276f8', '0x527700', '0x5278ac', '升降牌打开、等待洗牌',
         'msg_content 转字符串后以 | 分隔；仅第0段用于匹配 Devices.serial_no。第1段含义未确认。',
         ['匹配设备 lighting_switch=1，并标记页面重建。', 'setState 状态文案：升降牌打开，等待洗牌中...。'],
         ['0x527748', '0x527810', '0x527850', '0x527864', '0x5278a8', '0x52a6fc', '0x52a718']),
        (115, '0x5278b4', '0x5278bc', '0x5279c8', '设备离线通知',
         'msg_content 转字符串后直接与 Devices.serial_no 比较；不在此分支拆 |。',
         ['匹配设备 online=0、lighting_switch=0。', '此分支没有观察到直接 setState/markNeedsBuild 调用。'],
         ['0x52793c', '0x52796c', '0x5279b0', '0x5279b4']),
        (116, '0x5279cc', '0x5279d4', '0x527ae8', '设备在线通知',
         'msg_content 转字符串后直接与 Devices.serial_no 比较；不在此分支拆 |。',
         ['匹配设备 online=1。', '此分支没有观察到直接 setState/markNeedsBuild 调用。'],
         ['0x527a58', '0x527a88', '0x527ad0']),
        (114, '0x527aec', '0x527af4', '0x527d00', '单设备数据接收完成；全部完成后收尾',
         'msg_content 转字符串后直接与 Devices.serial_no 比较。',
         ['匹配设备 lighting_switch=0，并标记页面重建。',
          '遍历完成后，只有所有 Channel 的设备 lighting_switch 都不等于1，才进入总体收尾。',
          '状态文案：接受完成，等待下轮数据...；取消 timer，置 timer=null、remainingSeconds=0。',
          '5秒后的回调比较结果数量与 mj_count 总和，结果不足时播放 number_error.wav。'],
         ['0x527c00', '0x527c30', '0x527c88', '0x527cbc', '0x527cc0', '0x527ccc', '0x527cfc', '0x52a6d4', '0x52a658', '0x52a68c', '0x52a6a0']),
        (113, '0x527d08', '0x527d10', '0x527ef8', '开始新一轮数据接收',
         '该分支未读取 msg_content。',
         ['已有 remainingSeconds>0 时忽略这个开始通知。',
          '清空每个 Channel 的结果列表并标记页面重建。',
          'remainingSeconds=Utils.loginUser.timeout??60；状态文案：数据接收中...(N秒)。',
          '每1秒倒计时并更新文案；计时值<=0时取消定时器。该倒计时回调没有观察到自动提交。'],
         ['0x527d20', '0x527db8', '0x527e34', '0x527e44', '0x527e64', '0x527e8c', '0x527ea8', '0x527ed4', '0x52a40c', '0x52a440', '0x52a458', '0x52a4b4'])
    ]
    entries = []
    for number, cmp, begin, end, semantic, payload, actions, addresses in branches:
        entries.append({'msg_type': number, 'semantic_label': semantic,
                        'semantic_label_origin': 'Recovered handling/UI meaning; no original enum member name recovered.',
                        'comparison_address': cmp, 'branch_begin': begin, 'branch_end': end,
                        'raw_elf_comparison': raw_compare(data, cmp, number),
                        'payload': payload, 'processing_order': actions,
                        'evidence': evidence(MAIN, cmp, *addresses),
                        'confidence': 'Direct AOT branch/dataflow and model/UI cross-reference; receiver-side behavior only.'})
    entries[1]['ui_consumer_evidence'] = evidence('pages/frame_preview/frame_preview_page.dart',
                                               '0x459158', '0x459180', '0x463ea4', '0x463eac', '0x463eb4', '0x463f00', '0x463f18')

    mapping = {
        'library': {'file': str(LIB), 'sha256': hashlib.sha256(data).hexdigest()},
        'source': 'Local Blutter static Dart AOT dump cross-checked against raw ARM64 instructions; original dump unchanged.',
        'addressing': 'All code addresses are libapp.so ELF virtual addresses; current PT_LOAD mapping has equal file offset at these addresses.',
        'entry': {'function': '_MainPageState::initState anonymous WsEvent listener', 'address': '0x527460',
                  'enclosing_initState': '0x51f028',
                  'event_gate': 'WsEvent.field_7==4 (unboxed event integer); then jsonDecode(WsEvent.field_13) as Map<String,dynamic> and Message.fromJson.',
                  'evidence': evidence(MAIN, '0x52748c', '0x527490', '0x5274ac', '0x5274b4', '0x5274bc', '0x5274e8')},
        'dispatch_order': [101, 102, 117, 115, 116, 114, 113],
        'entries': entries,
        'other_event': {'event_integer': 10, 'behavior': 'Log ws链接服务器成功 and call Rust bridge wsLogin; attach a Future.then callback.',
                        'evidence': evidence(MAIN, '0x527efc', '0x527f18', '0x527f20', '0x527f28', '0x527f34', '0x527f60')},
        'field_identity_cross_checks': {
            'Devices.field_1f': {'json_key': 'lighting_switch', 'evidence': evidence('model/devices.dart', '0x45a068', '0x45a074')},
            'Devices.field_63': {'json_key': 'serial_no', 'evidence': evidence('model/devices.dart', '0x45a3c4', '0x45a3d0')},
            'Devices.field_67': {'json_key': 'online', 'evidence': evidence('model/devices.dart', '0x45a400', '0x45a40c')},
            'Devices.field_5f': {'json_key': 'mj_count', 'evidence': evidence('model/devices.dart', '0x45a388', '0x45a394')},
            'User.field_23': {'json_key': 'timeout', 'evidence': evidence('model/user.dart', '0x4921c0', '0x4921cc')}
        },
        'decode_data': {'address': '0x528074', 'rule_source': 'Static field 0xbc0, populated by server-address RSA-decoded JSON element [1] (separately analyzed by root agent).',
                        'algorithm': 'for rule in ruleString.split("|"): pair=rule.split(","); input=input.replaceAll(pair[1],pair[0]); return input;',
                        'replacement_direction': 'second comma-separated component -> first component; ordered global substitutions.',
                        'register_proof': '0x528164 x2=pair[1]; 0x52816c x3=pair[0]; 0x528174 x1=input; 0x528178 calls replaceAll.',
                        'evidence': evidence('common/utils.dart', '0x528094', '0x5280a4', '0x528130', '0x528164', '0x52816c', '0x528174', '0x528178'),
                        'limits': 'The runtime rule values are absent locally; empty/malformed rules may throw range errors. This function itself performs substitutions, not RSA/AES/gzip decoding.'},
        'boundaries': ['This recovers the APK receiver behavior, not the server enum source or the full sender contract.',
                       'Semantic labels are analyst descriptions; no original named msg_type enum was recovered.',
                       'GDT toString/split/indexOf operation names are reconstructed from argument/result use; seven comparisons and field writes are raw-code verified.',
                       'The observed lighting_switch field is not Devices.status (a different field).',
                       'No network request, native loading, or APK execution was performed.']
    }
    (OUT / 'msg_type_mapping.json').write_text(json.dumps(mapping, ensure_ascii=False, indent=2) + '\n')

    def field(name, typ, offset, address):
        return {'json_key': name, 'dart_type': typ, 'compressed_field_offset': offset, 'evidence': evidence('model/message.dart', address)}
    models = {
        'trust_boundary': 'These models are reconstructed from AOT factories/serialization/consumers, not original Dart source. Optionality reflects factory casts, while handling may require values.',
        'Message': {'class_id': 3539, 'fromJson_address': '0x52a198',
                    'fields': [field('msg_type', 'int?', '0x7', '0x52a1c4'), field('msg_content', 'dynamic', '0xb', '0x52a21c')],
                    'behavior': 'Factory performs nullable-int cast for msg_type; msg_content is stored without a type cast.'},
        'MessageUpImg': {'class_id': 3538, 'fromJson_address': '0x529e50',
                         'fields': [field('serial_number', 'String?', '0x7', '0x529e7c'),
                                    field('mahjong_number', 'int?', '0xb', '0x529edc'),
                                    field('img', 'String?', '0xf', '0x529f38'),
                                    field('ai_val', 'int?', '0x13', '0x529f98'),
                                    field('ai_precision', 'double?', '0x17', '0x529ff0')],
                         'limits': 'double? is an actual Dart cast; integer-valued JSON numbers do not necessarily pass it. JSON Schema number cannot express this VM-level distinction.'},
        'WsEvent': {'class_id': 3521, 'sse_decoder_address': '0x520e6c',
                    'fields': [{'chosen_name': 'event_integer', 'offset': '0x7', 'type': 'unboxed uint32', 'decode_order': 0},
                               {'chosen_name': 'first_string', 'offset': '0xf', 'type': 'String', 'decode_order': 1},
                               {'chosen_name': 'second_string', 'offset': '0x13', 'type': 'String', 'decode_order': 2}],
                    'evidence': evidence('src/rust/frb_generated.dart', '0x520e98', '0x520ea8', '0x520eb8', '0x520ec8', '0x520ed0', '0x520ed8'),
                    'limits': 'Original field identifier names are not recovered here. Rust business forwarding sets event_integer=4, first_string="", second_string=original data_content JSON.'},
        'Channel': {'class_id': 3548, 'observed_fields': [
            {'chosen_name': 'device', 'offset': '0x7', 'type': 'Devices', 'evidence': evidence(MAIN, '0x51f274')},
            {'chosen_name': 'integer_counter', 'offset': '0xb', 'type': 'unboxed int', 'default': 0, 'evidence': evidence(MAIN, '0x51f284')},
            {'chosen_name': 'results', 'offset': '0x13', 'type': 'List<ChannelResult>', 'evidence': evidence(MAIN, '0x51f240', '0x51f27c', '0x527db8')}],
            'limits': 'No original field names or full definition recovered; field_0xf remains unnamed.'},
        'ChannelResult': {'class_id': 3547, 'constructor': '0x4b6ecc', 'toString': '0x576020',
                          'fields_from_print_labels': [
                              {'name': 'result', 'offset': '0x7', 'type': 'String', 'default': 'constructor arg x2'},
                              {'name': 'resultJD', 'offset': '0xb', 'type': 'unboxed double', 'default': 0.0},
                              {'name': 'resultImg', 'offset': '0x13', 'type': 'String', 'default': 'constructor arg x3'},
                              {'name': 'result180', 'offset': '0x17', 'type': 'String', 'default': ''},
                              {'name': 'result180JD', 'offset': '0x1b', 'type': 'unboxed double', 'default': 0.0},
                              {'name': 'result180Img', 'offset': '0x23', 'type': 'String', 'default': ''},
                              {'name': 'mahjongNumber', 'offset': '0x27', 'type': 'unboxed int', 'default': 'constructor arg x5'},
                              {'name': 'uploadImg', 'offset': '0x2f', 'type': 'String', 'default': 'constructor arg x6'},
                              {'name': 'select', 'offset': '0x33', 'type': 'bool', 'default': False},
                              {'name': 'waring', 'offset': '0x37', 'type': 'bool', 'default': False},
                              {'name': 'shiBie', 'offset': '0x3b', 'type': 'List<ShiBie>', 'default': []}],
                          'unnamed_field': {'offset': '0x3f', 'type': 'unboxed int', 'default': -1},
                          'evidence': evidence('model/channel_result.dart', '0x4b6f18', '0x4b6f44', '0x4b6f64', '0x576058', '0x576070', '0x5760d0', '0x576148', '0x5761e4', '0x576230', '0x57626c', '0x576284', '0x57629c'),
                          'limits': 'Local result/UI model, not a confirmed on-wire JSON payload; spelling waring preserved.'}
    }
    assert 'class Message extends Object' in TEXT['model/message.dart']
    # Class id is checked from the original dump instead of trusting a remembered number.
    m = re.search(r'// class id: (\d+).*\nclass Message extends', TEXT['model/message.dart'])
    models['Message']['class_id'] = int(m[1])
    (OUT / 'payload_models.json').write_text(json.dumps(models, ensure_ascii=False, indent=2) + '\n')
    schema = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
              'title': 'Receiver-side reconstructed Message / msg_content',
              'type': 'object', 'properties': {'msg_type': {'type': ['integer', 'null']}, 'msg_content': {}},
              '$defs': {'MessageUpImg': {'type': 'object', 'properties': {
                  'serial_number': {'type': ['string', 'null']}, 'mahjong_number': {'type': ['integer', 'null']},
                  'img': {'type': ['string', 'null'], 'description': 'Image URL/path or sentinel x; missing img becomes empty string in saveImg.'},
                  'ai_val': {'type': ['integer', 'null'], 'description': 'MjConfig.number lookup, -1 skips identification mapping.'},
                  'ai_precision': {'type': ['number', 'null'], 'x-dart-cast': 'double?'}}}},
              'allOf': [{'if': {'properties': {'msg_type': {'const': 101}}, 'required': ['msg_type']},
                         'then': {'properties': {'msg_content': {'$ref': '#/$defs/MessageUpImg'}}, 'required': ['msg_content']}}],
              '$comment': 'Factory fields are nullable/optional. This schema describes factory casts and 101 handler object requirement; it is not a server contract. 102/114..117 convert dynamic content to string.'}
    (OUT / 'payload.schema.json').write_text(json.dumps(schema, ensure_ascii=False, indent=2) + '\n')
    # Selected original disassembly is copied as evidence; aot_dump is never edited.
    chosen = []
    for name in [MAIN, 'model/message.dart', 'common/utils.dart', 'src/rust/frb_generated.dart']:
        for line in TEXT[name].splitlines():
            match = re.search(r'//\s+(0x[0-9a-f]+):', line)
            if match:
                address = int(match[1], 16)
                if (name == MAIN and (0x527460 <= address < 0x528074 or 0x52a3d0 <= address < 0x52a724)) or \
                   (name == 'model/message.dart' and 0x529e50 <= address < 0x52a25c) or \
                   (name == 'common/utils.dart' and 0x528074 <= address < 0x5281d8) or \
                   (name == 'src/rust/frb_generated.dart' and 0x520e6c <= address < 0x520ef0):
                    chosen.append(f'// SOURCE {name}\n{line}')
    (OUT / 'dispatch_evidence.asm.txt').write_text('\n'.join(chosen) + '\n')
    manifest = {'sources': [{'file': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in FILES.values()],
                'checks': {'raw_cmp_instructions_verified': 7, 'msg_type_set': sorted(e['msg_type'] for e in entries),
                           'model_keys_verified': 7, 'read_only_static_analysis': True},
                'outputs': ['msg_type_mapping.json', 'payload_models.json', 'payload.schema.json', 'dispatch_evidence.asm.txt',
                            'reconstructed_dispatch.dart', '消息业务语义说明.txt', 'cross_project_evidence.json']}
    (OUT / 'evidence_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(manifest['checks'], ensure_ascii=False))


if __name__ == '__main__':
    main()
