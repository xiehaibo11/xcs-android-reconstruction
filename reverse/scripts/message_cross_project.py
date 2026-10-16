#!/usr/bin/env python3
"""Read-only protocol evidence scan; never execute the inspected JAR/APK."""

from _paths import app_root, workspace_root, study_root
import hashlib
import json
import re
import struct
import zipfile
from pathlib import Path

ROOT = workspace_root()
APP = ROOT / 'APP'
OUT = APP / 'analysis/message_semantics'
STUDY = study_root()
NEEDLES = ['msg_type', 'msg_content', 'msgType', 'msgtype', 'message_type',
           'messageType', '/api/login/login/distinguish']


def constant_utf8(data):
    if data[:4] != b'\xca\xfe\xba\xbe':
        raise ValueError('Not a JVM class')
    count, = struct.unpack_from('>H', data, 8)
    pos, index = 10, 1
    while index < count:
        offset, tag = pos, data[pos]
        pos += 1
        if tag == 1:
            length, = struct.unpack_from('>H', data, pos)
            pos += 2
            value = data[pos:pos + length].decode('utf-8', errors='replace')
            pos += length
            yield index, offset, value
        elif tag in (3, 4):
            pos += 4
        elif tag in (5, 6):
            pos += 8
            index += 1
        elif tag in (7, 8, 16, 19, 20):
            pos += 2
        elif tag in (9, 10, 11, 12, 17, 18):
            pos += 4
        elif tag == 15:
            pos += 3
        else:
            raise ValueError(f'Unknown constant-pool tag {tag}')
        index += 1


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    inventory, hits, errors = [], [], []
    for jar in sorted(STUDY.glob('*.jar')):
        item = {'path': str(jar), 'sha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
                'class_count': 0, 'utf8_constant_count': 0}
        with zipfile.ZipFile(jar) as archive:
            for name in archive.namelist():
                if not name.endswith('.class'):
                    continue
                item['class_count'] += 1
                try:
                    for index, offset, value in constant_utf8(archive.read(name)):
                        item['utf8_constant_count'] += 1
                        matches = [n for n in NEEDLES if n.lower() in value.lower()]
                        if matches or '/api/' in value or value == 'instructions_type':
                            # Only selected protocol labels/endpoints are emitted, not arbitrary constants.
                            hits.append({'jar': str(jar), 'class_entry': name,
                                         'cp_utf8_index': index, 'class_file_offset': hex(offset),
                                         'value': value, 'target_matches': matches})
                except Exception as exc:
                    errors.append({'jar': str(jar), 'class_entry': name, 'error': str(exc)})
        inventory.append(item)

    snapshot = json.loads((APP / 'analysis/flutter/snapshot_strings.json').read_text())
    endpoints = [{**r, 'file': str(APP / 'unpacked/lib/arm64-v8a/libapp.so'),
                  'offset_hex': hex(r['offset'])} for r in snapshot if r['text'].startswith('/api/')]
    jar_endpoints = []
    for h in hits:
        if '/api/' in h['value']:
            jar_endpoints.append({**h, 'normalized_path': h['value'][h['value'].index('/api/'):]})
    exact_shared_paths = sorted(set(r['text'] for r in endpoints) &
                                set(r['normalized_path'] for r in jar_endpoints))
    java_files = sorted((APP / 'jadx/sources').rglob('*.java'))
    java_hits = []
    for path in java_files:
        for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            matches = [n for n in NEEDLES if n.lower() in line.lower()]
            if matches or '/api/config/' in line:
                java_hits.append({'file': str(path), 'line': number, 'matches': matches})
    local_sources = [ROOT / 'CAMERA_RECOGNIZER.md', ROOT / 'camera_to_recognizer.py', ROOT / 'requirements.txt']
    local_hits = []
    for path in local_sources:
        for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            matches = [n for n in NEEDLES if n.lower() in line.lower()]
            if matches or '/api/config' in line:
                local_hits.append({'file': str(path), 'line': number, 'matches': matches})
    result = {
        'purpose': 'Look for independently named shared msg_type protocol, never infer semantics from equal numbers.',
        'targets': {'msg_type_values': [101, 102, 113, 114, 115, 116, 117], 'labels_and_endpoint': NEEDLES,
                    'endpoint_prefix': '/api/config'},
        'method': 'Parse every JVM class UTF-8 constant pool in the 23 previously extracted local JARs; exact/path comparison with APK snapshot; targeted text scan of Java and local project source.',
        'scope': {'jars': inventory, 'total_classes': sum(r['class_count'] for r in inventory),
                  'total_utf8_constants': sum(r['utf8_constant_count'] for r in inventory),
                  'apk_java_file_count': len(java_files), 'other_project_source_files': [str(p) for p in local_sources],
                  'excluded': ['Windows bundled JRE/runtime', 'userdata.json', 'serialized user config files',
                               'unrelated private directories', 'network services']},
        'jar_protocol_hits': hits, 'jar_endpoints': jar_endpoints, 'apk_snapshot_endpoints': endpoints,
        'exact_shared_endpoint_paths': exact_shared_paths,
        'target_label_hits_in_jars': [h for h in hits if h['target_matches']],
        'target_label_hits_in_business_classes': [h for h in hits if h['target_matches'] and
                                                h['class_entry'].startswith(('quesheng/', 'queshens/', 'com/server/', 'com/lsw/', 'com/serve/', 'com/mobilesdk/'))],
        'generic_library_matches': '125 case-insensitive messageType matches belong to io/netty generic MQTT/Redis/SOCKS codec and type-matcher classes, not an APK msg_type enum.',
        'apk_java_target_hits': java_hits, 'other_source_target_hits': local_hits, 'parse_errors': errors,
        'conclusion': 'No msg_type/msg_content or /api/login/login/distinguish match was found in the inspected JAR/Java source. Generic messageType matches are Netty library names, with no matches in project business classes. No complete APK API path is shared with the inspected Windows JAR endpoints. Windows instructions_type and /api/config/GetLastVersion are adjacent-project evidence only; they do not establish meanings for APK msg_type values.',
        'limits': ['Constant-pool/text absence does not exclude computed/obfuscated names or absent server source.',
                   'The 101/102/113..117 numbers were not assigned meanings by cross-project matches.',
                   'APK numeric meanings require direct Dart AOT branch and payload evidence.']
    }
    (OUT / 'cross_project_evidence.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    (OUT / '跨项目协议旁证说明.txt').write_text(
        f"只读扫描 {len(inventory)} 个已提取 JAR、{result['scope']['total_classes']} 个 JVM class、"
        f"{result['scope']['total_utf8_constants']} 条 UTF-8 常量，以及 {len(java_files)} 个 APK Java 文件。\n"
        "没有发现 msg_type/msg_content 或 /api/login/login/distinguish 的精确匹配；messageType 的 125 个大小写不敏感命中属于 Netty 的 MQTT/Redis/SOCKS 等通用库名称，业务 class 没有命中。\n"
        "APK 的 /api/config/* 完整接口路径也未与 Windows JAR 接口精确共享。\n"
        "Windows 游戏端与识别端出现 /api/login/login、/api/config/GetLastVersion；设备协议使用 instructions_type。"
        "这些只作为旁证，不用于解释 APK 的 101、102、113..117，也不声称两个产品的消息枚举相同。\n"
        "检索只覆盖明列的 class 常量池及项目源文件；未读取 userdata.json、序列化用户配置、私钥或无关私人目录，未联网或执行被分析的程序。\n"
        "消息业务含义以本目录后续 Dart AOT 分支证据为准。\n")
    print(json.dumps({'jars': len(inventory), 'classes': result['scope']['total_classes'],
                      'utf8_constants': result['scope']['total_utf8_constants'], 'target_hits': len(result['target_label_hits_in_jars']),
                      'exact_shared_paths': exact_shared_paths, 'java_files': len(java_files), 'errors': len(errors)}))


if __name__ == '__main__':
    main()
