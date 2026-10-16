#!/usr/bin/env python3
"""Assemble recovered login and HTTP contracts into one reviewable artifact."""

from _paths import app_root, workspace_root
import copy
import json
from pathlib import Path

ROOT = app_root()
http = json.loads((ROOT / 'analysis/http_contract/endpoint_contracts.json').read_text())
login = json.loads((ROOT / 'analysis/login_flow/dart_login_flow.json').read_text())

def prop(name, typ, origin, value=None):
    result = {'name': name, 'dart_type': typ, 'origin': origin,
              'inclusion': 'inserted by observed caller', 'server_required': 'unknown'}
    if value is not None: result['constant_value'] = value
    return result

login_entries = [
 {'owner': 'LoginService', 'method': 'login', 'address': '0x48f670', 'http_method': 'POST',
  'path_template': '/api/login/login/distinguish',
  'actual_request_path': '/api/login/login/distinguish?app_name=xcs',
  'path_parameters': [], 'query_parameters': [prop('app_name', 'String', 'literal URL concatenation', 'xcs')],
  'request_body': {'dart_container_type': 'Map<String,Object>', 'properties': [
   prop('username', 'String', 'username controller text'), prop('password', 'String', 'password controller text'),
   prop('devicetype', 'int', 'literal tagged Smi 2 -> Dart integer 1', 1)]},
  'response_client_observations': login['http_steps'][0]['consumed_response'],
  'evidence_file': 'analysis/login_flow/dart_login_evidence.json', 'evidence_groups': ['login_request', 'login_route', 'login_response']},
 {'owner': 'LoginService', 'method': 'getServerAddr', 'address': '0x48fe38', 'http_method': 'POST',
  'path_template': '/api/server/get_server_addr', 'path_parameters': [], 'query_parameters': [],
  'request_body': {'dart_container_type': 'Map<String,Object>', 'properties': [
   prop('client_type', 'int', 'literal tagged Smi 2 -> Dart integer 1', 1),
   prop('key', 'String', 'base64Encode(public PEM asset codeUnits)')]},
  'response_client_observations': login['http_steps'][1]['consumed_response'],
  'response_decryption': login['server_config_decryption'],
  'evidence_file': 'analysis/login_flow/dart_login_evidence.json', 'evidence_groups': ['server_addr_request', 'server_addr_crypto', 'rsa_padding']}]
entries = login_entries + copy.deepcopy(http['endpoints'])
names = set()
for entry in entries:
    body = entry.get('request_body') or {}
    names.update(p['name'] for p in body.get('properties', []))
    names.update(p['name'] for p in entry.get('query_parameters', []))
record = {'artifact_kind': 'Evidence-backed client contract aggregation; not original source or server enforcement',
          'counts': {'fixed_endpoint_templates': len(entries),
                     'GET': sum(e['http_method'] == 'GET' for e in entries),
                     'POST': sum(e['http_method'] == 'POST' for e in entries),
                     'unique_body_or_query_field_names': len(names), 'dynamic_image_GET_separate': True},
          'endpoints': entries, 'transport': http['transport'],
          'dynamic_url_helpers': http['dynamic_url_helpers'],
          'input_artifacts': ['analysis/http_contract/endpoint_contracts.json', 'analysis/login_flow/dart_login_flow.json'],
          'client_only_limits': 'Observed call sites and serializers do not establish server required fields, numeric ranges, default values or current availability.'}
(ROOT / 'analysis/http_endpoints_all.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')

marker = '\n完整 HTTP 接口附录（自动整合）\n'
report = ROOT / '登录与业务协议还原报告.txt'
base = report.read_text().split(marker)[0]
lines = [marker, f"确认 {len(entries)} 个固定模板：11 GET、11 POST；{len(names)} 个不同 body/query 字段名。",
         '以下“无”表示观察到的调用没有传 data/query，不表示服务端禁止传参。',
         '参数必填、取值范围和服务端默认值没有由客户端静态分析证明。', '']
for i, entry in enumerate(entries, 1):
    lines.append(f"{i:02d}. {entry['http_method']} {entry['path_template']}")
    if entry.get('actual_request_path'):
        lines.append('    实际请求路径：' + entry['actual_request_path'])
    for p in entry.get('path_parameters', []):
        typ = p.get('client_dart_type', p.get('dart_type', '见详细JSON'))
        text = f"    路径 {p['name']}: {typ}"
        if 'client_default' in p: text += f"；客户端空值回退 {p['client_default']}"
        lines.append(text)
    query = entry.get('query_parameters', [])
    if query:
        text = ', '.join(p['name'] + ':' + p.get('dart_type', '?') +
                        (f"={p['constant_value']}" if 'constant_value' in p else '') for p in query)
        lines.append('    查询：' + text)
    body = entry.get('request_body') or {}
    properties = body.get('properties', [])
    if properties:
        lines.append('    JSON ' + body.get('dart_container_type', 'Map') + ': ' +
                     ', '.join(p['name'] + ':' + p.get('dart_type', '?') +
                               (f"={p['constant_value']}" if 'constant_value' in p else '') for p in properties))
    elif not query:
        lines.append('    data/query：无')
    lines.append('')
lines += [
 '预览保存字段保留实际拼写 bate、img_min_hreshold。brightness 为 double，其他18项为 int；不要修正拼写后当作真实字段。',
 '预览 device_id 取 Devices.id，不是 direction；img_type 空值回退1，但枚举业务名字没有确认。',
 '/api/zhuo/add 提交 JSON 数组，每项4个字段；serial_number 通过 num.tryParse，空序列号回退文本0，格式错误会抛异常。',
 '/api/app/check_update 查询固定 type=1、app_name=xcs，version 来自 PackageInfo.fromPlatform().version。',
 '改密码请求中的确认密码只用于本地比较，未作为独立字段发送。',
 '', '动态图片 GET 独立记录：',
 '    101消息 img 若以 http:// 或 https:// 开头则原样作为 URL；否则拼接 http://{业务主机}/{img}。',
 '    此图片相对路径拼接没有硬编码 :8081，业务接口baseUri与图片URL不能合并推断。',
 '    请求通过公共 HttpClient.get，响应消费为字符串，经替换规则、Base64解码后写本地缓存。',
 '    缓存名为 .png 不证明网络直接传 PNG 二进制；img=x 走本地占位图且不发 GET。',
 '', '原生登录补充：',
 '    wsLogin(JWT) 原始字符串被保存于 SDK 内存，自动重登录复用同一内容。',
 '    types=6 的 data_content 为该 JWT String；from/to 默认空且省略，qos=false，fp 为生成的指纹。',
 '    types=50 内层要求 code:i32、user_id:String、data:String；code=0 才进入认证成功分支并启动心跳/QoS。',
 '    调用 Future<int> 返回0/3/203分别属于连接启动/发送本地结果，不能替代服务端 code 判断。',
 '    types=54 负责被踢后的通道、心跳/QoS和状态清理。',
 '    已审查路径没有确认认证成功/失败/被踢对应的 Flutter 事件整数；user_id/data 也未确认写入SDK全局。',
 '    连接事件10发生在认证前，两个String为空，随后Dart才发送JWT登录。',
 '', '脚本入口：',
 '    scripts/aot_function_index.py：方法索引与原始ELF直接调用验证。',
 '    scripts/recover_login_flow.py：登录结构与89个关键地址的证据记录。',
 '    scripts/assemble_protocol_report.py：22个接口合并及本附录。',
 '    scripts/verify_protocol_reconstruction.py：原APK、证据行、源哈希、68个HTTP方法摘录与7个消息分支的统一检查。',
 '    scripts/message_aot_semantics.py：消息语义与模型提取。',
 '    scripts/flutter_http_contracts.py、flutter_verify_http_contracts.py：HTTP合约提取与方法摘录验证。',
 '']
report.write_text(base + '\n'.join(lines))
print(json.dumps(record['counts'], ensure_ascii=False))
