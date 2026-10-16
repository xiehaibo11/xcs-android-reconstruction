#!/usr/bin/env python3
"""Save evidence-backed login semantics from the application's static AOT dump."""

from _paths import app_root, workspace_root
import hashlib
import json
import re
from pathlib import Path

ROOT = app_root()
OUT = ROOT / 'analysis/login_flow'
OUT.mkdir(parents=True, exist_ok=True)
PREFIX = 'analysis/aot_dump/asm/'
LOGIN = PREFIX + 'distinguish/pages/login/login_page.dart'
SERVICE = PREFIX + 'distinguish/service/login_service.dart'
UTILS = PREFIX + 'distinguish/common/utils.dart'
MAIN = PREFIX + 'distinguish/pages/main/main_page.dart'
CRYPTO = PREFIX + 'encrypt/encrypt.dart'
USER = PREFIX + 'distinguish/model/user.dart'
REQ = PREFIX + 'distinguish/common/http/request_interceptors.dart'

def proof(path, addresses):
    source = ROOT / path
    lines = source.read_text().splitlines()
    excerpts = []
    for address in addresses:
        selected = [(i + 1, s) for i, s in enumerate(lines)
                    if re.search(r'\b' + re.escape(address) + r':', s)]
        if not selected:
            raise ValueError(f'Missing evidence: {path} {address}')
        excerpts.append({'address': address, 'lines': [
            {'line': n, 'text': s, 'sha256': hashlib.sha256(s.encode()).hexdigest()}
            for n, s in selected]})
    return {'file': path, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'excerpts': excerpts}

evidence = {
 'login_request': proof(LOGIN, ['0x48f4e4', '0x48f518', '0x48f528', '0x48f57c', '0x48f590', '0x48f5a4', '0x48f5b0', '0x48f5ec', '0x48f62c']),
 'login_route': proof(SERVICE, ['0x48f6a4', '0x48f6ac', '0x48f6bc', '0x48f6e4', '0x48fe6c', '0x48fe7c']),
 'login_response': proof(LOGIN, ['0x48f908', '0x48fa28', '0x48fa8c', '0x48faa0', '0x48faec', '0x48fb68']),
 'server_addr_request': proof(LOGIN, ['0x48fd08', '0x48fd34', '0x48fd40', '0x48fd48', '0x48fd54', '0x48fd64', '0x48fdd8']),
 'server_addr_crypto': proof(LOGIN, ['0x492308', '0x492330', '0x492378', '0x49239c', '0x492404', '0x492424', '0x49242c', '0x492490', '0x4924fc', '0x4925c8', '0x4925d4']),
 'rsa_padding': proof(CRYPTO, ['0x49bc8c', '0x49bcac', '0x493cbc', '0x493cd8', '0x493cf8', '0x493c00', '0x493c14']),
 'persistence': proof(LOGIN, ['0x48f1d8', '0x48f204', '0x48f22c', '0x48f238', '0x48f240', '0x48f264', '0x48f26c', '0x48f290', '0x48f298']),
 'persistence_file': proof(UTILS, ['0x48f2d8', '0x48f2f0', '0x48f374', '0x51dd9c', '0x51ddb4', '0x51de44']),
 'version_refresh': proof(LOGIN, ['0x51dae4', '0x51daf4', '0x51dd50', '0x51dd60']),
 'websocket_init': proof(MAIN, ['0x51f114', '0x51f390', '0x51f3b4', '0x52a830', '0x52a838', '0x52a858', '0x52a898', '0x52a8a0']),
 'websocket_jwt': proof(MAIN, ['0x527f1c', '0x527f20', '0x527f2c', '0x527f34', '0x4ab03c', '0x4ab044']),
 'headers': proof(REQ, ['0x68d248', '0x68d264', '0x68d298', '0x68d2a4']),
 'substitution_rules': proof(UTILS, ['0x528094', '0x5280a4', '0x528130', '0x528164', '0x52816c', '0x528178']),
}
(OUT / 'dart_login_evidence.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n')

record = {
 'status': 'confirmed client-side static semantics; no business-server traffic or target execution',
 'scope': 'Dart AOT client flow, not recovered server implementation or original source',
 'integer_note': 'Map/List integers use tagged Smi: raw immediate 2 represents Dart integer 1. Unboxed native ints and Duration microseconds are not divided by two.',
 'http_body_encoding': 'application/json; AppDio BaseOptions and Dio DefaultTransformer encode non-String Map/List as JSON. Evidence is recorded in ../http_contract/endpoint_contracts.json.',
 'http_headers': {'clientversion': 'Utils.version captured at AppDio construction, not refreshed in each request interceptor', 'clienttype': 'android', 'Authorization': 'Bearer {JWT, initially empty}', 'deviceId': 'snapshot default empty String; no assignment found'},
 'initial_login_base_url': 'http://{ip_text_controller}:8081/',
 'http_steps': [
  {'order': 1, 'method': 'POST', 'path': '/api/login/login/distinguish?app_name=xcs',
   'body_logical_map': {'username': 'username controller text (String)', 'password': 'password controller text (String)', 'devicetype': 1},
   'success_handling': 'HttpResponse.ok checked first; data.success == false shows data.msg and exits; otherwise consume jwt/loginUser/devices.',
   'consumed_response': {'jwt': 'String, stored in static slot 0xba4', 'loginUser': 'User.fromJson(Map<String,dynamic>)', 'devices': 'Iterable of Devices.fromJson maps'},
   'evidence': ['login_request', 'login_route', 'login_response']},
  {'order': 2, 'method': 'POST', 'path': '/api/server/get_server_addr',
   'body_logical_map': {'client_type': 1, 'key': 'base64Encode(rootBundle.loadString("key/pub_key.pem").codeUnits)'},
   'authorization': 'Bearer JWT from step 1, via common interceptor',
   'consumed_response': {'success': 'bool', 'msg': 'String; ciphertext on success, error text on failure'},
   'evidence': ['server_addr_request', 'server_addr_crypto']}],
 'server_config_decryption': {
  'private_key_asset': 'key/private_key.pem', 'algorithm': 'RSAEngine wrapped in PKCS1Encoding (PKCS#1 v1.5)',
  'key_bits': 2048, 'ciphertext': 'base64Decode(response.data.msg)',
  'plaintext': 'UTF-8 decode with allowMalformed:true, followed by jsonDecode',
  'decoded_shape': ['business server host string', 'image-data substitution-rules string'],
  'assignments': {'0xbb4': 'decoded[0]', '0xbc0': 'decoded[1]', '0xb94': 'http://{decoded[0]}:8081/'},
  'rule_format': 'split rules by |, split each rule by comma; decodedString=decodedString.replaceAll(rule[1],rule[0]) in original order',
  'note': 'Actual runtime host and rules are supplied by server; no ciphertext captured. No server-side key/decryption semantics asserted.',
  'evidence': ['server_addr_crypto', 'rsa_padding', 'substitution_rules']},
 'after_http_login': ['sort Devices by direction', 'save login configuration',
  'check application update; route to UpdateAppPage if update response succeeds, otherwise MainPage',
  'MainPage subscribes to Rust WsEvent stream; getMjConfigReq success initializes WebSocket host extracted from current HTTP base URL',
  'Rust connection event 10 triggers wsLogin(JWT); transport connection and native login validation are separate steps'],
 'websocket': {'uri': 'ws://{business_host}:18889', 'init_argument': 'baseUrl.substring(7).substring(0,indexOf(":8081"))',
  'login_argument': 'JWT (static slot 0xba4)', 'trigger_event': 10,
  'native_protocol_login_type': 6, 'native_protocol_login_response_type': 50,
  'retry_before_start_games': 'If wsIsLogin returns false, call wsLogin(JWT) before sendStartGamesReq; native return int must not be confused with server code.',
  'evidence': ['websocket_init', 'websocket_jwt']},
 'persistence': {'directory': 'getApplicationSupportDirectory()', 'filename': 'app_config.conf',
  'format': 'jsonEncode then File.writeAsStringSync',
  'fields': {'ip': 'String from login host controller', 'username': 'String', 'password': 'String if rememberPassword is true, otherwise empty String', 'rememberPassword': 'bool'},
  'readback': 'existsSync/readAsStringSync/jsonDecode; populate ip/username/password controllers and rememberPassword checkbox',
  'note': 'This observed login config path uses a local file; no encryption call in this write path.',
  'evidence': ['persistence', 'persistence_file']},
 'user_model': {'from_json_address': '0x491ce4', 'fields': {'id': 'int?', 'username': 'String?', 'token': 'String?', 'login_type': 'int?', 'exp': 'int?', 'nbf': 'int?', 'data_send': 'int?', 'timeout': 'int?', 'delay': 'int?'},
  'storage_offsets': {'id': '0x8', 'username': '0xc', 'token': '0x10', 'login_type': '0x14', 'exp': '0x18', 'nbf': '0x1c', 'data_send': '0x20', 'timeout': '0x24', 'delay': '0x28'},
  'note': 'Object offsets shown untagged; assembly field_N refers N=offset-1. Field names exp/nbf are preserved but units are not independently confirmed.'},
 'version': {'default_initializer': '2.0.6', 'runtime_refresh': 'PackageInfo.fromPlatform().version in read_config', 'apk_manifest_version': '2.1.6'},
 'snapshot_static_defaults': {'source': 'analysis/aot_static_defaults/static_field_defaults.txt',
  'method': 'Read deserialized snapshot FieldTable.At(slot/4); no target Dart code invoked',
  'values': {'0xb28': 'xcs', '0xb94': 'token', '0xba4': '', '0xbb4': '', '0xbc0': '', '0xbcc': ''},
  'deviceId': 'Empty string in snapshot; no StoreStaticField(0xbcc) found across dumped assemblies.',
  'initial_authorization': 'Bearer '},
 'unresolved': ['Live server response values and current server availability', 'Server-side authorization and request validation', 'Unknown/null/invalid response handling beyond observed branches']}
(OUT / 'dart_login_flow.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')

schemas = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
 'title': 'Observed successful login response consumed by XCS client', 'type': 'object',
 'required': ['success', 'jwt', 'loginUser', 'devices'], 'additionalProperties': True,
 'properties': {'success': {'type': 'boolean'}, 'jwt': {'type': 'string'},
   'loginUser': {'type': 'object', 'additionalProperties': True, 'properties': {
    k: {'type': ['integer' if v.startswith('int') else 'string', 'null']}
    for k, v in record['user_model']['fields'].items()}},
   'devices': {'type': 'array', 'items': {'type': 'object'}}, 'msg': {'type': 'string'}},
 '$comment': 'Describes fields the client consumes. It is not a captured response or proof of server enforcement. success=false is error; the login branch checks equality with false rather than requiring true.'}
(OUT / 'login_response.schema.json').write_text(json.dumps(schemas, ensure_ascii=False, indent=2) + '\n')
(OUT / 'server_config_plaintext.schema.json').write_text(json.dumps({
 '$schema': 'https://json-schema.org/draft/2020-12/schema', 'title': 'Decrypted server configuration consumed by client',
 'type': 'array', 'minItems': 2, 'prefixItems': [{'type': 'string', 'description': 'business host'}, {'type': 'string', 'description': 'ordered substitution rules: a,b|c,d -> replace b with a, then d with c'}],
 '$comment': 'Additional elements are not consumed in the observed login closure. Real host/rules require an actual response; no fabricated values.'}, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({'saved': str(OUT), 'evidence_groups': len(evidence),
                  'evidence_addresses': sum(len(v['excerpts']) for v in evidence.values())}, ensure_ascii=False))
