#!/usr/bin/env python3
"""Reconstruct local storage/startup from AOT; never executes target code."""

from _paths import app_root, workspace_root
import hashlib
import json
import re
import subprocess
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

APP = app_root()
OUT = APP / 'analysis/local_state'
EVIDENCE = OUT / 'evidence'
EVIDENCE.mkdir(parents=True, exist_ok=True)
LLVM = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
LIB = APP / 'unpacked/lib/arm64-v8a/libapp.so'
LIB_DATA = LIB.read_bytes()
INDEX = json.loads((APP / 'analysis/aot_runtime/function_index.json').read_text())
FUNCTIONS = {int(f['address'], 16): f for f in INDEX['functions']}
for address, relative in [(0x48d774, 'analysis/aot_dump/asm/path_provider/path_provider.dart'),
                          (0x48d8a8, 'analysis/aot_dump/asm/path_provider_android/messages.g.dart')]:
    lines = (APP / relative).read_text().splitlines()
    meta = next(i for i, line in enumerate(lines) if f'addr: {hex(address)},' in line)
    end = next(i for i in range(meta + 1, len(lines)) if lines[i] == '  }')
    direct = []
    for i in range(meta + 1, end):
        match = re.search(r'//\s+(0x[0-9a-f]+): bl\s+#(0x[0-9a-f]+)\s*(?:; (.*))?', lines[i])
        if match:
            direct.append({'address': match.group(1), 'target': match.group(2),
                           'label': match.group(3) or '', 'line': i + 1})
    FUNCTIONS[address] = {'address': hex(address), 'path': relative, 'line': meta + 1,
                          'signature': lines[meta - 1].strip(), 'direct_calls': direct}
with LIB.open('rb') as stream:
    elf = ELFFile(stream)
    SECTIONS = [(s['sh_addr'], s['sh_offset'], s['sh_size'])
                for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def raw(address, size=4):
    section = next(s for s in SECTIONS if s[0] <= address and address + size <= s[0] + s[2])
    offset = section[1] + address - section[0]
    return LIB_DATA[offset:offset + size], offset


def raw_proof(address):
    data, offset = raw(address)
    return {'library': str(LIB), 'library_sha256': digest(LIB),
            'elf_virtual_address': hex(address), 'file_offset': hex(offset),
            'bytes_hex': data.hex(), 'opcode': hex(int.from_bytes(data, 'little'))}


def function_lines(address):
    f = FUNCTIONS[address]
    p = APP / f['path']
    lines = p.read_text().splitlines()
    start = f['line'] - 2
    end = next(i for i in range(start + 2, len(lines)) if lines[i] == '  }')
    return f, p, lines, start, end


def proof(address, needle):
    f, p, lines, start, end = function_lines(address)
    i = next(i for i in range(start, end + 1) if needle in lines[i])
    return {'file': str(p), 'sha256': digest(p), 'line': i + 1,
            'excerpt': lines[i].strip(), 'function_address': hex(address)}


def file_proof(relative, needle):
    p = APP / relative
    lines = p.read_text().splitlines()
    i = next(i for i, line in enumerate(lines) if needle in line)
    return {'file': str(p), 'sha256': digest(p), 'line': i + 1,
            'excerpt': lines[i].strip()}


SELECTED = [0x6fc7d0, 0x5a8584, 0x4a6c80, 0x4a6d2c, 0x6fd4a8,
            0x4baf5c, 0x6fd320, 0x6fd360, 0x4baedc, 0x48f1a4,
            0x48f0bc, 0x48f3cc, 0x48f42c, 0x51d9d4, 0x51daa4,
            0x51ef74, 0x564fd4, 0x48f830, 0x49221c, 0x48c8bc,
            0x48f2ac, 0x51dd78, 0x48c270, 0x48c86c, 0x42c004,
            0x455208, 0x67f850, 0x48d774, 0x48d8a8]
excerpts, calls = [], []
for address in SELECTED:
    f, path, lines, start, end = function_lines(address)
    snippet = EVIDENCE / f'{address:08x}.asm.txt'
    snippet.write_text('\n'.join(lines[start:end + 1]) + '\n')
    excerpts.append({'file': str(path), 'sha256': digest(path),
                     'source_start_line': start + 1, 'source_end_line': end + 1,
                     'snippet': str(snippet), 'snippet_sha256': digest(snippet),
                     'function_address': hex(address), 'function_signature': f['signature']})
    for call in f['direct_calls']:
        check = raw_proof(int(call['address'], 16))
        opcode = int(check['opcode'], 16)
        assert opcode & 0xfc000000 == 0x94000000
        imm = opcode & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        assert int(call['address'], 16) + (imm << 2) == int(call['target'], 16)
        check.update({'target': call['target'], 'label': call['label'],
                      'function_address': hex(address), 'verified': True})
        calls.append(check)

# Independently disassemble all factory instructions directly from original ELF.
factory_data, _ = raw(0x6fd4a8, 0x170)
instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(factory_data, 0x6fd4a8))
assert len(instructions) == 0x170 // 4
getters = [i for i in instructions if i.mnemonic == 'blr']
assert [i.address for i in getters] == [0x6fd4e0, 0x6fd500, 0x6fd520, 0x6fd540,
                                      0x6fd560, 0x6fd580, 0x6fd5a0, 0x6fd5bc]
discard_checks = []
for index, getter in enumerate(getters):
    following = next(i for i in instructions if i.address == getter.address + 4)
    overwrite = next(i for i in instructions if i.address == getter.address + 8) if index < 7 else following
    if index < 7:
        assert overwrite.mnemonic == 'ldur' and overwrite.op_str.startswith('x0, [')
    else:
        assert overwrite.mnemonic == 'bl' and overwrite.op_str == '#0x4a6cd8'
    discard_checks.append({'getter_call': hex(getter.address),
                           'next_x0_overwrite': hex(overwrite.address),
                           'mnemonic': overwrite.mnemonic, 'operands': overwrite.op_str})
raw_factory = []
for instruction in instructions:
    check = raw_proof(instruction.address)
    check.update({'mnemonic': instruction.mnemonic, 'operands': instruction.op_str})
    raw_factory.append(check)
critical_session_checks = []
for address, mnemonic, operands in [(0x67f8d0, 'cmp', 'w0, #0x322'),
                                    (0x67f920, 'mov', 'x16, #0x322')]:
    data, _ = raw(address)
    instruction = next(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(data, address))
    assert (instruction.mnemonic, instruction.op_str) == (mnemonic, operands)
    check = raw_proof(address)
    check.update({'mnemonic': mnemonic, 'operands': operands,
                  'dart_smi_encoded_value': 802, 'decoded_value': 401})
    critical_session_checks.append(check)
llvm = subprocess.run([LLVM, '-D', '--start-address=0x6fd4a8',
                       '--stop-address=0x6fd618', str(LIB)],
                      capture_output=True, text=True, check=True).stdout
(EVIDENCE / 'view_setting_from_json.llvm.txt').write_text(llvm)

defaults = {'orientationMjHeight': 3.0, 'orientationMjWidth': 1.9,
            'orientationHeight': 640.0, 'validMjWidth': 34.0,
            'validMjHeight': 70.0, 'editMjWidth': 60.0,
            'editMjHeight': 64.0, 'orientationAiVis': True}
(OUT / 'view_setting_defaults.json').write_text(json.dumps(defaults, ensure_ascii=False, indent=2) + '\n')

claims = []


def claim(key, text, evidence, status='confirmed_static', boundary=None):
    item = {'id': key, 'status': status, 'statement': text, 'evidence': evidence}
    if boundary:
        item['boundary'] = boundary
    claims.append(item)


claim('startup', '启动在 RustLib 尚未初始化时 await RustLib.init；已初始化则跳过该分支。调用 initConfig 后立即 runApp；initConfig 本身不 await _dbRead。',
      [proof(0x6fc7d0, '0x6fc82c: cmp'), proof(0x6fc7d0, '0x6fc830: b.ne'),
       proof(0x6fc7d0, '0x6fc840: r0 = Await()'),
       proof(0x6fc7d0, '0x6fc84c: r0 = initConfig()'),
       proof(0x6fc7d0, '0x6fc850: r0 = runApp()'),
       proof(0x6fd320, '0x6fd34c: r0 = _dbRead()'),
       proof(0x6fd320, 'ReturnAsyncNotFuture')])
claim('home', 'GetMaterialApp 的 home 为 LoginPage。',
      [proof(0x5a8584, '0x5a867c: r0 = LoginPage()'),
       proof(0x5a8584, '0x5a8694: StoreField')])
claim('support_path', 'Android applicationSupport 通过 Pigeon→n5.j.h→i→r5.c.d，返回 getFilesDir；空时回退 dataDir/files。',
      [proof(0x48d774, 'getApplicationSupportPath()'),
       proof(0x48d8a8, '"dev.flutter.pigeon.PathProviderApi.getApplicationSupportPath"'),
       file_proof('jadx/sources/n5/i.java', 'getApplicationSupportPath'),
       file_proof('jadx/sources/n5/i.java', 'arrayList.add(0, bVar.h());'),
       file_proof('jadx/sources/n5/j.java', 'return r5.c.d(this.f7049b);'),
       file_proof('jadx/sources/n5/j.java', 'public String h()'),
       file_proof('jadx/sources/n5/j.java', 'return i();'),
       file_proof('jadx/sources/r5/c.java', 'File filesDir = context.getFilesDir();'),
       file_proof('jadx/sources/r5/c.java', 'new File(b(context), "files")')],
      boundary='逻辑路径是应用私有 files 目录；未读取任何真实 Android 安装数据。')
claim('login_write', 'app_config.conf 是 JSON 文本；ip/username 原文本，password 在 rememberPassword=true 时保存原文本，否则为空字符串。无加密调用。',
      [proof(0x48f1a4, '"ip"'), proof(0x48f1a4, '"username"'),
       proof(0x48f1a4, '"password"'), proof(0x48f1a4, '0x48f238:'),
       proof(0x48f1a4, '0x48f264: r1 = ""'),
       proof(0x48f1a4, '"rememberPassword"'), proof(0x48f1a4, 'jsonEncode'),
       proof(0x48f2ac, '"/app_config.conf"'), proof(0x48f2ac, 'writeAsStringSync')])
claim('login_read', 'initState 先用内存 username/password 填表，再异步读 app_config.conf；有文件即依次 String cast 三个文本键、bool cast rememberPassword；读取 password 时不检查 rememberPassword。',
      [proof(0x51d9d4, 'LoadStaticField(0xbb8)'), proof(0x51d9d4, 'LoadStaticField(0xbbc)'),
       proof(0x51d9d4, 'read_config'), proof(0x51daa4, '"ip"'),
       proof(0x51daa4, '"username"'), proof(0x51daa4, '"password"'),
       proof(0x51daa4, '"rememberPassword"'), proof(0x51daa4, '0x51dcfc: r0 = bool()'),
       proof(0x51dd78, 'existsSync'), proof(0x51dd78, 'readAsStringSync')],
      boundary='所选方法无局部 catch；JSON/类型/IO 错误可能中断恢复。未验证框架最终错误呈现。')
claim('save_timing', '登录配置保存发生在 server_addr 配置成功回调；save_config 不 await loginConfDbWrite。',
      [proof(0x49221c, '0x4925e4: r0 = save_config()'),
       proof(0x48f1a4, '0x48f298: r0 = loginConfDbWrite()'),
       proof(0x48f1a4, '0x48f2a0: r0 = ReturnAsyncNotFuture()')])
claim('reset', '登录重置先立即 setState(field_33=true)，清空 IP/用户名/密码三个输入并再次保存配置；1 秒后执行 form.currentState.saveAndValidate。此方法不删除配置文件或清 JWT。rememberPassword(field_2f)未在该方法重置。',
      [proof(0x48f0bc, 'AnonymousClosure: (0x48f42c)'),
       proof(0x48f0bc, '0x48f108: r0 = setState()'),
       proof(0x48f0bc, '0x48f11c: r0 = text=()'), proof(0x48f0bc, '0x48f130: r0 = text=()'),
       proof(0x48f0bc, '0x48f144: r0 = text=()'), proof(0x48f0bc, 'save_config'),
       proof(0x48f0bc, '1000000'), proof(0x48f42c, 'field_33'),
       proof(0x48f0bc, 'AnonymousClosure: (0x48f3cc)'),
       proof(0x48f0bc, 'Future.delayed'), proof(0x48f3cc, 'saveAndValidate')],
      boundary='field_33 保留字段名；不据此把它命名为记住密码开关。')
claim('memory_login', '登录成功回调把输入用户名和密码写入内存静态字段 bb8/bbc，未受 rememberPassword 开关控制。JWT=ba4，User=ba8，设备列表=bb0。',
      [proof(0x48f830, 'StoreStaticField(0xbb8'), proof(0x48f830, 'StoreStaticField(0xbbc'),
       proof(0x48f830, 'StoreStaticField(0xba4'), proof(0x48f830, 'StoreStaticField(0xba8'),
       proof(0x48f830, 'StoreStaticField(0xbb0')])
claim('view_write', 'view_setting.conf 保存当前对象的 8 键 JSON；设置保存回调调用 writeDb 后立即提示保存成功，没有 await 写盘。',
      [proof(0x4baf5c, '"/view_setting.conf"'), proof(0x4baf5c, 'toJson'),
       proof(0x4baf5c, 'jsonEncode'), proof(0x4baf5c, 'writeAsStringSync'),
       proof(0x4baedc, '0x4baf0c: r0 = writeDb()'), proof(0x4baedc, '"保存成功"'),
       proof(0x4baedc, '0x4baf18: r0 = showSuccess()')])
claim('view_read_bug', 'ViewSetting.fromJson 的 8 次取值结果被覆盖，随后分配新对象并写入固定默认值；正常返回时忽略 JSON 字段值。',
      [proof(0x6fd360, 'ViewSetting.fromJson'), proof(0x6fd360, '0x6fd474: StoreField'),
       proof(0x6fd4a8, '0x6fd5c0: r0 = ViewSetting()'),
       proof(0x6fd4a8, '0x6fd5c4: d0 = 3.000000'),
       proof(0x6fd4a8, '0x6fd5cc: d0 = 1.900000'),
       proof(0x6fd4a8, '0x6fd5d4: d0 = 640.000000'),
       proof(0x6fd4a8, '0x6fd5dc: d0 = 34.000000'),
       proof(0x6fd4a8, '0x6fd5e4: d0 = 70.000000'),
       proof(0x6fd4a8, '0x6fd5ec: d0 = 60.000000'),
       proof(0x6fd4a8, '0x6fd5f4: d0 = 64.000000'),
       proof(0x6fd4a8, '0x6fd5fc: r1 = true')],
      boundary='8 次 getter 仍实际执行。JSON 解码、Map cast 或 getter 抛错时可能不返回新对象。该事实仅适用于此 APK 构建。')
claim('local_phrase', 'KeyFormPage 拒绝空口令和字面保留值6666；通过此校验的口令经 UTF8→MD5→HashDigest.toString，写入 inlet_pwd.conf 文本。不是登录密码的保存路径；包装 save_config 没有 await 真正写盘函数。',
      [proof(0x48c270, '"6666"'), proof(0x48c270, '"请更换其他口令"'),
       proof(0x48c270, 'Instance_Utf8Encoder'), proof(0x48c270, 'Instance__MD5'),
       proof(0x48c270, '0x48c370: r0 = toString()'), proof(0x48c86c, 'inletPwdDbWrite'),
       proof(0x48c86c, 'ReturnAsyncNotFuture'), proof(0x48c8bc, '"/inlet_pwd.conf"'),
       proof(0x48c8bc, 'writeAsStringSync')],
      boundary='在 53 个业务汇编文件中只确认写入链，读取/校验及导航入口未闭合；不能推断该文件参与服务端认证。')
claim('edit_password', '修改密码成功回调提示并 offAll(LoginPage)，该回调不重写 app_config.conf，不更新内存密码 bbc，也不清除 Dart JWT ba4。',
      [proof(0x42c004, '"old_password"'), proof(0x42c004, '"password"'),
       proof(0x455208, '"修改密码成功"'), proof(0x455208, 'GetNavigation.offAll')],
      boundary='仅限定所选回调。原生 JWT 与 Dart 静态字段是不同存储；导航动作本身未证明原生 wsLogout 被调用。')
claim('http_401', 'HTTP statusCode==401 且 response.data.code==401 时，错误拦截器清空 Dart JWT 并 offAll(LoginPage)；其余错误交给 handler.next。该方法不清理本地文件或内存 username/password。',
      [proof(0x67f850, '0x67f8d0: cmp'), proof(0x67f850, '"code"'),
       proof(0x67f850, '0x67f920:'), proof(0x67f850, 'StoreStaticField(0xba4'),
       proof(0x67f850, 'GetNavigation.offAll'), proof(0x67f850, '0x67f988: r0 = next()')],
      boundary='0x322 是 Dart Smi 编码：802>>1=401，不能按 802 解释业务码。')

business_files = sorted((APP / 'analysis/aot_dump/asm/distinguish').rglob('*.dart'))
slot_writes = {hex(x): [] for x in [0xba0, 0xba4, 0xba8, 0xbb0, 0xbb4, 0xbb8, 0xbbc, 0xbc0, 0xbcc]}
file_refs = {name: [] for name in ['app_config.conf', 'view_setting.conf', 'inlet_pwd.conf']}
for path in business_files:
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        match = re.search(r'StoreStaticField\((0x[0-9a-f]+),', line)
        if match and match.group(1) in slot_writes:
            slot_writes[match.group(1)].append({'file': str(path), 'sha256': digest(path),
                                              'line': i + 1, 'excerpt': line.strip()})
        for name in file_refs:
            if re.search(r'// 0x[0-9a-f]+: r\d+ = "/' + re.escape(name) + r'"', line):
                file_refs[name].append({'file': str(path), 'sha256': digest(path),
                                       'line': i + 1, 'excerpt': line.strip()})

result = {'scope': '此 APK 的静态配置、启动及会话状态；分析伪代码不是原始源码。',
          'storage': [
              {'name': 'app_config.conf', 'root': 'Android applicationSupport → getFilesDir()',
               'encoding': 'JSON String, no encryption in selected writer',
               'fields': ['ip', 'username', 'password', 'rememberPassword'],
               'reader': 'Utils.loginConfDbRead → LoginPage.read_config',
               'writer': 'LoginPage.save_config → Utils.loginConfDbWrite'},
              {'name': 'view_setting.conf', 'root': 'same applicationSupport directory',
               'encoding': 'JSON String', 'fields': list(defaults),
               'reader': 'ViewSettingService._dbRead → ViewSetting.fromJson',
               'writer': 'ViewSettingService.writeDb'},
              {'name': 'inlet_pwd.conf', 'root': 'same applicationSupport directory',
               'encoding': 'UTF8 input → MD5 → digest hex text',
               'reader': 'not closed in business AOT scope',
               'writer': 'KeyFormPage.save_config → Utils.inletPwdDbWrite'}],
          'view_setting_defaults': defaults,
          'claims': claims,
          'negative_evidence_scope': {'business_files': len(business_files),
                                      'static_field_write_sites': slot_writes,
                                      'literal_file_reference_sites': file_refs,
                                      'limits': '仅此构建已导出的业务函数；不覆盖框架、原生、服务端或运行时动态行为。'},
          'from_json_raw_getter_return_discard_checks': discard_checks,
          'function_excerpts': excerpts,
          'raw_direct_call_checks': calls,
          'raw_instruction_checks': raw_factory + critical_session_checks,
          'extraction_script': str(Path(__file__).resolve()),
          'script_sha256': digest(Path(__file__).resolve()),
          'verification': {'complete_function_excerpts': len(excerpts),
                           'claims': len(claims), 'raw_direct_calls': len(calls),
                           'factory_instruction_words': len(raw_factory),
                           'factory_getters_discarded': len(getters),
                           'target_code_executed': False, 'business_server_contacted': False}}
(OUT / 'local_state.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
(OUT / '中文说明.txt').write_text('本地配置、启动与会话状态静态还原\n\n' +
    '\n\n'.join(f"{i['id']}：{i['statement']}" +
                (f"\n边界：{i['boundary']}" if 'boundary' in i else '') for i in claims) +
    '\n\n默认 ViewSetting：\n' + json.dumps(defaults, ensure_ascii=False, indent=2) +
    '\n\n详细精确行号、完整方法片段及原 ELF 指令在 local_state.json/evidence。\n')
(OUT / 'reconstructed_local_state.dart').write_text('''// 分析伪代码；不可直接编译，不是恢复出的原始源码。
// 所有文件根目录：Android getApplicationSupportDirectory → getFilesDir。
main() async {
  ensureFlutterInitialized();
  if (!RustLib.isInitialized) await RustLib.init(); // 判据是实例 field_b 非空
  ViewSettingService.instance.initConfig(); // 不 await；内部也不 await _dbRead
  runApp(MyApp(home: LoginPage()));
}
saveLoginConfig() async {
  final text = jsonEncode({"ip": ip.text, "username": username.text,
    "password": rememberPassword ? password.text : "",
    "rememberPassword": rememberPassword});
  Utils.loginConfDbWrite(text); // 未 await；真正 writer 在 await supportDir 后写盘
}
readLoginConfig() async {
  final text = await Utils.loginConfDbRead();
  if (text != null) {
    final config = jsonDecode(text);
    ip.text = config["ip"] as String;
    username.text = config["username"] as String;
    password.text = config["password"] as String;
    rememberPassword = config["rememberPassword"] as bool;
  }
}
ViewSetting reconstructedFromJson(Map<String, dynamic> json) {
  // 八次取值真实存在，但本构建正常返回路径不使用结果。
  json["orientationMjHeight"]; json["orientationMjWidth"];
  json["validMjWidth"]; json["validMjHeight"];
  json["editMjWidth"]; json["editMjHeight"];
  json["orientationAiVis"]; json["orientationHeight"];
  return ViewSetting(orientationMjHeight: 3.0, orientationMjWidth: 1.9,
    orientationHeight: 640.0, validMjWidth: 34.0, validMjHeight: 70.0,
    editMjWidth: 60.0, editMjHeight: 64.0, orientationAiVis: true);
}
// inlet_pwd.conf: UTF8(input) → MD5 → HashDigest.toString()，只闭合写路径。
// 该路径和 app_config.conf 明文记住登录密码是两条不同链。
''')
print(json.dumps(result['verification'], ensure_ascii=False))
