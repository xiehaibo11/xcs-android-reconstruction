#!/usr/bin/env python3
"""Materialize bounded reverse-engineering claims and recheck their original bytes.

This produces evidence, not replacement application source. Existing frozen audits
are read-only inputs. A source association never asserts whole-method completeness.
"""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import hashlib
import json
import re
import shutil
import zipfile

ROOT = _public_app_root()
OUT = Path(__file__).resolve().parent
DEST = ROOT / "reconstruction/evidence/logic"
AUDIT = ROOT / "analysis/completeness_audit/flutter"
ELF = ROOT / "unpacked/lib/arm64-v8a/libapp.so"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")

claims = [
    {
        "id": "password_change",
        "status": "bounded_static_contract",
        "methods": "42c004 42c1c8 455208 457320 457418 457438 4573d0".split(),
        "request": {"method": "POST", "path": "/account/edit/pwd", "body": {"old_password": "old controller text", "password": "new controller text"}},
        "validation": [
            "原密码 UTF-16 长度至少 6；小于 6 提示请输入原密码。",
            "新密码仅检查非空；本链没有最小长度 6、trim 或 MD5。",
            "确认密码非空且与新密码相等；表单通过后 onLogin 再次比较两次密码。",
        ],
        "response": [
            "所有普通 HttpResponse 回调首先 dismiss loading。",
            "ok 为 false：showErr(exception.message 或空字符串)，留在当前页。",
            "ok 为 true 且 body.success == false：将 body.msg 按 String 读取并 showErr。",
            "其余正常分支：toast 修改密码成功，然后 Get.offAll(LoginPage)。这是 success != false 分支，不是严格 success == true。",
            "回调内没有直接清除 token、删除 login_conf、更新所存密码或断开 WebSocket 的操作。页面销毁或导航其他效果不能由本回调缺少操作推断。",
        ],
        "limits": ["未将 UI 样式、框架异常或服务端密码约束纳入闭合范围。"]
    },
    {
        "id": "online_config_initialization",
        "status": "bounded_static_contract",
        "methods": "52afa4 52b020 52b0b4 52b110 52c350 5653ec".split(),
        "request": {"method": "GET", "path": "/api/config/get_config"},
        "response": [
            "ok false 或 success == false 时显示错误并记录红色日志，保留当前表单。",
            "其余正常分支记录获取配置成功，body.data 强制为 Map<String,dynamic>，经 OnlineConfig.fromJson 保存，setState 后再次执行 _initFormData。",
        ],
        "default_values": {"east": 26, "south": 26, "west": 26, "north": 26, "timeout": 60, "delay": 5, "data_send": 1, "count_type": 1, "upload_img_clarity": 1},
        "state_slots": {"0x1b": "east text", "0x1f": "south text", "0x23": "west text", "0x27": "north text", "0x2b": "data_send unboxed integer", "0x33": "count_type unboxed integer", "0x3b": "upload_img_clarity unboxed integer", "0x43": "timeout text", "0x47": "delay text", "0x4b": "manual SSID text", "0x4f": "manual WiFi password text"},
        "notes": ["四方向读 config_number；其余五项读 data_config。默认值针对模型/字段为空分支，不代表服务端默认。", "_initFormData 没有把 wifi_config 写回手工 SSID、密码输入框；build 单独展示当前 WiFi。"],
        "limits": ["OnlineConfig 嵌套模型空值接受性仍以原模型字段契约为准；不能将表单默认推成 JSON schema 默认。"]
    },
    {
        "id": "online_data_save",
        "status": "bounded_static_contract",
        "methods": "4ac23c 4aff50 4aff98 4b02b0 4b0318 4b062c 4b06c0 4b0710 4b07a4 4b0838 4b0888 4b091c 4b09b0 4b0a44 4b0ad8 4b0b28 4b0bbc 4b0c50 4b0ce4".split(),
        "request": {"method": "POST", "path": "/api/config/set_data_config", "body_types": {"data_send": "int", "timeout": "int.parse(timeout text)", "delay": "int.parse(delay text)", "count_type": "int", "upload_img_clarity": "int"}},
        "enums": {"count_type": {"1": "光控计数", "2": "机头双线（该 Radio 外层 Visibility.visible=false）", "5": "机头单线", "3": "T系列", "4": "S系列"}, "upload_img_clarity": {"0": "节流", "1": "标清", "2": "高清", "3": "超清"}, "data_send": {"1": "自动放送", "2": "手动发送"}},
        "events": [
            "count_type、upload_img_clarity、data_send 的 Radio 回调先 setState 写入非空 int，再立即 onSaveDataConfig。",
            "保存配置按钮也调用同一方法。此方法无 saveAndValidate、取值范围验证或 int.parse 异常捕获。",
            "请求发出之前，把 int.parse(timeout text) 写入 Utils.loginUser.timeout (0x23)。",
            "失败仅显示错误；未回滚 Radio 状态或 loginUser.timeout。成功 toast 保存成功。没有同步更新 loginUser.data_send 或 loginUser.delay 的写入。",
        ],
        "response_policy": "ok false => exception error; otherwise success == false => body.msg String error; otherwise toast 保存成功",
        "limits": ["没有证明服务端接受任意数值；不把输入类型检查替代服务器约束。"]
    },
    {
        "id": "direction_count_save",
        "status": "bounded_static_contract",
        "methods": "4b0db0 4b103c 4b10a4".split(),
        "request": {"method": "POST", "path": "/api/config/set_number", "body_types": {"east": "int.parse(text)", "south": "int.parse(text)", "west": "int.parse(text)", "north": "int.parse(text)"}},
        "events": [
            "点击时显示保存方位数量；方法内没有表单或数值范围验证。",
            "ok false：显示并红色记录异常消息；success == false：显示并红色记录 body.msg。",
            "其余正常分支遍历页面构造参数中的 channel 列表；device.direction=1/2/3/4 时将 device.mj_count 写成 east/south/west/north。",
            "成功回调读取的是响应到达时的控制器文本并再次 int.parse，不是请求发出时的值快照。",
            "最后 toast 配置方位数量成功；回调无显式 setState 或 markNeedsBuild。",
        ],
        "slot_proofs": {"Devices.direction": "0x4b", "Devices.mj_count": "0x5f"},
        "limits": ["未对不在 1..4 的 direction 写入数量；不应猜测其方向。"]
    },
    {
        "id": "channel_display_order",
        "status": "bounded_static_contract",
        "methods": "4ac23c 4b04ec 4b0570 4b05a8 5281d8".split(),
        "events": [
            "正序显示 Radio=false；倒叙显示 Radio=true。回调 setState 后写 static field 0xbc4 (field_table+0x1788)。",
            "该设置回调不发送配置 HTTP 请求，也不写文件。",
            "saveImg 0x5282ac 读取此值；true 时把识别 channel_id 偶数减 1、奇数加 1；false 时保留原 id。",
        ],
        "limits": ["仅闭合该设置写入和 saveImg 的读点；未把整个 saveImg 标记完成。"]
    },
    {
        "id": "manual_wifi_save_and_restart",
        "status": "bounded_static_contract",
        "methods": "4afb30 4afc3c 4afd30 4af648 4af6e0 4af7f8 4af558".split(),
        "requests": [{"method": "POST", "path": "/api/config/set_wifi", "body_types": {"ssid": "String controller text", "pwd": "String controller text"}}, {"method": "GET", "path": "/api/zhuo/restart_device", "parameters": "no request-specific parameters in this wrapper"}],
        "events": [
            "设置页手工 WiFi 保存函数没有非空校验，直接发送 ssid、pwd。成功仅 toast 保存成功，不刷新已加载配置。",
            "手工 WiFi 请求异常会 showErr 并写红色日志；业务 success==false 时 showErr(body.msg)，此分支没有红色日志调用。",
            "重启前写黑色日志重启所有设备；失败 showErr 并写红色日志。",
            "重启成功先 Navigator.pop 当前路由，再 showErr(重启所有设备成功) 并写同文黑色日志。showErr 是原函数名，不代表分支失败。",
            "_scanWifi 只打开 OnlineSettingWifiPage，本方法不直接调用 Android WiFi 扫描插件。",
        ],
        "limits": ["设备是否已实际重启、WiFi 是否已切换取决于服务端和设备执行，不由 toast 证明。"]
    },
    {
        "id": "wifi_page_lifecycle_and_submit",
        "status": "bounded_static_contract",
        "methods": "52c834 52c940 52c988 556b04 4b2ed8 4b2f5c 4b2fb8 4b3018 4b309c 4b2a78 4b2b8c 4b2c14 4b2c70 4b42d0 4b447c".split(),
        "events": [
            "initState 连续调用两次 _onDeviceUpWifi；没有 await 两次调用。",
            "每 3 秒 _onGetWifiDeviceWifiList；每 15 秒 _onDeviceUpWifi。",
            "deviceUp 的普通 HttpResponse 回调无 ok/success 分支：记录响应 data 后调用取列表。",
            "dispose 取消两只 Timer 并 dispose SSID/密码控制器和两个 FocusNode。没有中止既有 HTTP Future 的代码。",
            "点击 WiFi 条目先清空密码，再填 SSID 并请求密码框焦点。",
            "读取默认 WiFi 使用 POST /api/config/get_default_wifi；ok true 且 success 必须为布尔 true 时填 data.ssid.toString、data.pwd.toString。false/网络失败静默；success 非 bool 的类型异常不能当 false。",
            "本页保存检查 SSID 非空、pwd 非空；分别提示请选择WIFI！/请输入WIFI密码！。POST /api/config/set_wifi；保存后仅 toast，不自动退页或停轮询。",
        ],
        "timers_ms": {"get_device_wifi_list": 3000, "wifi_device_up": 15000},
        "limits": ["迟到列表回调没有 mounted 检查；取消计时器不代表既有请求已取消。", "这两个 Timer 是 WiFi 页面刷新机制，与 WebSocket 心跳不同。"]
    },
    {
        "id": "wifi_list_decode",
        "status": "partial_static_contract_not_full_parser_equivalence",
        "methods": "4b30f8 4b3e18 4b3fdc 4b4214".split(),
        "events": [
            "只检查 HttpResponse.ok，不检查 body.success。body.data == 空串时产生空列表。",
            "data 转字符串后找双引号：不存在双引号时先按逗号分记录，再按竖线分字段，field[0] 为 dBm 文本，field[1] 去双引号后作 SSID。",
            "存在双引号时先按竖线分记录，再按逗号分字段，field[0] 去双引号后作 SSID，field[1].split(Signallevel)[0] 作分数文本。",
            "dBm 分数：>-45 为5/5；(-55,-45] 为4/5；(-70,-55] 为3/5；(-80,-70] 为2/5；其余1/5。",
            "两种分支都有对首字段空或长度恰为2、第二字段空的跳过路径；逗号外层分支额外显式跳过字段数为1。",
            "SSID 开头为字面 \\x 时，取最后一个 \\x 位置加4为界，把前缀每两个hex字符解析为字节，UTF8解码后拼接剩余文本。",
            "WifiListItem 保存SSID和分数String；分数按/拆分且至少2段时计算 trunc(int(first)/int(second)*100)，否则百分比0。",
            "排序比较器是 (a.percentage??0) > (b.percentage??0) ? 0 : 1，不是常规三值比较器；不能声称已得到稳定降序。",
        ],
        "limits": ["两条循环包含异常恢复跳转及保留寄存器路径；异常路径下继续项的具体取值尚未穷尽验证。", "未运行 Dart 排序器，对异常比较器不得静默替换成 Java Comparator 降序后宣称等价。", "需要对两种实际服务器字符串及畸形样本进行动态差分，完整 parser 仍未闭合。"]
    },
    {
        "id": "msg117_tail_and_inlet_file_boundary",
        "status": "bounded_negative_findings_with_explicit_unknowns",
        "methods": "527460 52a6fc 48c86c 48c8bc".split(),
        "events": [
            "msg117 在 0x5276f8..0x5278ac 把 msg_content.toString 按|拆分，只读取 index0 并与 Devices.serial_no 比较；匹配则 lighting_switch=1 并 markNeedsBuild。",
            "循环结束后不管是否匹配，setState 将文案设为升降牌打开，等待洗牌中...；本分支不读取 index1、校验第二段或用第二段恢复状态。",
            "inlet_pwd.conf 在当前完整已导出 AOT 中只看到 KeyForm 保存路径及 Utils.inletPwdDbWrite。对全部 AOT、Java、原生反编译文本的限定扫描未找到文件读取函数。",
        ],
        "limits": ["msg117 发送端第二段含义未知；接收端忽略不等于发送端不存在该字段。", "未证明被优化/内联/构造路径的代码或外部进程永不读取 inlet_pwd.conf；访问控制读取用途保持未恢复。"]
    },
]

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    DEST.mkdir(parents=True, exist_ok=True)
    data = ELF.read_bytes()
    ledger = json.loads((AUDIT / "method_coverage.json").read_text())
    methods = {m["address"][2:]: m for m in ledger["methods"]}
    selected = sorted({a for c in claims for a in c["methods"]})
    proofs = []
    failures = []
    raw_words = 0
    (OUT / "methods").mkdir(exist_ok=True)
    for a in selected:
        m = methods[a]
        asm_path = ROOT / m["complete_excerpt"]
        raw_path = ROOT / m["raw_disassembly"]
        asm = asm_path.read_bytes()
        raw = raw_path.read_bytes()
        off = m["elf_file_offset"]
        size = m["exported_body_size"]
        machine = data[off:off+size]
        checks = {"asm_sha_matches_frozen": sha(asm) == m["complete_excerpt_sha256"], "raw_sha_matches_frozen": sha(raw) == m["raw_disassembly_sha256"], "body_bytes_match_frozen": sha(machine) == m["exported_body_sha256"]}
        instructions = re.findall(rb"^0x([0-9a-f]+): ([0-9a-f]{8})\s", raw, flags=re.M)
        words_ok = True
        for addr, hexword in instructions:
            va = int(addr, 16)
            expected = bytes.fromhex(hexword.decode())
            position = off + va - int(a, 16)
            words_ok &= data[position:position+4] == expected
        raw_words += len(instructions)
        checks["each_raw_instruction_matches_original_elf"] = bool(words_ok)
        checks["raw_covers_whole_exported_body"] = len(instructions)*4 == size
        if not all(checks.values()):
            failures.append({"address": "0x"+a, "checks": checks})
        shutil.copyfile(asm_path, OUT / "methods" / (a+".asm.txt"))
        shutil.copyfile(raw_path, OUT / "methods" / (a+".raw.txt"))
        proofs.append({"address": "0x"+a, "signature": m["signature"], "class": m["class_name"], "source": m["source"], "source_line": m["source_start_line"], "exported_body_size": size, "elf_file_offset": off, "body_sha256": sha(machine), "asm_sha256": sha(asm), "raw_sha256": sha(raw), "previous_semantic_coverage": m["semantic_coverage"], "whole_method_completed": False, "checks": checks})
    source_manifest = [{"path": str(ELF.relative_to(ROOT)), "sha256": sha(data)}, {"path": str((AUDIT/"method_coverage.json").relative_to(ROOT)), "sha256": sha((AUDIT/"method_coverage.json").read_bytes())}]
    findings = {"scope": "Incremental, bounded static contracts for password/settings/WiFi; not complete recovered source or complete application behavior.", "claims": claims, "method_proofs": proofs, "source_manifest": source_manifest, "original_source_recovered": False, "target_app_executed": False, "business_server_contacted": False}
    write_json(OUT / "logic_contracts.json", findings)
    scan = []
    for rel in ["analysis/aot_dump/asm", "jadx/sources", "jadx_fallback", "analysis/completeness_audit/native/ghidra_rust/functions", "analysis/completeness_audit/native/ghidra_rsa/functions"]:
        directory = ROOT / rel
        files = [p for p in directory.rglob("*") if p.suffix in (".dart", ".java", ".c", ".txt")]
        hits = []
        for p in files:
            for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if re.search(r"inlet.?pwd", line, re.I):
                    hits.append({"file": str(p.relative_to(ROOT)), "line": n, "text": line.strip()})
        scan.append({"directory": rel, "scanned_files": len(files), "hits": hits})
    write_json(OUT / "inlet_reader_search.json", {"pattern": "inlet.?pwd", "case_insensitive": True, "meaning": "Bounded text search, not proof of absence from all runtime paths.", "scans": scan})
    baseline_missing = sum(p["previous_semantic_coverage"] == "no_explicit_semantic_association_found" for p in proofs)
    summary = {"status": "PASS" if not failures else "FAIL", "scope": "Proof-byte consistency only; does not assert recovered original source or dynamic equivalence.", "claim_count": len(claims), "reviewed_method_evidence_count": len(proofs), "selected_methods_without_prior_explicit_association": baseline_missing, "checked_raw_instruction_words": raw_words, "failures": failures, "original_source_recovered": False, "full_app_behavior_completed": False, "frozen_audit_modified": False}
    write_json(OUT / "verification.json", summary)
    for name in ["logic_contracts.json", "verification.json", "inlet_reader_search.json"]:
        shutil.copyfile(OUT / name, DEST / name)
    print(json.dumps(summary, ensure_ascii=False))

if __name__ == "__main__":
    main()
