#!/usr/bin/env python3
"""Write manually audited Rust protocol findings with links to static evidence.

These are reconstructed analysis artifacts, not recovered Rust source. This
script never loads a native library or communicates with the application server.
"""

from _paths import app_root, workspace_root
import csv
import hashlib
import json
from pathlib import Path

APP = app_root()
OUT = APP / "analysis/deep_rust"
LIB = APP / "unpacked/lib/arm64-v8a/librust_lib_distinguish.so"


def proof(address, subdir="functions", needle=None):
    path = OUT / subdir / f"{address:08x}.c"
    lines = path.read_text().splitlines()
    if needle:
        hits = [i + 1 for i, line in enumerate(lines) if needle in line]
        if not hits:
            raise ValueError(f"Missing proof: {path}: {needle}")
    else:
        hits = [2]
    return {
        "file": str(path), "line": hits[0],
        "ghidra_address": f"0x{address:x}",
        "elf_virtual_address": f"0x{address - 0x100000:x}",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def save(name, obj):
    (OUT / name).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


serializer = proof(0x1c6ce0, needle='"types"')
parser = proof(0x1cae5c, needle="LAB_001caf54")
receiver = proof(0x1e99a0, "lifecycle/functions", "0x32 <")
business = proof(0x1c5f58, "lifecycle/functions", '"msg_type"')
ack = proof(0x1c5e50, "lifecycle/functions", "CONCAT44(local_50._4_4_,4)")
login = proof(0x1eb278, "lifecycle/functions", "local_40 = 6")
login_parser = proof(0x1ca468, needle='FUN_001e83c0("data",4)')

properties = {
    "types": {"type": "integer", "minimum": -2147483648,
              "maximum": 2147483647, "default": 0},
    "data_content": {"type": "string", "default": ""},
    "from": {"type": "string", "default": ""},
    "to": {"type": "string", "default": ""},
    "fp": {"type": "string", "default": ""},
    "qos": {"type": "boolean", "default": False},
}
common = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object", "properties": properties,
    "$comment": "Static reconstruction of six named fields. Unknown-key behavior and duplicate-key errors are not fully represented. JSON Schema default is annotation only.",
}
outbound = json.loads(json.dumps(common))
outbound.update({
    "title": "Reconstructed outbound WebSocket Protocol",
    "required": ["types", "qos"],
    "x-evidence": [serializer, proof(0x1ace4c, needle="(int)uVar1 < 0"),
                   proof(0x1accb4)],
    "x-serialization-order": ["types", "data_content", "from", "to", "fp", "qos"],
})
for key in ("data_content", "from", "to", "fp"):
    outbound["properties"][key]["minLength"] = 1
    outbound["properties"][key].pop("default")
    outbound["properties"][key]["description"] = "Omitted by this serializer when empty."
save("protocol_outbound.schema.json", outbound)
inbound = json.loads(json.dumps(common))
inbound.update({"title": "Reconstructed inbound named Protocol fields",
                "x-evidence": [parser],
                "x-missing-field-defaults": {k: v["default"] for k, v in properties.items()}})
save("protocol_inbound.schema.json", inbound)

save("protocol_layout.json", {
    "library": str(LIB),
    "library_sha256": hashlib.sha256(LIB.read_bytes()).hexdigest(),
    "ghidra_image_base": "0x100000",
    "scope": "arm64 Rust native protocol; memory offsets are build-specific, not JSON offsets",
    "evidence": [serializer, parser],
    "fields": [
        {"json_key": "data_content", "rust_type": "String", "memory_offset": "0x00", "length_offset": "0x10"},
        {"json_key": "from", "rust_type": "String", "memory_offset": "0x18", "length_offset": "0x28"},
        {"json_key": "to", "rust_type": "String", "memory_offset": "0x30", "length_offset": "0x40"},
        {"json_key": "fp", "rust_type": "String", "memory_offset": "0x48", "length_offset": "0x58"},
        {"json_key": "types", "rust_type": "i32", "memory_offset": "0x60"},
        {"json_key": "qos", "rust_type": "bool", "memory_offset": "0x68"},
    ],
    "data_content": "Serialized as a JSON string. Login responses and business messages parse JSON inside that string.",
    "source_status": "manually reconstructed from Ghidra pseudo-C; not original Rust source",
})
save("message_types.json", {
    "outer_field": "types", "evidence": [receiver],
    "entries": [
        {"value": 2, "direction": "receive", "meaning": "business message", "handler": "0x1c5f58"},
        {"value": 4, "direction": "send_and_receive", "meaning": "QoS acknowledgement", "handler": "0x1e0cf4", "evidence": [ack]},
        {"value": 6, "direction": "send", "meaning": "login", "evidence": [login]},
        {"value": 50, "direction": "receive", "meaning": "login response", "handler": "0x1c6e5c"},
        {"value": 51, "direction": "receive", "meaning": "heartbeat response; updates stored time"},
        {"value": 52, "direction": "receive", "meaning": "server error branch (log semantic independently indexed in URI evidence)", "detail_limit": "No payload callback established by this audit."},
        {"value": 54, "direction": "receive", "meaning": "kicked/offline; calls disconnect handler", "handler": "0x1e2ea0"},
    ],
    "unknown_values": "Separate log branch; no complete protocol enum recovered.",
    "limit": "Directions reflect inspected send/receive branches only; no claim that other values are unsupported everywhere.",
})
save("login_response.schema.json", {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "JSON decoded from data_content of outer types=50",
    "type": "object", "required": ["code", "user_id", "data"],
    "properties": {
        "code": {"type": "integer", "minimum": -2147483648, "maximum": 2147483647,
                 "description": "0 reaches the login success branch; nonzero reaches failure."},
        "user_id": {"type": "string"}, "data": {"type": "string"},
    },
    "x-evidence": [login_parser, proof(0x1ca2f8), proof(0x1c942c),
                   proof(0x1e99a0, "lifecycle/functions", "(int)local_108 == 0")],
    "$comment": "Required named fields verified through missing-field error paths. Unknown-key behavior is not asserted.",
})
save("business_message_forwarding.json", {
    "outer_type": 2, "payload_field": "data_content",
    "inner_format": "JSON value containing integer msg_type",
    "forwarded_msg_types": [101, 102, 113, 114, 115, 116, 117],
    "forwarded_content": "Original data_content string; not the parsed JSON value.",
    "rust_event_integer_field_value": 4,
    "forwarding_function_ghidra_address": "0x1ec7f0",
    "evidence": [business],
    "limits": [
        "The names and remaining fields of each msg_type were not recovered.",
        "Other msg_type values do not use the forwarding path in this inspected handler.",
        "Missing/non-integer msg_type reaches an unwrap/panic path; float/range edge cases were not exhaustively audited.",
        "Value 4 is an event integer field, not evidence of a Rust/Dart enum variant; see flutter_event_encoding.json for the independent encoder audit.",
    ],
})
save("qos_ack_construction.json", {
    "evidence": [ack],
    "assignments": {"types": 4, "qos": False,
                    "data_content": "received.fp", "from": "received.to",
                    "to": "received.from", "fp": "fresh UUID string"},
    "uuid_evidence": [proof(0x20a4a4, "stage2/functions"), proof(0x20a070, "stage2/functions")],
    "limit": "Constructor semantics only; retransmission timing/window policy not established.",
})
save("frb_wire_parameters.json", {
    "bridge": "flutter_rust_bridge", "version_string": "2.0.0-dev.37",
    "functions": [
        {"name": "init_ws", "wrapper_ghidra_address": "0x1b7b4c",
         "decoded_parameters": ["UTF-8 String"], "evidence": [proof(0x1b7b4c)]},
        {"name": "ws_login", "wrapper_ghidra_address": "0x1b7c90",
         "decoded_parameters": ["UTF-8 String"], "evidence": [proof(0x1b7c90)]},
        {"name": "create_event_stream", "decoded_parameters": ["String decoded for bridge/stream sink setup"],
         "evidence": [proof(0x1c6260, "stage2/functions")],
         "limit": "The stream sink representation is not a business message argument."},
    ],
    "string_wire_encoding": {"length": "4-byte little-endian signed i32",
                             "content": "length bytes validated as UTF-8",
                             "evidence": [proof(0x1db42c, "stage2/functions"),
                                          proof(0x1c62f8, "stage2/functions")]},
    "limits": ["Business parameter names/content are not inferred from the binary wire decoder.",
               "This is the FFI argument format, not the network WebSocket wire frame."],
})

rows = []
for path in (OUT / "decompile_status.tsv", OUT / "stage2/decompile_status.tsv", OUT / "lifecycle/decompile_status.tsv"):
    with path.open() as stream:
        rows.extend(csv.DictReader(stream, delimiter="\t"))
unique = {r["address"] for r in rows}
summary = {
    "script": str(Path(__file__).resolve()), "library": str(LIB),
    "exports": len(rows), "unique_decompiled_functions": len(unique),
    "all_decompiler_exports_completed": all(r["completed"] == "true" for r in rows),
    "outbound_fields": 6, "confirmed_outer_message_values": 7,
    "forwarded_inner_msg_type_values": 7,
    "performed_native_execution": False, "performed_backend_requests": False,
    "decompiler_limit": "Successful export is not proof of correct C types or complete Rust source recovery.",
}
save("extraction_summary.json", summary)
(OUT / "Rust协议提取说明.txt").write_text("""Rust WebSocket / Flutter 桥接协议静态提取

本目录的 JSON Schema 是依据原生反编译控制流人工复原的协议说明，不是原项目源文件。
Ghidra 地址使用 image base 0x100000；JSON 条目同时记录 ELF 虚拟地址和伪代码证据。

1. 外层 Protocol 六字段
types 为有符号 32 位整数；qos 为 bool；data_content/from/to/fp 为 String。
发送顺序是 types、data_content、from、to、fp、qos。types/qos 总是输出，四个字符串为空时省略。
接收对象缺少字段时：types=0、qos=false、字符串为空。Schema 中 default 只是标注，不自动补值。
data_content 本身是字符串，可能承载第二层 JSON。发送和接收 Schema 分开保存。

2. 类型分发
发送登录 types=6；接收 2=业务、4=QoS ACK、50=登录响应、51=心跳响应、52=服务器错误分支、54=被踢下线。
只恢复了已审查分支，不是完整类型枚举。登录响应内层要求 code 整数、user_id 字符串、data 字符串；code=0 进入成功分支。

3. 业务消息与 ACK
types=2 的 data_content 解为 JSON，读取独立的 msg_type。
101、102、113、114、115、116、117 将原 data_content 字符串交给 Rust 事件转发函数。
还未确认各 msg_type 的业务名称、剩余字段；转发结构的整数值 4 是事件字段，不能当成 enum 判别值。独立编码核验见 flutter_event_encoding.json。
ACK 构造器设置 types=4/qos=false，data_content=接收包 fp，交换 from/to，并生成新的 UUID fp。

4. 桥接参数
init_ws、ws_login 的 wire 解码器各读取一个 UTF-8 String。
长度为 4 字节小端有符号 i32，随后是 UTF-8 字节；这是 FFI 参数格式，不是服务器协议。
参数的业务名称和登录内容暂未恢复。

5. 校验与边界
三轮 Ghidra 导出、按函数去重的数量见 extraction_summary.json。
伪代码类型可能不准确，所有结论保留函数地址与控制流证据；完整 Dart/Rust 源码、HTTP 参数和重连时序仍未恢复。
未执行原生库，未连接服务器，未把库内字符串候选当作业务字段定义。
""")
print(json.dumps(summary, ensure_ascii=False))
