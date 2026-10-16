#!/usr/bin/env python3
"""Identify this APK's Dart AOT headers and engine strings without executing it."""

from _paths import app_root, workspace_root
import hashlib
import json
import re
import struct
from pathlib import Path


class Elf:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        data = self.data
        if data[:4] != b"\x7fELF" or data[5] != 1:
            raise ValueError("Expected little-endian ELF")
        self.bits = 64 if data[4] == 2 else 32
        self.machine = struct.unpack_from("<H", data, 18)[0]
        if self.bits == 64:
            shoff = struct.unpack_from("<Q", data, 40)[0]
            size, count, strings_index = struct.unpack_from("<HHH", data, 58)
            raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + size * i)
                   for i in range(count)]
        else:
            shoff = struct.unpack_from("<I", data, 32)[0]
            size, count, strings_index = struct.unpack_from("<HHH", data, 46)
            raw = [struct.unpack_from("<10I", data, shoff + size * i) for i in range(count)]
        names = data[raw[strings_index][4]:raw[strings_index][4] + raw[strings_index][5]]
        self.sections = []
        for section in raw:
            self.sections.append({
                "name": names[section[0]:].split(b"\0", 1)[0].decode("ascii"),
                "type": section[1], "vma": section[3], "offset": section[4],
                "size": section[5], "link": section[6], "entsize": section[9],
            })

    def map(self, vma):
        for section in self.sections:
            if section["type"] == 8 or not section["vma"]:
                continue
            if section["vma"] <= vma < section["vma"] + section["size"]:
                return section["offset"] + vma - section["vma"]
        raise ValueError(f"Unmapped address {vma:#x}")

    def symbols(self):
        for section in self.sections:
            if section["type"] != 11:
                continue
            strings_section = self.sections[section["link"]]
            strings = self.data[strings_section["offset"]:strings_section["offset"] + strings_section["size"]]
            for offset in range(section["offset"], section["offset"] + section["size"], section["entsize"]):
                if self.bits == 64:
                    name, _, _, section_index, vma, size = struct.unpack_from("<IBBHQQ", self.data, offset)
                else:
                    name, vma, size, _, _, section_index = struct.unpack_from("<IIIBBH", self.data, offset)
                yield {"name": strings[name:].split(b"\0", 1)[0].decode("ascii"),
                       "vma": vma, "size": size, "section_index": section_index}


def string_evidence(elf, offset, text):
    return {"text": text, "file": str(elf.path), "file_offset": offset,
            "file_offset_hex": f"0x{offset:x}", "byte_length": len(text.encode("ascii"))}


def identify(app, architecture):
    library_dir = app / "unpacked/lib" / architecture
    dart = Elf(library_dir / "libapp.so")
    engine = Elf(library_dir / "libflutter.so")
    symbols = {symbol["name"]: symbol for symbol in dart.symbols()
               if symbol["name"].startswith("_kDart")}
    headers = {}
    for name in ["_kDartVmSnapshotData", "_kDartIsolateSnapshotData"]:
        symbol = symbols[name]
        offset = dart.map(symbol["vma"])
        data = dart.data
        magic, length, kind = struct.unpack_from("<IQQ", data, offset)
        if magic != 0xdcdcf5f5:
            raise ValueError("Unexpected snapshot magic")
        version = data[offset + 20:offset + 52].decode("ascii")
        if not re.fullmatch("[0-9a-f]{32}", version):
            raise ValueError("Unexpected snapshot version hash")
        feature_end = data.index(b"\0", offset + 52)
        features = data[offset + 52:feature_end].decode("ascii")
        headers[name] = {
            "symbol_vma": f"0x{symbol['vma']:x}", "symbol_byte_size": symbol["size"],
            "file_offset": offset, "file_offset_hex": f"0x{offset:x}",
            "magic_bytes_hex": data[offset:offset + 4].hex(),
            "magic_integer_little_endian": f"0x{magic:x}",
            "snapshot_length_header_value": length,
            "snapshot_kind_header_value": kind,
            "snapshot_hash": version,
            "hash_file_offset": f"0x{offset + 20:x}",
            "features_string": features,
            "features_file_offset": f"0x{offset + 52:x}",
            "features": features.split(" "),
            "first_cluster_byte_file_offset": f"0x{feature_end + 1:x}",
        }
    if headers["_kDartVmSnapshotData"]["snapshot_hash"] != headers["_kDartIsolateSnapshotData"]["snapshot_hash"]:
        raise ValueError("VM / isolate snapshot version mismatch")

    rodata = next(section for section in engine.sections if section["name"] == ".rodata")
    payload = engine.data[rodata["offset"]:rodata["offset"] + rodata["size"]]
    versions = []
    for match in re.finditer(rb"\x00([\d\w.\-]+ \((?:stable|beta|dev)\)[^\x00]{0,200})(?=\x00)", payload):
        versions.append(string_evidence(engine, rodata["offset"] + match.start(1), match.group(1).decode("ascii")))
    forty_character_hashes = []
    for match in re.finditer(rb"\x00([0-9a-f]{40})(?=\x00)", payload):
        text = match.group(1).decode("ascii")
        if len(set(text)) > 4:
            forty_character_hashes.append(string_evidence(engine, rodata["offset"] + match.start(1), text))
    snapshot_hash_strings = []
    expected_hash = headers["_kDartVmSnapshotData"]["snapshot_hash"].encode()
    for match in re.finditer(b"\x00(" + expected_hash + b")(?=\x00)", payload):
        snapshot_hash_strings.append(string_evidence(engine, rodata["offset"] + match.start(1), expected_hash.decode()))

    features = headers["_kDartVmSnapshotData"]["features"]
    return {
        "apk_architecture_directory": architecture,
        "elf_bits": dart.bits,
        "elf_machine_value": dart.machine,
        "elf_machine_name": {183: "EM_AARCH64", 40: "EM_ARM", 62: "EM_X86_64"}[dart.machine],
        "libapp": {"path": str(dart.path), "sha256": hashlib.sha256(dart.data).hexdigest()},
        "libflutter": {"path": str(engine.path), "sha256": hashlib.sha256(engine.data).hexdigest()},
        "dart_version_strings": versions,
        "libflutter_snapshot_hash_constants": snapshot_hash_strings,
        "libflutter_40_character_hash_constants": forty_character_hashes,
        "snapshot_headers": headers,
        "snapshot_symbols": [{**symbol, "vma_hex": f"0x{symbol['vma']:x}",
                              "file_offset_hex": f"0x{dart.map(symbol['vma']):x}"}
                             for symbol in symbols.values() if symbol["vma"]],
        "product_feature": "product" in features,
        "compressed_pointers_feature": "compressed-pointers" in features,
        "target_platform_feature": "android" if "android" in features else None,
        "target_arch_feature": next((feature for feature in ["arm64", "arm", "x64"] if feature in features), None),
    }


def main():
    app = app_root()
    result = {
        "method": "只读解析 libapp 的 ELF 动态符号并经 section VMA 映射定位快照头；"
                  "读取 libflutter .rodata 中完整 NUL 分隔版本和 hash 常量。未执行库。",
        "header_layout_evidence": {
            "magic_relative_offset": 0, "magic_bytes": 4,
            "length_relative_offset": 4, "length_bytes": 8,
            "kind_relative_offset": 12, "kind_bytes": 8,
            "snapshot_hash_relative_offset": 20, "snapshot_hash_bytes": 32,
            "features_relative_offset": 52, "features_encoding": "ASCII NUL-terminated",
            "local_crosscheck": str(app / "tools/blutter/extract_dart_info.py"),
        },
        "architectures": [identify(app, arch) for arch in ["arm64-v8a", "armeabi-v7a", "x86_64"]],
        "matching_requirements": {
            "preferred_input_directory": str(app / "unpacked/lib/arm64-v8a"),
            "dart_sdk_version": "3.5.2",
            "snapshot_hash": "80a49c7111088100a233b2ae788e1f48",
            "target": "android arm64", "product": True, "compressed_pointers": True,
            "features": ["no-code_comments", "no-dwarf_stack_traces_mode", "dedup_instructions", "no-tsan", "no-msan"],
            "local_blutter_library_configuration_name": "dartvm3.5.2_android_arm64",
            "rationale": "匹配版本、快照序列化 hash、目标架构、product 与压缩指针布局，"
                         "避免以通用字节解析把对象表和代码对象误解码。",
        },
        "flutter_version_identification": {
            "exact_flutter_semantic_version": None,
            "engine_revision_candidate": "a6bd3f1de158bb61090e0c8053df93a10cb548e1",
            "other_revision_constant": "9d530bb0bcbfd571ee3d820fdd79ff859d61e2cd",
            "limits": "本地 .rodata 可直接确认两个完整 40 位 hash，但单凭字符串不能区分"
                      "engine revision 与其他构建 revision。Flutter 发布版本需父任务进行官方映射核验；"
                      "本报告未凭附近文本推断版本。",
        },
        "object_table_analysis_guidance": {
            "existing_string_extractor": str(app / "scripts/extract_snapshot_strings.py"),
            "validated_arm64_string_sequence_range": {"start": "0x278c4", "stop": "0xa0b79", "string_count": 23484},
            "existing_extractor_limits": "已验证的特定字符串 cluster 范围解析器，未恢复 RefId、Library、"
                                         "Class、Field、Function、ObjectPool、Code 等对象引用。",
            "preferred_next_step": "使用父任务准备的匹配 VM/Blutter 解析对象和 AOT 指令，再根据 ObjectPool"
                                   "引用确认端点字符串、JSON map 构造、鉴权和 Message.fromJson 分支。",
            "key_artifacts_to_request": ["asm/（应用 package:distinguish 的指令输出）", "objs.txt", "pp.txt", "blutter 输出日志"],
            "avoid": "不要按快照字符串排列顺序推断接口参数或所属模型，也不要直接将 Dart AOT ARM64"
                     "机器码当标准 C ABI 原生函数处理。",
        },
        "constraints": "未下载/构建 AOT 工具，未连接业务服务器，未输出私钥，未执行原始 APK 或原生库。",
    }
    output = app / "analysis/aot_runtime"
    output.mkdir(parents=True, exist_ok=True)
    destination = output / "runtime_identification.json"
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(destination),
                      "architectures": [{"directory": item["apk_architecture_directory"],
                                          "dart": item["dart_version_strings"],
                                          "hash": item["snapshot_headers"]["_kDartVmSnapshotData"]["snapshot_hash"],
                                          "features": item["snapshot_headers"]["_kDartVmSnapshotData"]["features_string"]}
                                         for item in result["architectures"]]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
